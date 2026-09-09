#!/usr/bin/env python3
# new Env("Daily Unified Orchestrator")
"""Inline daily check-in orchestrator with automatic catch-up and circuit breaking."""
from __future__ import annotations

import argparse
import heapq
import json
import os
import re
import signal
import subprocess
import sys
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait as wait_futures
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from common import BJT, upstash_redis_command
from alert_levels import detect_unconfigured
from discord_notify import notify_task_result, notify_unconfigured
from task_registry import TASKS, resolve_execution_queue
from circuit_breaker import (
    is_task_suspended,
    load_circuit_state,
    record_task_outcome,
    resume_task,
    resume_all_tasks,
    save_suspended_result_record,
    MAX_DAILY_ATTEMPTS,
)

TRAVEL_EVENT_RE = re.compile(r"TRAVEL_EVENT\s+state=(\w+)\s+arrive_at=(\d+)")


def _merge_result(prev: Any, ok: bool, unconf: bool, suspended: bool = False) -> Any:
    if prev is True or ok is True:
        return True
    if suspended:
        return "suspended"
    cur: Any = "unconfigured" if unconf else ok
    if prev is None:
        return cur
    if prev == "suspended":
        return "suspended"
    if prev is False or cur is False:
        return False
    return "unconfigured"


def bjt_now() -> datetime:
    return datetime.now(BJT)


def _hm_today_ts(hm: str) -> float:
    h, m = (int(x) for x in hm.split(":"))
    return bjt_now().replace(hour=h, minute=m, second=0, microsecond=0).timestamp()


def _fmt_bjt(ts: float) -> str:
    return datetime.fromtimestamp(ts, BJT).strftime("%H:%M:%S")


def _read_latvi_last_sign() -> Optional[float]:
    prefix = os.getenv("CAT_CHECKIN_REDIS_PREFIX", "cat_checkin:").rstrip(":")
    try:
        ok, res = upstash_redis_command(["GET", f"{prefix}:state:latvi"])
        if ok and isinstance(res, dict):
            raw = res.get("result")
            if raw:
                data = json.loads(raw) if isinstance(raw, str) else raw
                if isinstance(data, dict) and data.get("last_sign_ts"):
                    return float(data["last_sign_ts"])
    except Exception:
        pass
    state_file = Path(os.getenv("LATVI_STATE_FILE", str(ROOT_DIR / ".latvi_state.json")))
    if not state_file.is_absolute():
        state_file = ROOT_DIR / state_file
    if state_file.exists():
        try:
            data = json.loads(state_file.read_text(encoding="utf-8"))
            if data.get("last_sign_ts"):
                return float(data["last_sign_ts"])
        except Exception:
            pass
    return None


def _latvi_signed_today() -> bool:
    last = _read_latvi_last_sign()
    if not last:
        return False
    return datetime.fromtimestamp(last, BJT).date() == bjt_now().date()


def _get_today_successful_tasks() -> Set[str]:
    """获取今日已成功执行的任务 ID 集合（通过 Redis 与本地结果目录双通道校验）。"""
    today = bjt_now().strftime("%Y-%m-%d")
    succeeded_tasks: Set[str] = set()
    result_to_id = {cfg["result"]: tid for tid, cfg in TASKS.items()}

    prefix = os.getenv("CAT_CHECKIN_REDIS_PREFIX", "cat_checkin:").rstrip(":")
    raw_key = f"{prefix}:raw:{today}"
    try:
        ok, res = upstash_redis_command(["HGETALL", raw_key])
        if ok and isinstance(res, dict):
            raw_hash = res.get("result")
            field_map = {}
            if isinstance(raw_hash, dict):
                field_map = raw_hash
            elif isinstance(raw_hash, list):
                for i in range(0, len(raw_hash), 2):
                    if i + 1 < len(raw_hash):
                        field_map[str(raw_hash[i])] = raw_hash[i + 1]
            for field, val in field_map.items():
                if field in result_to_id:
                    try:
                        data = json.loads(val) if isinstance(val, str) else val
                        if isinstance(data, dict) and data.get("ok") is True and data.get("date") == today:
                            succeeded_tasks.add(result_to_id[field])
                    except Exception:
                        pass
    except Exception:
        pass

    out_dir = Path(os.getenv("TASK_OUTPUT_DIR", ".task_results"))
    if out_dir.exists() and out_dir.is_dir():
        for res_file, tid in result_to_id.items():
            fpath = out_dir / res_file
            if fpath.exists():
                try:
                    data = json.loads(fpath.read_text(encoding="utf-8"))
                    if isinstance(data, dict) and data.get("ok") is True and data.get("date") == today:
                        succeeded_tasks.add(tid)
                except Exception:
                    pass

    return succeeded_tasks


def build_task_env(cfg: Dict[str, Any]) -> Dict[str, str]:
    env = os.environ.copy()
    env.setdefault("TZ", "Asia/Shanghai")
    env.setdefault("TASK_OUTPUT_DIR", ".task_results")
    env["TASK_TIMEOUT"] = str(cfg["timeout"])
    env["PYTHONUNBUFFERED"] = "1"
    if cfg.get("account"):
        n = str(cfg["account"])
        cookie = os.getenv(f"WORKBUDDY_COOKIE_{n}", "") or (os.getenv("WORKBUDDY_COOKIE", "") if n == "1" else "")
        refresh = os.getenv(f"WORKBUDDY_REFRESH_TOKEN_{n}", "") or (os.getenv("WORKBUDDY_REFRESH_TOKEN", "") if n == "1" else "")
        if not cookie and not refresh:
            raise RuntimeError(
                f"workbuddy 账号 {n} 缺少 WORKBUDDY_COOKIE_{n}/WORKBUDDY_REFRESH_TOKEN_{n}，拒绝继承其他账号凭据"
            )
        for k in list(env.keys()):
            if re.match(r"^(QL_)?WORKBUDDY_(COOKIE|REFRESH_TOKEN)(_\d+)?$", k, re.I):
                del env[k]
        env["WORKBUDDY_COOKIE"] = cookie
        env["WORKBUDDY_COOKIE_1"] = cookie
        env["WORKBUDDY_REFRESH_TOKEN"] = refresh
        env["WORKBUDDY_REFRESH_TOKEN_1"] = refresh
        env["WORKBUDDY_ACCOUNT_IDX"] = n
        env["WORKBUDDY_WAIT_TRAVEL"] = "true"
    if cfg["id"] == "latvi":
        env.setdefault("LATVI_STATE_FILE", ".latvi_state.json")
    for k, v in (cfg.get("env") or {}).items():
        env[str(k)] = str(v)
    env["TASK_ID"] = cfg["id"]
    if cfg.get("result"):
        env["TASK_RESULT_NAME"] = cfg["result"]
    if cfg.get("name"):
        env["TASK_TITLE"] = cfg["name"]
    return env


def _cooldown_due_at(cfg: Dict[str, Any]) -> Optional[float]:
    """滚动冷却型任务的下次到期时刻（epoch）；无 sched 元数据/无状态 → None（视为已到期）。"""
    sched = cfg.get("sched") or {}
    if sched.get("type") != "rolling":
        return None
    period_h = float(sched.get("period_h") or 24)
    task_id = cfg["id"]
    prefix = os.getenv("CAT_CHECKIN_REDIS_PREFIX", "cat_checkin:").rstrip(":")
    try:
        from common import load_kv_state
        state = load_kv_state(f"{prefix}:state:notify:{task_id}", f".notify_state_{task_id}.json")
        ts = float(state.get("last_credit_ts") or 0)
    except Exception:
        return None
    if ts <= 0:
        return None
    return ts + period_h * 3600


def run_task_subprocess(cfg: Dict[str, Any]) -> Tuple[bool, str]:
    cap = cfg["timeout"] + 120
    try:
        env = build_task_env(cfg)
        cmd = [sys.executable, "-u", str(BASE_DIR / "run_task.py"), cfg["script"]]
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT_DIR),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except Exception as exc:
        return False, f"failed to spawn: {exc}"
    try:
        out, _ = proc.communicate(timeout=cap)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        try:
            out, _ = proc.communicate(timeout=10)
        except Exception:
            out = ""
        out = f"[orchestrator kill >{cap}s]\n{(out or '')}"
    return proc.returncode == 0, (out or "").strip()


class Orchestrator:
    def __init__(self, hard_deadline: float = 0.0) -> None:
        self.hard_deadline = hard_deadline or (time.time() + 7200)
        self.heap: List[Tuple[float, int, str, Optional[Dict[str, Any]]]] = []
        self.seq = 0
        self.results: Dict[str, Any] = {}
        self.executor = ThreadPoolExecutor(max_workers=int(os.getenv("BATCH_PARALLEL", "4")))
        self.futures: Dict[Future, Tuple[str, Optional[Dict[str, Any]]]] = {}

    def push(self, fire_at: float, kind: str, cfg: Optional[Dict[str, Any]] = None) -> None:
        heapq.heappush(self.heap, (fire_at, self.seq, kind, cfg))
        self.seq += 1

    def _label(self, kind: str, cfg: Optional[Dict[str, Any]]) -> str:
        return cfg["id"] if cfg else kind

    def _submit(self, kind: str, cfg: Optional[Dict[str, Any]]) -> None:
        fut = self.executor.submit(run_task_subprocess, cfg or {})
        self.futures[fut] = (kind, cfg)

    def _on_task_done(self, cfg: Dict[str, Any], ok: bool, out: str) -> None:
        tid = cfg["id"]
        unconf = (not ok) and bool(detect_unconfigured(out or ""))
        suspended = False
        circuit_info = {}
        if not unconf:
            try:
                circuit_info, newly_tripped = record_task_outcome(tid, ok=ok, output=out or "")
                suspended = bool(circuit_info.get("status") == "suspended")
            except Exception as exc:
                print(f"WARN: circuit breaker 状态记录异常: {exc}", file=sys.stderr)

        prev = self.results.get(tid)
        self.results[tid] = _merge_result(prev, ok, unconf, suspended=suspended)
        tag = "OK" if ok else ("SKIP" if unconf else ("SUSPENDED" if suspended else "FAIL"))
        print(f"\n{'='*60}\n[{tag}] [{tid}] done (ok={ok})\n{'-'*60}")
        if out:
            print(out)
        print(f"{'='*60}")
        if unconf:
            print(f"  ⚪ 凭据未配置，按跳过处理")
        elif suspended:
            print(f"  🛑 任务已达 {MAX_DAILY_ATTEMPTS} 次重试上限，触发熔断停用！等待人工修复后上线")
        elif not ok:
            next_retry_at = circuit_info.get("next_retry_at")
            attempts = circuit_info.get("attempts", 1)
            if next_retry_at:
                print(f"  🔁 [分时段重试] [{tid}] 第 {attempts+1}/{MAX_DAILY_ATTEMPTS} 次重试安排在 {_fmt_bjt(next_retry_at)}")

        try:
            if unconf:
                notify_unconfigured(
                    task_id=tid,
                    name=cfg.get("name") or tid,
                    script=cfg.get("script") or "",
                    output=out or "",
                )
            else:
                notify_task_result(
                    task_id=tid,
                    name=cfg.get("name") or tid,
                    script=cfg.get("script") or "",
                    ok=ok,
                    output=out or "",
                )
        except Exception as exc:
            print(f"WARN: Discord 失败提醒推送失败: {exc}", file=sys.stderr)

        for _m in TRAVEL_EVENT_RE.findall(out or "")[-1:]:
            print(f"  -> travel event {_m[0]} (回程由 workbuddy 接力派发，本 run 不等待)")

    def run(self) -> int:
        due_only = os.getenv("DUE_ONLY", "0").lower() in {"1", "true", "yes"}
        while self.heap or self.futures:
            now = time.time()
            while self.heap and self.heap[0][0] <= now:
                fire, _, kind, cfg = heapq.heappop(self.heap)
                if cfg:
                    tid = cfg["id"]
                    if is_task_suspended(tid):
                        print(f"🛑 [CIRCUIT_BREAKER] 任务 [{tid}] 已熔断停用，跳过执行")
                        save_suspended_result_record(tid, "已熔断停用，跳过执行")
                        self.results[tid] = "suspended"
                        continue
                if due_only and cfg:
                    due_at = _cooldown_due_at(cfg)
                    if due_at and due_at > now:
                        print(f"[heartbeat] [{cfg['id']}] 冷却中，跳过（{_fmt_bjt(due_at)} BJT 到期）")
                        continue
                self._submit(kind, cfg)
            if not self.heap and not self.futures:
                break
            if self.futures:
                timeout = max(0.0, self.heap[0][0] - time.time()) if self.heap else None
                done, _ = wait_futures(list(self.futures), timeout=timeout, return_when=FIRST_COMPLETED)
            else:
                top = self.heap[0][0]
                time.sleep(min(max(0.1, top - time.time()), 60.0))
                continue
            for fut in done:
                kind, cfg = self.futures.pop(fut)
                try:
                    ok, out = fut.result()
                except Exception as exc:
                    ok, out = False, f"orchestrator error: {exc}"
                if cfg:
                    self._on_task_done(cfg, ok, out)

        print(f"\n{'#'*60}\nOrchestrator done: {len(self.results)} task instances")
        failed = [k for k, v in self.results.items() if v is False]
        skipped = [k for k, v in self.results.items() if v == "unconfigured"]
        suspended = [k for k, v in self.results.items() if v == "suspended"]
        for tid, res in self.results.items():
            mark = "OK" if res is True else ("SKIP(未配置)" if res == "unconfigured" else ("SUSPENDED(已熔断)" if res == "suspended" else "FAIL"))
            print(f"  {mark} {tid}")
        if skipped:
            print(f"skipped (credentials not configured): {', '.join(skipped)}")
        if suspended:
            print(f"suspended (circuit broken, 8-attempt limit reached): {', '.join(suspended)}")
        if failed:
            print(f"failed: {', '.join(failed)}")
            return 1
        return 0


def build_default_timeline(orch: Orchestrator) -> None:
    now = time.time()
    due_ids = plan_due_tasks("")
    for tid in due_ids:
        orch.push(now, "task", TASKS[tid])
    print(f"Due tasks ({len(due_ids)}): {', '.join(due_ids)}")


def build_explicit_timeline(orch: Orchestrator, raw: str) -> None:
    queue = resolve_execution_queue(input_tasks=raw)
    now = time.time()
    ids = []
    for cfg in queue:
        orch.push(now, "task", cfg)
        ids.append(cfg["id"])
    print(f"Explicit tasks: {', '.join(ids)}")


def plan_due_tasks(raw_tasks: str = "", due_only: bool = False) -> List[str]:
    """评估当前时刻会立即执行的任务集（--plan 模式，不启动任何子进程）。

    1. 若显式指定 raw_tasks：
       按照指定的任务队列匹配。
       若 due_only=True（显式心跳过滤），则对 rolling 任务和 latvi 做冷却判断；
       若 due_only=False，候选任务中非熔断任务全部执行。
    2. 若未指定 raw_tasks（日常调度 / 心跳兜底 / 漏跑自愈）：
       全量巡检 TASKS 全部注册任务：
       - 熔断停用 (suspended) -> 跳过；
       - 今日已成功 (ok=True) -> 跳过；
       - 今日已签的 latvi -> 跳过；
       - 冷却中的 rolling 任务 (due_at > now) -> 跳过；
       - 今日失败且处于退避等待期的任务 (next_retry_at > now) -> 跳过；
       其余所有今日未完成、遗漏未执行或到期重试的任务均判定为 DUE。
    """
    now = time.time()
    today = bjt_now().strftime("%Y-%m-%d")

    if raw_tasks.strip():
        cfgs = resolve_execution_queue(input_tasks=raw_tasks)
        due: List[str] = []
        for cfg in cfgs:
            tid = cfg["id"]
            if is_task_suspended(tid):
                continue
            if due_only:
                if tid == "latvi":
                    if _latvi_signed_today():
                        continue
                else:
                    due_at = _cooldown_due_at(cfg)
                    if due_at and due_at > now:
                        continue
            due.append(tid)
        return due

    successful_today = _get_today_successful_tasks()
    due = []
    for tid, cfg in TASKS.items():
        if is_task_suspended(tid):
            continue
        if tid in successful_today:
            continue
        if tid == "latvi":
            if _latvi_signed_today():
                continue
        due_at = _cooldown_due_at(cfg)
        if due_at and due_at > now:
            continue
        state = load_circuit_state(tid)
        if str(state.get("attempt_date") or "") == today and int(state.get("attempts") or 0) > 0:
            next_retry = float(state.get("next_retry_at") or 0)
            if next_retry > now:
                continue
        due.append(tid)
    return due


def main() -> None:
    parser = argparse.ArgumentParser(description="Daily Unified Orchestrator")
    parser.add_argument("--tasks", type=str, default="", help="comma-separated task list (explicit mode)")
    parser.add_argument("--reset-circuit", action="store_true", help="reset circuit breaker state and resume tasks")
    parser.add_argument("--reset-circuit-tasks", type=str, default="", help="comma-separated task list to resume from circuit breaker")
    parser.add_argument("--plan", action="store_true", help="evaluate the due task set and exit without executing anything (prints DUE_TASKS=<list|none>)")
    parser.add_argument("--due-only", action="store_true", help="plan mode: apply heartbeat DUE_ONLY filtering (rolling cooldown / latvi signed-today)")
    args = parser.parse_args()

    if args.plan:
        due = plan_due_tasks(args.tasks, due_only=args.due_only)
        print(f"DUE_TASKS={','.join(due) if due else 'none'}")
        sys.exit(0)

    print(f"Daily orchestrator start @ {bjt_now().strftime('%Y-%m-%d %H:%M:%S')} BJT")
    is_explicit = bool(args.tasks.strip())

    if args.reset_circuit or args.reset_circuit_tasks:
        target_tasks = [t.strip() for t in args.reset_circuit_tasks.split(",") if t.strip()]
        if target_tasks:
            for t in target_tasks:
                resume_task(t, reason="命令行显式指定恢复上线 (--reset-circuit-tasks)")
                print(f"🔄 [CIRCUIT_BREAKER] 任务 [{t}] 熔断状态已重置上线")
        elif args.reset_circuit:
            if is_explicit:
                for t in [t.strip() for t in args.tasks.split(",") if t.strip()]:
                    resume_task(t, reason="手动任务调度恢复上线 (--reset-circuit)")
                    print(f"🔄 [CIRCUIT_BREAKER] 任务 [{t}] 熔断状态已重置上线")
            else:
                resume_all_tasks(reason="全局调度恢复上线 (--reset-circuit)")
                print("🔄 [CIRCUIT_BREAKER] 全部任务熔断状态已重置上线")

    orch = Orchestrator()
    if is_explicit:
        build_explicit_timeline(orch, args.tasks)
    else:
        build_default_timeline(orch)
    sys.exit(orch.run())


if __name__ == "__main__":
    main()
