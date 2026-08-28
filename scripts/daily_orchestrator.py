#!/usr/bin/env python3
# new Env("Daily Unified Orchestrator")
"""Single-run inline daily check-in orchestrator."""
from __future__ import annotations
import argparse, heapq, json, os, re, signal, subprocess, sys, time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait as wait_futures
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
from common import BJT, upstash_redis_command
from discord_notify import notify_summary, notify_task_progress
from task_registry import TASKS, resolve_execution_queue
TRAVEL_EVENT_RE = re.compile(r"TRAVEL_EVENT\s+state=(\w+)\s+arrive_at=(\d+)")
MAX_CLAIM_ROUNDS, CLAIM_MARGIN_SEC, LATVI_ENTER_EARLY_SEC = 3, 15*60, 120
def bjt_now() -> datetime:
    return datetime.now(BJT)
def _hm_today_ts(hm: str) -> float:
    h, m = (int(x) for x in hm.split(":"))
    d = bjt_now().replace(hour=h, minute=m, second=0, microsecond=0)
    return d.timestamp()
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
    except Exception as e:
        print(f"WARN: read Latvi Redis state failed: {e}", file=sys.stderr)
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
def latvi_plan() -> Dict[str, Any]:
    fit_deadline = _hm_today_ts(os.getenv("LATVI_FIT_DEADLINE", "19:30"))
    last = _read_latvi_last_sign()
    if last is None:
        return {"mode": "immediate", "window_open": None, "fire_at": time.time() + 5}
    window_open = last + 86400
    if window_open > fit_deadline:
        return {"mode": "skip", "window_open": window_open, "fire_at": None}
    fire_at = max(time.time() + 30, window_open - LATVI_ENTER_EARLY_SEC)
    return {"mode": "scheduled", "window_open": window_open, "fire_at": fire_at}
def build_task_env(cfg: Dict[str, Any]) -> Dict[str, str]:
    env = os.environ.copy()
    env.setdefault("TZ", "Asia/Shanghai")
    env.setdefault("TASK_OUTPUT_DIR", ".task_results")
    env["TASK_TIMEOUT"] = str(cfg["timeout"])
    if cfg.get("account"):
        n = str(cfg["account"])
        cookie = os.getenv(f"WORKBUDDY_COOKIE_{n}", "") or (os.getenv("WORKBUDDY_COOKIE", "") if n == "1" else "")
        if not cookie:
            # 缺失时若静默继承父进程的其他账号 cookie：两个并发子进程踩同一账号、
            # 结果还写进账号 n 的 JSON 名下（张冠李戴且无告警）——必须显式失败
            raise RuntimeError(
                f"workbuddy 账号 {n} 缺少 WORKBUDDY_COOKIE_{n}（secret 未配置或为空），拒绝继承其他账号的 cookie"
            )
        # 隔离当前子进程凭证：清除所有 WORKBUDDY_COOKIE_*，只保留当前账号的单个 COOKIE 与 COOKIE_1
        for k in list(env.keys()):
            if re.match(r"^(QL_)?WORKBUDDY_COOKIE(_\d+)?$", k, re.I):
                del env[k]
        env["WORKBUDDY_COOKIE"] = cookie
        env["WORKBUDDY_COOKIE_1"] = cookie
        env["WORKBUDDY_WAIT_TRAVEL"] = "true"
        env["WORKBUDDY_NO_RELAY"] = "1"
        env["TASK_RESULT_NAME"] = cfg["result"]
    if cfg["id"] == "latvi":
        env["LATVI_NO_RELAY"] = "1"
        env.setdefault("LATVI_STATE_FILE", ".latvi_state.json")
    return env
def _read_elapsed(cfg: Dict[str, Any]) -> Optional[float]:
    """从 run_task 落盘的结果 JSON 中 best-effort 读取耗时，供 Discord 进度卡片展示。"""
    result_name = cfg.get("result") or ""
    if not result_name:
        return None
    out_dir = Path(os.getenv("TASK_OUTPUT_DIR", str(ROOT_DIR / ".task_results")))
    if not out_dir.is_absolute():
        out_dir = ROOT_DIR / out_dir
    path = out_dir / result_name
    try:
        return float(json.loads(path.read_text(encoding="utf-8")).get("elapsed"))
    except Exception:
        return None
def run_task_subprocess(cfg: Dict[str, Any]) -> Tuple[bool, str]:
    cap = cfg["timeout"] + 120
    try:
        env = build_task_env(cfg)
        cmd = [sys.executable, str(BASE_DIR / "run_task.py"), cfg["script"]]
        proc = subprocess.Popen(cmd, cwd=str(ROOT_DIR), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
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
    def __init__(self, hard_deadline: float) -> None:
        self.hard_deadline = hard_deadline
        self.heap: List[Tuple[float, int, str, Optional[Dict[str, Any]]]] = []
        self.seq = 0
        self.results: Dict[str, bool] = {}
        self.claim_rounds: Dict[str, int] = {}
        self.executor = ThreadPoolExecutor(max_workers=int(os.getenv("BATCH_PARALLEL", "4")))
        self.futures: Dict[Future, Tuple[str, Optional[Dict[str, Any]]]] = {}
        self.latvi_fire_at: Optional[float] = None
        self.dropped = 0
        self.done_seq = 0
        self.ok_count = 0
        self.fail_count = 0
    def push(self, fire_at: float, kind: str, cfg: Optional[Dict[str, Any]] = None) -> None:
        heapq.heappush(self.heap, (fire_at, self.seq, kind, cfg))
        self.seq += 1
    def _label(self, kind: str, cfg: Optional[Dict[str, Any]]) -> str:
        return cfg["id"] if cfg else kind
    def _submit(self, kind: str, cfg: Optional[Dict[str, Any]]) -> None:
        fut = self.executor.submit(run_task_subprocess, cfg or {})
        self.futures[fut] = (kind, cfg)
    def _claim_cutoff(self) -> float:
        anchor = self.latvi_fire_at if self.latvi_fire_at else self.hard_deadline - 300
        margin = CLAIM_MARGIN_SEC if self.latvi_fire_at else 20*60
        return anchor - margin
    def _on_task_done(self, cfg: Dict[str, Any], ok: bool, out: str) -> None:
        tid = cfg["id"]
        prev = self.results.get(tid)
        self.results[tid] = ok if prev is None else (prev and ok)
        tag = "OK" if ok else "FAIL"
        print(f"\n{'='*60}\n[{tag}] [{tid}] done (ok={ok})\n{'-'*60}")
        if out:
            print(out)
        print(f"{'='*60}")
        # Discord 实时进度轮播：每完成一个任务实例推一条卡片（best-effort，绝不阻塞调度）
        self.done_seq += 1
        if ok:
            self.ok_count += 1
        else:
            self.fail_count += 1
        try:
            notify_task_progress(
                task_id=tid,
                name=cfg.get("name") or tid,
                script=cfg.get("script") or "",
                ok=ok,
                output=out or "",
                elapsed=_read_elapsed(cfg),
                progress=f"第 {self.done_seq} 个完成 · ✅ {self.ok_count} · ❌ {self.fail_count}",
            )
        except Exception as exc:
            print(f"WARN: Discord 进度推送失败: {exc}", file=sys.stderr)
        matches = TRAVEL_EVENT_RE.findall(out or "")
        if matches:
            state, arrive_raw = matches[-1]
            arrive_at = int(arrive_raw)
            rounds = self.claim_rounds.get(tid, 0)
            cutoff = self._claim_cutoff()
            claim_fire = arrive_at + 60
            if state == "traveling" and rounds < MAX_CLAIM_ROUNDS:
                if claim_fire <= cutoff:
                    self.push(claim_fire, "task", cfg)
                    self.claim_rounds[tid] = rounds + 1
                    print(f"  -> enqueued claim round {rounds+1} @ {_fmt_bjt(claim_fire)} (cutoff {_fmt_bjt(cutoff)})")
                else:
                    print(f"  -> claim @ {_fmt_bjt(claim_fire)} past cutoff {_fmt_bjt(cutoff)}, deferred to next run")
    def _notify_summary(self) -> None:
        """本轮全部任务结束后的 Discord 总计推送（best-effort，不影响退出码）。"""
        if not self.results:
            return
        failed = sorted(k for k, v in self.results.items() if not v)
        total = len(self.results)
        ok_n = total - len(failed)
        title = (
            f"📋 签到执行完毕 ({bjt_now().strftime('%Y-%m-%d %H:%M')}) — "
            f"✅ {ok_n}/{total}" + (f" ❌ {len(failed)}" if failed else "")
        )
        lines = [f"✅ 成功 {ok_n} | ❌ 失败 {len(failed)} | 共 {total}", ""]
        for tid, ok in self.results.items():
            name = TASKS.get(tid, {}).get("name") or tid
            lines.append(f"{'✅' if ok else '❌'} {name}")
        if failed:
            lines += ["", f"失败站点：{', '.join(failed)}"]
        try:
            notify_summary(title, "\n".join(lines), ok=not failed)
        except Exception as exc:
            print(f"WARN: Discord 总计推送失败: {exc}", file=sys.stderr)
    def run(self) -> int:
        while self.heap or self.futures:
            now = time.time()
            while self.heap and self.heap[0][0] <= now:
                fire, _, kind, cfg = heapq.heappop(self.heap)
                if fire > self.hard_deadline:
                    print(f"dropping event [{self._label(kind, cfg)}] past hard wall")
                    self.dropped += 1
                    continue
                self._submit(kind, cfg)
            if not self.heap and not self.futures:
                break
            if self.futures:
                timeout: Optional[float] = None
                if self.heap and self.heap[0][0] <= self.hard_deadline:
                    timeout = max(0.0, self.heap[0][0] - time.time())
                done, _ = wait_futures(list(self.futures), timeout=timeout, return_when=FIRST_COMPLETED)
            else:
                # concurrent.futures.wait 对空集合立即返回（忽略 timeout），
                # futures 为空时必须 sleep 等堆顶事件，否则主循环 100% CPU 忙等数小时
                top = self.heap[0][0]
                if top > self.hard_deadline:
                    # 堆有序：堆顶越硬墙则剩余事件全部必被丢弃，直接清堆退出
                    while self.heap:
                        fire, _, kind, cfg = heapq.heappop(self.heap)
                        print(f"dropping event [{self._label(kind, cfg)}] past hard wall")
                        self.dropped += 1
                    break
                time.sleep(min(top - time.time(), 60.0))
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
        if not self.results and self.dropped:
            # 硬墙后启动的 run 全部事件被 drop 却 exit 0 → workflow 绿色但什么都没干，必须显式失败
            print(f"WARNING: no tasks executed — {self.dropped} event(s) dropped past hard wall "
                  f"{os.getenv('ORCH_HARD_DEADLINE', '19:55')} BJT（run 启动过晚）")
            return 1
        self._notify_summary()
        failed = [k for k, v in self.results.items() if not v]
        for tid, ok in self.results.items():
            print(f"  {'OK' if ok else 'FAIL'} {tid}")
        if failed:
            print(f"failed: {', '.join(failed)}")
            return 1
        return 0
def build_default_timeline(orch: Orchestrator) -> None:
    now = time.time()
    stage_a = [t for t in TASKS.values() if "matrix" in t["tags"] or "workbuddy" in t["tags"]]
    for cfg in stage_a:
        orch.push(now, "task", cfg)
    ms_cfg = TASKS["modelscope"]
    ms_fire = max(now, _hm_today_ts("09:10"))
    orch.push(ms_fire, "task", ms_cfg)
    plan = latvi_plan()
    latvi_cfg = TASKS["latvi"]
    if plan["mode"] == "skip":
        print(f"Latvi window {_fmt_bjt(plan['window_open'])} past fit deadline {os.getenv('LATVI_FIT_DEADLINE','19:30')}, skipping today; next run will re-anchor")
    else:
        orch.latvi_fire_at = plan["fire_at"]
        orch.push(plan["fire_at"], "task", latvi_cfg)
    print("Timeline:")
    print(f"  immediate ({len(stage_a)} tasks, concurrency {os.getenv('BATCH_PARALLEL','4')}): " + ", ".join(t["id"] for t in stage_a))
    print(f"  modelscope @ {_fmt_bjt(ms_fire)} (gate 09:10)")
    if plan["mode"] == "skip":
        print(f"  latvi: skipped (window {_fmt_bjt(plan['window_open'])} past deadline)")
    else:
        wo = plan.get("window_open")
        basis = f"last {datetime.fromtimestamp(wo - 86400, BJT).strftime('%m-%d %H:%M:%S')} +24h" if wo else "no history"
        print(f"  latvi @ {_fmt_bjt(plan['fire_at'])} (basis: {basis}{', window '+_fmt_bjt(wo) if wo else ''})")
        if wo:
            print(f"  next window estimate: {datetime.fromtimestamp(wo + 86400, BJT).strftime('%m-%d %H:%M:%S')}")
def build_explicit_timeline(orch: Orchestrator, raw: str) -> None:
    queue = resolve_execution_queue(input_tasks=raw)
    now = time.time()
    ids = []
    for cfg in queue:
        orch.push(now, "task", cfg)
        if cfg["id"] == "latvi":
            orch.latvi_fire_at = now
        ids.append(cfg["id"])
    print(f"Explicit tasks: {', '.join(ids)}")
def main() -> None:
    parser = argparse.ArgumentParser(description="Daily Unified Orchestrator")
    parser.add_argument("--tasks", type=str, default="", help="comma-separated task list (explicit mode)")
    args = parser.parse_args()
    print(f"Daily orchestrator start @ {bjt_now().strftime('%Y-%m-%d %H:%M:%S')} BJT")
    is_explicit = bool(args.tasks.strip())
    now_ts = time.time()
    if is_explicit:
        hard_deadline = now_ts + 86400
        hard_wall_str = "None (explicit task mode)"
    else:
        configured_wall = os.getenv("ORCH_HARD_DEADLINE", "19:55")
        wall_ts = _hm_today_ts(configured_wall)
        if wall_ts <= now_ts:
            hard_deadline = now_ts + 6 * 3600
            hard_wall_str = f"{configured_wall} BJT (past wall -> relaxed to +6h: {_fmt_bjt(hard_deadline)})"
        else:
            hard_deadline = wall_ts
            hard_wall_str = f"{configured_wall} BJT"

    orch = Orchestrator(hard_deadline)
    if is_explicit:
        build_explicit_timeline(orch, args.tasks)
    else:
        build_default_timeline(orch)
    print(f"Hard wall: {hard_wall_str}\n")
    sys.exit(orch.run())
if __name__ == "__main__":
    main()
