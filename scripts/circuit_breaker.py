#!/usr/bin/env python3
# new Env("统一重试与熔断管理器")
"""全任务统一时延分段重试与 8 次失败熔断停用管理器。

核心职能：
1. 全任务统一管理：所有 16+ 任务共享统一状态逻辑，单个签到脚本零冗余代码；
2. 分时段进行重试：按失败轮次阶梯计算下次重试时刻（15m, 30m, 45m, 1h, 1.5h, 2h, 3h），
   彻底解决反爬 WAF 时域拦截窗口（避免无效密集重试）；
3. 8 次为上限：单日累计尝试 8 次为绝对硬上限；
4. 熔断停用与等待修复上线：若 8 次仍未成功，立即触发熔断并停用任务，后续调度自动跳过，
   等待人工修复后通过 CLI 或 Actions 工作流参数主动重新上线。
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from common import BJT, load_kv_state, save_kv_state
from task_registry import TASKS

# 单日累计最大尝试次数上限（超过该次数立即熔断）
MAX_DAILY_ATTEMPTS = 8

# 分时段重试延时阶梯（秒）：对应第 1~7 次失败后距离下一次重试的等待时间
# 15分 -> 30分 -> 45分 -> 1小时 -> 1.5小时 -> 2小时 -> 3小时（累计达 9 小时时域跨度）
RETRY_INTERVALS: List[int] = [
    15 * 60,   # 1st fail -> wait 15 min (900s)
    30 * 60,   # 2nd fail -> wait 30 min (1800s)
    45 * 60,   # 3rd fail -> wait 45 min (2700s)
    60 * 60,   # 4th fail -> wait 60 min (3600s)
    90 * 60,   # 5th fail -> wait 90 min (5400s)
    120 * 60,  # 6th fail -> wait 120 min (7200s)
    180 * 60,  # 7th fail -> wait 180 min (10800s)
]


def _bjt_today() -> str:
    """获取当前北京时间日期（YYYY-MM-DD）。"""
    return dt.datetime.now(BJT).strftime("%Y-%m-%d")


def _bjt_now_ts() -> float:
    """获取当前北京时间 Unix 时间戳。"""
    return dt.datetime.now(BJT).timestamp()


def _state_paths(task_id: str) -> Tuple[str, str]:
    """获取任务状态在 Upstash Redis 与本地文件的存储路径。

    保持与 discord_notify.py 的存储契约 100% 对齐，共享 Actions 缓存与 Redis 键。
    """
    prefix = (os.getenv("CAT_CHECKIN_REDIS_PREFIX") or "cat_checkin:").rstrip(":")
    return f"{prefix}:state:notify:{task_id}", f".notify_state_{task_id}.json"


def load_circuit_state(task_id: str) -> Dict[str, Any]:
    """读取指定任务的重试与熔断状态字典。"""
    redis_key, state_file = _state_paths(task_id)
    state = load_kv_state(redis_key, state_file)
    return dict(state) if isinstance(state, dict) else {}


def save_circuit_state(task_id: str, state: Dict[str, Any]) -> None:
    """双通道持久化指定任务的重试与熔断状态字典。"""
    redis_key, state_file = _state_paths(task_id)
    save_kv_state(redis_key, state_file, state)


def is_task_suspended(task_id: str) -> bool:
    """检查任务当前是否处于熔断停用状态。"""
    state = load_circuit_state(task_id)
    return bool(state.get("circuit_broken")) or str(state.get("status") or "").lower() == "suspended"


def get_task_attempts_today(task_id: str) -> int:
    """获取指定任务今日已尝试的次数（跨日自动归零）。"""
    state = load_circuit_state(task_id)
    if str(state.get("attempt_date") or "") == _bjt_today():
        try:
            return int(state.get("attempts") or 0)
        except (TypeError, ValueError):
            return 0
    return 0


def save_suspended_result_record(task_id: str, reason: str = "") -> None:
    """在 .task_results/ 与 Upstash Redis 写入熔断停用结果，供统一日报与报告识别。"""
    cfg = TASKS.get(task_id) or {"id": task_id, "script": f"{task_id}.py"}
    out_dir = Path(os.getenv("TASK_OUTPUT_DIR", ".task_results"))
    out_dir.mkdir(parents=True, exist_ok=True)
    result_name = cfg.get("result") or f"{task_id}.json"
    if not result_name.endswith(".json"):
        result_name += ".json"
    today_bj = _bjt_today()
    record = {
        "name": cfg.get("name") or task_id,
        "script": cfg.get("script", f"{task_id}.py"),
        "ok": False,
        "status": "suspended",
        "circuit_broken": True,
        "date": today_bj,
        "elapsed": 0.0,
        "output": (
            f"🛑 任务已达 {MAX_DAILY_ATTEMPTS} 次失败上限，触发熔断停用！\n"
            f"原因：{reason or '单日持续执行失败'}\n"
            f"后续自动调度与重试已暂停，等待人工排查修复后重新上线。\n"
            f"上线指引：CLI `python3 scripts/circuit_breaker.py resume {task_id}` 或 Actions 手动调度勾选 reset_circuit"
        ),
        "timestamp": int(_bjt_now_ts()),
    }
    try:
        (out_dir / result_name).write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as exc:
        print(f"WARN: 保存熔断结果到本地文件失败: {exc}", file=sys.stderr)
    try:
        url = os.getenv("UPSTASH_REDIS_REST_URL", "")
        token = os.getenv("UPSTASH_REDIS_REST_TOKEN", "")
        if url and token:
            from common import upstash_redis_pipeline
            prefix = os.getenv("CAT_CHECKIN_REDIS_PREFIX", "cat_checkin:").rstrip(":")
            raw_key = f"{prefix}:raw:{today_bj}"
            res_json = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
            upstash_redis_pipeline([
                ["HSET", raw_key, result_name, res_json],
                ["EXPIRE", raw_key, 1209600],
            ])
    except Exception as exc:
        print(f"WARN: 保存熔断结果到 Redis 失败: {exc}", file=sys.stderr)


def trip_circuit_breaker(
    task_id: str,
    reason: str = f"单日连续失败已达 {MAX_DAILY_ATTEMPTS} 次上限，自动熔断停用",
    output: str = "",
) -> Dict[str, Any]:
    """将任务置为熔断停用状态并持久化。"""
    state = load_circuit_state(task_id)
    now_iso = dt.datetime.now(BJT).isoformat()
    state["status"] = "suspended"
    state["circuit_broken"] = True
    state["suspended_at"] = now_iso
    state["suspend_reason"] = reason
    state["updated_at"] = now_iso
    save_circuit_state(task_id, state)
    save_suspended_result_record(task_id, reason)
    print(f"🚨 [CIRCUIT_BREAKER] 任务 [{task_id}] 已触发熔断停用！原因: {reason}")
    try:
        from discord_notify import notify_circuit_breaker
        cfg = TASKS.get(task_id) or {}
        notify_circuit_breaker(
            task_id=task_id,
            reason=reason,
            output=output,
            name=cfg.get("name", task_id),
            script=cfg.get("script", f"{task_id}.py"),
        )
    except Exception as exc:
        print(f"WARN: Discord 熔断告警推送异常: {exc}", file=sys.stderr)
    return state


def resume_task(task_id: str, reason: str = "人工修复后重新上线") -> Dict[str, Any]:
    """人工修复后重新上线处于熔断状态的任务。

    清除熔断标记、重置当日尝试次数为 0，状态恢复为 active。
    """
    state = load_circuit_state(task_id)
    now_iso = dt.datetime.now(BJT).isoformat()
    state["status"] = "active"
    state["circuit_broken"] = False
    state["suspended_at"] = None
    state["suspend_reason"] = None
    state["attempts"] = 0
    state["next_retry_at"] = None
    state["updated_at"] = now_iso
    save_circuit_state(task_id, state)
    print(f"🔄 [CIRCUIT_BREAKER] 任务 [{task_id}] 已重新上线（{reason}）")
    return state


def resume_all_tasks(reason: str = "人工全量重新上线") -> List[str]:
    """重新上线所有处于熔断停用状态的任务。"""
    resumed = []
    for tid in TASKS.keys():
        if is_task_suspended(tid):
            resume_task(tid, reason=reason)
            resumed.append(tid)
    return resumed


def record_task_outcome(
    task_id: str,
    ok: bool,
    output: str = "",
) -> Tuple[Dict[str, Any], bool]:
    """全任务统一记录单次执行结果，自动计算时延分段重试或触发 8 次上限熔断。

    返回值：(更新后的状态字典, 是否刚触发了熔断停用)。
    """
    state = load_circuit_state(task_id)
    today = _bjt_today()
    now_ts = _bjt_now_ts()
    now_iso = dt.datetime.now(BJT).isoformat()

    # 跨日自动归零当日尝试计数
    if str(state.get("attempt_date") or "") == today:
        try:
            attempts = int(state.get("attempts") or 0) + 1
        except (TypeError, ValueError):
            attempts = 1
    else:
        attempts = 1

    state["updated_at"] = now_iso
    state["attempt_date"] = today
    state["attempts"] = attempts

    just_tripped = False

    if ok:
        # 任务成功：清除重试与熔断标记，记录上次成功日期
        state["last_ok_date"] = today
        state["fail_streak"] = 0
        state["circuit_broken"] = False
        state["status"] = "active"
        state["suspended_at"] = None
        state["suspend_reason"] = None
        state["next_retry_at"] = None
        save_circuit_state(task_id, state)
        return state, False

    # 任务失败
    state["last_fail_ts"] = now_ts

    if attempts >= MAX_DAILY_ATTEMPTS:
        # 达到 8 次上限，立即触发熔断停用！
        reason = f"单日连续失败已达 {MAX_DAILY_ATTEMPTS} 次上限（时域风控/持续故障熔断）"
        state["status"] = "suspended"
        state["circuit_broken"] = True
        state["suspended_at"] = now_iso
        state["suspend_reason"] = reason
        state["next_retry_at"] = None
        just_tripped = True
        save_suspended_result_record(task_id, reason)
        print(f"🛑 [CIRCUIT_BREAKER] 任务 [{task_id}] 今日已累计失败 {attempts}/{MAX_DAILY_ATTEMPTS} 次，触发熔断停用！停止后续执行。")
    else:
        # 未达上限：计算分时段下次重试时刻 (next_retry_at)
        idx = min(attempts - 1, len(RETRY_INTERVALS) - 1)
        delay_sec = RETRY_INTERVALS[idx]
        next_retry_ts = now_ts + delay_sec
        state["next_retry_at"] = next_retry_ts
        next_dt_str = dt.datetime.fromtimestamp(next_retry_ts, BJT).strftime("%H:%M:%S")
        print(
            f"🔁 [分时段重试] 任务 [{task_id}] 今日第 {attempts}/{MAX_DAILY_ATTEMPTS} 次失败，"
            f"安排在 {next_dt_str} BJT（{int(delay_sec // 60)} 分钟后）进行下次重试"
        )

    save_circuit_state(task_id, state)
    return state, just_tripped


def get_due_retries(task_ids: Optional[List[str]] = None) -> List[str]:
    """查询今日已失败、未熔断且当前已到达分时段重试时刻（next_retry_at <= now）的任务列表。"""
    today = _bjt_today()
    now_ts = _bjt_now_ts()
    pool = task_ids if task_ids is not None else list(TASKS.keys())
    due = []
    for tid in pool:
        state = load_circuit_state(tid)
        # 已熔断停用的任务不参与重试
        if bool(state.get("circuit_broken")) or str(state.get("status") or "").lower() == "suspended":
            continue
        # 今日有过尝试且非成功
        if str(state.get("attempt_date") or "") == today and int(state.get("attempts") or 0) > 0:
            if str(state.get("last_ok_date") or "") == today:
                continue
            next_at = float(state.get("next_retry_at") or 0)
            if next_at > 0 and next_at <= now_ts:
                due.append(tid)
    return due


def get_min_next_retry_delay(task_ids: Optional[List[str]] = None) -> Optional[int]:
    """计算当前距离下一个未到期重试任务的最小等待秒数（最小返回 60 秒）。"""
    today = _bjt_today()
    now_ts = _bjt_now_ts()
    pool = task_ids if task_ids is not None else list(TASKS.keys())
    delays = []
    for tid in pool:
        state = load_circuit_state(tid)
        if bool(state.get("circuit_broken")) or str(state.get("status") or "").lower() == "suspended":
            continue
        if str(state.get("attempt_date") or "") == today and int(state.get("attempts") or 0) > 0:
            if str(state.get("last_ok_date") or "") == today:
                continue
            next_at = float(state.get("next_retry_at") or 0)
            if next_at > now_ts:
                delays.append(int(next_at - now_ts))
    return max(60, min(delays)) if delays else None


def evaluate_retry_candidates(
    raw_tasks: str | List[str],
    max_attempts: int = MAX_DAILY_ATTEMPTS,
) -> Dict[str, Any]:
    """综合评估失败任务列表的重试资质与熔断状态，供 Actions 工作流步骤调用。"""
    today = _bjt_today()
    now_ts = _bjt_now_ts()

    if isinstance(raw_tasks, str):
        tasks = [t.strip() for t in raw_tasks.replace(",", " ").split() if t.strip()]
    else:
        tasks = list(raw_tasks)

    # 规范化为任务 ID（若传入的是 script 名如 agentrouter.py，映射为 agentrouter）
    normalized: List[str] = []
    for t in tasks:
        tid = t
        if t.endswith(".py"):
            tid = t[:-3]
        matched = next((k for k, v in TASKS.items() if k == tid or v.get("script") == t), tid)
        if matched not in normalized:
            normalized.append(matched)

    retryable: List[str] = []
    due_now: List[str] = []
    suspended: List[str] = []
    tripped: List[str] = []
    delays: List[int] = []

    for tid in normalized:
        state = load_circuit_state(tid)
        is_susp = bool(state.get("circuit_broken")) or str(state.get("status") or "").lower() == "suspended"
        att = int(state.get("attempts") or 0) if str(state.get("attempt_date") or "") == today else 0

        if is_susp:
            suspended.append(tid)
            continue

        if att >= max_attempts:
            # 达到上限，补触发熔断
            trip_circuit_breaker(tid, reason=f"单日累计失败达 {max_attempts} 次上限，自动熔断停用")
            tripped.append(tid)
            continue

        retryable.append(tid)
        next_at = float(state.get("next_retry_at") or 0)
        if next_at <= now_ts:
            due_now.append(tid)
        else:
            delays.append(int(next_at - now_ts))

    min_delay = max(60, min(delays)) if delays else None

    return {
        "today": today,
        "total_checked": len(normalized),
        "retryable": retryable,
        "due_now": due_now,
        "suspended": suspended,
        "tripped": tripped,
        "next_delay_seconds": min_delay,
    }


def cli_status(task_id: Optional[str] = None) -> None:
    """格式化打印指定任务或全量任务的重试与熔断状态表格。"""
    today = _bjt_today()
    now_ts = _bjt_now_ts()
    targets = [task_id] if task_id else list(TASKS.keys())

    print(f"\n{'='*75}")
    print(f"📊 任务重试与熔断状态列表（当前北京时间日期: {today}）")
    print(f"{'='*75}")
    print(f"{'任务 ID':<20} {'状态':<14} {'今日尝试':<10} {'下次重试':<14} {'上次成功':<12}")
    print(f"{'-'*75}")

    for tid in targets:
        st = load_circuit_state(tid)
        is_susp = bool(st.get("circuit_broken")) or str(st.get("status") or "").lower() == "suspended"
        att = int(st.get("attempts") or 0) if str(st.get("attempt_date") or "") == today else 0
        last_ok = str(st.get("last_ok_date") or "—")
        next_at = float(st.get("next_retry_at") or 0)

        if is_susp:
            status_desc = "🛑 熔断停用"
            next_desc = "等待修复"
        elif last_ok == today:
            status_desc = "✅ 今日成功"
            next_desc = "—"
        elif att > 0:
            status_desc = f"⚠️ 失败待试"
            if next_at <= now_ts:
                next_desc = "到期就绪"
            else:
                rem_min = max(1, int((next_at - now_ts) // 60))
                next_desc = f"{rem_min} 分钟后"
        else:
            status_desc = "⚪ 尚未执行"
            next_desc = "—"

        att_desc = f"{att}/{MAX_DAILY_ATTEMPTS}" if att > 0 else "0"
        print(f"{tid:<20} {status_desc:<14} {att_desc:<10} {next_desc:<14} {last_ok:<12}")

    print(f"{'='*75}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Unified Circuit Breaker & Time-Slot Retry Manager")
    sub = parser.add_subparsers(dest="subcommand", help="子命令")

    # status
    p_status = sub.add_parser("status", help="查看任务重试与熔断状态")
    p_status.add_argument("task_id", nargs="?", default=None, help="可选：指定任务 ID")

    # resume
    p_resume = sub.add_parser("resume", help="修复后重新上线处于熔断状态的任务")
    p_resume.add_argument("task_id", help="任务 ID，或 'all' 重新上线全部")
    p_resume.add_argument("--reason", default="人工修复后重新上线", help="上线原因记录")

    # suspend
    p_suspend = sub.add_parser("suspend", help="手动熔断停用指定任务")
    p_suspend.add_argument("task_id", help="任务 ID")
    p_suspend.add_argument("--reason", default="手动熔断停用", help="停用原因说明")

    # check-retry
    p_check = sub.add_parser("check-retry", help="评估失败站点的重试资质（供 CI 调用）")
    p_check.add_argument("tasks", help="逗号或空格分隔的任务列表")
    p_check.add_argument("--max-attempts", type=int, default=MAX_DAILY_ATTEMPTS, help="最大尝试上限")

    # get-due-retries
    sub.add_parser("get-due-retries", help="输出当前已到达分时段重试时刻的任务列表")

    args = parser.parse_args()

    if args.subcommand == "status":
        cli_status(args.task_id)
    elif args.subcommand == "resume":
        if args.task_id.lower() == "all":
            resumed = resume_all_tasks(reason=args.reason)
            print(f"✅ 已重新上线 {len(resumed)} 个熔断任务: {', '.join(resumed) if resumed else '无'}")
        else:
            resume_task(args.task_id, reason=args.reason)
    elif args.subcommand == "suspend":
        trip_circuit_breaker(args.task_id, reason=args.reason)
    elif args.subcommand == "check-retry":
        res = evaluate_retry_candidates(args.tasks, max_attempts=args.max_attempts)
        retryable_str = ",".join(res["retryable"])
        due_str = ",".join(res["due_now"])
        suspended_str = ",".join(res["suspended"] + res["tripped"])
        should_retry = "true" if res["retryable"] else "false"
        next_delay = res["next_delay_seconds"] or 0

        print(f"TOTAL_CHECKED={res['total_checked']}")
        print(f"SHOULD_RETRY={should_retry}")
        print(f"RETRYABLE_TASKS={retryable_str}")
        print(f"DUE_TASKS={due_str}")
        print(f"SUSPENDED_TASKS={suspended_str}")
        print(f"NEXT_DELAY_SECONDS={next_delay}")
    elif args.subcommand == "get-due-retries":
        due = get_due_retries()
        print(",".join(due))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

