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

from common import BJT, load_kv_state, save_kv_state, upstash_redis_command
from task_registry import TASKS

# 单日累计最大尝试次数上限（超过该次数立即熔断）
MAX_DAILY_ATTEMPTS = 8

def task_allows_auto_suspend(task_id: str) -> bool:
    """该任务是否允许被「8 次失败上限」自动熔断。

    注册表里标了 `no_auto_suspend` 的常驻任务（如 telecom-exchange 0点场抢兑）
    「错过即损失整场」，自动停用等于永久停跑——它由 rolling 自排程每天按时
    拉起，失败只写当日结果。人工 `circuit_breaker.py suspend` 不受此开关影响。
    注册表查不到时返回 True（保守沿用原行为）。
    """
    return not bool((TASKS.get(task_id) or {}).get("no_auto_suspend"))


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
    """获取熔断器专属状态在 Upstash Redis 与本地文件的存储路径。

    必须使用独立键 cat_checkin:cb:<task_id>（CLAUDE.md §4 拓扑），不得复用
    notify 状态键：discord_notify.notify_task_result 每次运行结束都会用
    「新建字典」整键覆盖 state:notify:<task_id>（只含 updated_at/attempt_date/
    attempts/last_ok_date/fail_streak/ok_streak），熔断器写入的 status/
    circuit_broken/next_retry_at/suspend_reason 会在同一次运行内被抹掉——
    resume 失效、熔断拦截失效、status 表格永远显示「尚未执行」
    （2026-11-19 复盘，与 rolling 键 2026-11-05 被覆盖同构）。
    """
    prefix = (os.getenv("CAT_CHECKIN_REDIS_PREFIX") or "cat_checkin:").rstrip(":")
    return f"{prefix}:cb:{task_id}", f".cb_state_{task_id}.json"


# 熔断器专属字段：旧实现曾把这些字段写进 notify 键，迁移时只认领这些字段，
# 绝不把 notify 的展示字段（ok_streak/warn_texts 等）带进 cb 状态。
_CB_OWNED_FIELDS = (
    "status", "circuit_broken", "suspended_at", "suspend_reason",
    "attempts", "attempt_date", "next_retry_at", "last_fail_ts",
    "last_ok_date", "fail_streak", "updated_at",
)


def _legacy_notify_state(task_id: str) -> Dict[str, Any]:
    """读取旧版共用的 notify 状态（只读迁移源，不回写）。

    与 cb 键同契约区分「确认不存在」与「读取失败」：notify 键读取失败时
    返回 _CB_READ_FAILED 标记（调用方禁止据此初始化写入），确认不存在
    时返回空 dict 允许初始化（PR #34 终局评审指认）。
    """
    prefix = (os.getenv("CAT_CHECKIN_REDIS_PREFIX") or "cat_checkin:").rstrip(":")
    key = f"{prefix}:state:notify:{task_id}"
    state_file = f".notify_state_{task_id}.json"
    state, confirmed_absent, read_failed = _load_cb_state_raw(key, state_file)
    if read_failed:
        state = dict(state)
        state[_CB_READ_FAILED] = True
        return state
    # 读取成功即有效：合法空字典 {}（键存在但无 owned 字段）允许正常初始化；
    # 无效 JSON / 读取异常已由 _load_cb_state_raw 归入 read_failed
    # （PR #34 第十一轮评审指认，不得把有效空态判为读取失败）
    return state


# 内部标记：读取失败（无法确认状态）时附加在返回字典上，绝不持久化。
# 消费方（is_task_suspended / record_task_outcome / get_due_retries 等）据此
# fail-closed 处理：不调度、不覆盖写入（PR #34 full review 指认）。
_CB_READ_FAILED = "_read_failed"


def _load_cb_state_raw(redis_key: str, state_file: str) -> Tuple[Dict[str, Any], bool, bool]:
    """单次读取 cb 状态，返回 (状态字典, 是否确认缺键, 是否读取失败)。

    「确认缺键」= 本地文件无有效数据 且 Redis 明确返回 nil（GET 成功但
    result 为空）。读取失败（网络异常/HTTP 错误）返回 ({}, False)——既不
    迁移也不覆盖，让本次记录按新任务计 1 次尝试（PR #34 两轮评审指认：
    二次 GET 探测存在 TOCTOU 竞争，必须一次读取同时判定存在性与数据）。
    凭据未配置（纯本地模式）：文件缺失即确认缺键。
    """
    state: Dict[str, Any] = {}
    local_ok = False
    local_read_failed = False
    try:
        if os.path.exists(state_file):
            with open(state_file, encoding="utf-8") as f:
                data = json.loads(f.read())
            if isinstance(data, dict):
                state.update(data)
                local_ok = True
            else:
                local_read_failed = True  # 文件存在但结构不符
    except Exception:
        local_read_failed = True  # 文件存在但损坏/不可读 ≠ 确认缺键
    try:
        from common import _upstash_redis_env
        url, token = _upstash_redis_env()
        if not url or not token:
            # 纯本地模式：文件有效→用文件；文件确实不存在→确认缺键（可迁移）
            if local_read_failed:
                return state, False, True
            return state, (not local_ok), False
        ok, res = upstash_redis_command(["GET", redis_key])
        if not ok:
            # 读取失败：本地有数据则用本地（不迁移），否则无法确认（fail-closed）
            return state, False, (not local_ok or local_read_failed)
        raw_val = res.get("result") if isinstance(res, dict) else None
        if raw_val is None or raw_val == "":
            # Redis 明确 nil：键不存在。本地有数据时以本地为准不迁移；
            # 本地文件损坏时仍属读取失败，不可迁移（full review 指认）
            if local_read_failed:
                return state, False, True
            return state, (not local_ok), False
        if isinstance(raw_val, str):
            try:
                remote = json.loads(raw_val)
                if isinstance(remote, dict):
                    if local_ok:
                        # cb 字典是整份替换型快照，按 updated_at 时间戳择新：
                        # - 本地更新（本地熔断写入成功 + Redis SET 失败）→ 用本地，
                        #   不被远端旧 active 抹掉停用标记（PR #34 第十三轮）
                        # - 远端更新（CI 缓存恢复到数个 run 前的陈旧 active 文件，
                        #   而 Redis 已有较新 suspended）→ 用远端，防止陈旧缓存
                        #   复活已熔断任务并在下次 save 时永久抹掉熔断（终局自审）
                        # - 时间戳缺失/不可比 → 保守用本地（不降级已写入的熔断）
                        def _ts(d):
                            try:
                                return dt.datetime.fromisoformat(str(d.get("updated_at") or "")).timestamp()
                            except (ValueError, TypeError):
                                return 0.0
                        if _ts(remote) > _ts(state):
                            return dict(remote), False, False
                        return state, False, False
                    state.update(remote)
                    return state, False, False
            except Exception:
                pass
        # 键存在但值非空且无法解析/结构不符（如 "[]"、损坏 JSON）：
        # 不是缺键，禁止迁移——否则旧 notify 熔断标记会覆盖现存值
        # （PR #34 第三轮评审指认）。本地有数据用本地，否则空状态不迁移。
        return state, False, (not local_ok or local_read_failed)
    except Exception:
        return state, False, True


def load_circuit_state(task_id: str) -> Dict[str, Any]:
    """读取指定任务的重试与熔断状态字典（cb 专属键，缺失时一次性认领旧 notify 字段）。

    迁移语义：仅当单次读取确认 cb 键不存在时，从旧 notify 键只认领
    _CB_OWNED_FIELDS 中存在的字段（含熔断标记，保证升级前已停用的任务不会
    因换键而「复活」）；cb 键一旦存在即为权威，不再回读 notify——notify 键
    里的 circuit_broken 可能是 discord_notify 推送熔断卡时留下的陈旧标记
    （该函数只置位不清除）。读取失败不迁移：返回空状态，绝不把陈旧熔断
    标记写回 cb。
    """
    redis_key, state_file = _state_paths(task_id)
    state, confirmed_absent, read_failed = _load_cb_state_raw(redis_key, state_file)
    if not state and confirmed_absent and not read_failed:
        legacy = _legacy_notify_state(task_id)
        if legacy.get(_CB_READ_FAILED):
            # 旧 notify 键读取失败：同样 fail-closed，不得据残缺数据迁移
            # （标记不在 _CB_OWNED_FIELDS 中，必须显式传播，PR #34 终局评审）
            read_failed = True
        else:
            state = {k: legacy[k] for k in _CB_OWNED_FIELDS if k in legacy}
    if read_failed:
        # 非持久化标记：调用方据此 fail-closed（不调度、不覆盖写入）
        state = dict(state)
        state[_CB_READ_FAILED] = True
    return state


def save_circuit_state(task_id: str, state: Dict[str, Any]) -> Tuple[bool, bool]:
    """双通道持久化指定任务的重试与熔断状态字典。

    返回 (本地写入成功?, 权威写入确认?)。保存边界强制剔除内部标记
    （_read_failed 绝不落盘）。读取失败时写入入口应停止调用本函数；
    此处的过滤是最后一道防线。权威确认语义见 common.save_kv_state：
    配置 Redis 时必须 SET 成功，纯本地模式本地写入成功即确认
    （PR #34 第十三轮评审指认）。本地写入结果单独返回，供调用方区分
    「本地已生效/远端未确认」与「本地+远端均未落盘」（第十五轮评审）。
    """
    redis_key, state_file = _state_paths(task_id)
    clean = {k: v for k, v in state.items() if k != _CB_READ_FAILED}
    local_ok, confirmed = save_kv_state(redis_key, state_file, clean)
    return local_ok, confirmed


def is_task_suspended(task_id: str) -> bool:
    """检查任务当前是否处于熔断停用状态。

    读取失败（Redis GET 失败且无本地 cb 文件）时 fail-closed：按已停用
    处理，防止把真实停用的任务重新调度（PR #34 full review 指认）。
    """
    state = load_circuit_state(task_id)
    if state.get(_CB_READ_FAILED):
        return True
    return bool(state.get("circuit_broken")) or str(state.get("status") or "").lower() == "suspended"


def get_task_attempts_today(task_id: str) -> int:
    """获取指定任务今日已尝试的次数（跨日自动归零）。

    读取失败时返回 MAX_DAILY_ATTEMPTS（fail-closed）：不得以 0 冒充「今日
    未尝试」让配额判断 fail-open 放行未知状态的任务，与 is_task_suspended /
    get_due_retries 的 fail-closed 方向一致（PR #34 终局自审指认）。
    """
    state = load_circuit_state(task_id)
    if state.get(_CB_READ_FAILED):
        return MAX_DAILY_ATTEMPTS
    if str(state.get("attempt_date") or "") == _bjt_today():
        return _safe_attempts(state)
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
    if state.get(_CB_READ_FAILED):
        # 保留标记返回：调用方（evaluate_retry_candidates）据此区分
        # 「熔断写入完成」与「读取失败拒写」，不得虚报 tripped
        # （PR #34 第十二轮评审指认，规则 9a(1)）
        print(f"⚠️ [CIRCUIT_BREAKER] [{task_id}] 状态读取失败，跳过熔断写入（fail-closed）",
              file=sys.stderr)
        return state
    now_iso = dt.datetime.now(BJT).isoformat()
    state["status"] = "suspended"
    state["circuit_broken"] = True
    state["suspended_at"] = now_iso
    state["suspend_reason"] = reason
    state["updated_at"] = now_iso
    _local_ok, confirmed = save_circuit_state(task_id, state)
    if not confirmed:
        # 权威写入未确认（Redis SET 失败）：不得宣称已停用——远端仍是旧状态，
        # 下次读取会还原本任务为 active。保留失败标记交调用方 fail-closed
        # （PR #34 第十三轮评审指认）
        print(f"⚠️ [CIRCUIT_BREAKER] [{task_id}] 熔断状态权威写入未确认，不报告停用（fail-closed）",
              file=sys.stderr)
        state[_CB_READ_FAILED] = True
        return state
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
    读取失败时拒绝写入（无法确认真实状态，避免标记污染持久状态）。
    """
    state = load_circuit_state(task_id)
    if state.get(_CB_READ_FAILED):
        # 保留标记返回：调用方（resume_all_tasks）据此区分「拒绝写入」与
        # 「成功恢复」，不得把失败任务计入 resumed（PR #34 终局评审）
        print(f"⚠️ [CIRCUIT_BREAKER] [{task_id}] 状态读取失败，拒绝 resume 写入（fail-closed）",
              file=sys.stderr)
        return state
    now_iso = dt.datetime.now(BJT).isoformat()
    state["status"] = "active"
    state["circuit_broken"] = False
    state["suspended_at"] = None
    state["suspend_reason"] = None
    state["attempts"] = 0
    state["next_retry_at"] = None
    state["updated_at"] = now_iso
    local_ok, confirmed = save_circuit_state(task_id, state)
    if not confirmed:
        # 区分两种未确认情形（PR #34 第十五轮评审：save 返回 False 不证明本地
        # 写入成功，纯本地模式文件写失败时不得谎称「本地恢复已生效」）：
        # - 本地成功 + 远端失败：本地 active 快照已生效（load 本地优先 →
        #   is_task_suspended=False，调度器会跑），但 Redis 仍是旧熔断态
        # - 本地 + 远端均失败：原 suspended 文件未改变，恢复完全未生效
        # 两种都保留 _CB_READ_FAILED 让 resume_all_tasks 排除（不算完整恢复）。
        if local_ok:
            print(f"⚠️ [CIRCUIT_BREAKER] [{task_id}] 本地恢复已生效，但远端权威写入未确认"
                  f"（Redis 仍是旧熔断态，需重试远端写入）", file=sys.stderr)
        else:
            print(f"⚠️ [CIRCUIT_BREAKER] [{task_id}] 恢复写入失败（本地+远端均未落盘），"
                  f"任务仍处熔断态，需人工排查", file=sys.stderr)
        state[_CB_READ_FAILED] = True
        return state
    print(f"🔄 [CIRCUIT_BREAKER] 任务 [{task_id}] 已重新上线（{reason}）")
    return state


_AUTO_TRIP_REASON_MARKERS = (
    "8 次上限",
    "单日累计失败达",
    "单日连续失败已达",
    f"{MAX_DAILY_ATTEMPTS} 次上限",
)


def reconcile_constant_task_suspensions() -> List[str]:
    """把历史上被「8 次上限」自动停用的常驻任务恢复上线。

    2026-11-22：telecom-exchange 这类每日必跑任务不再参与自动熔断。但旧规则
    可能已经把它的状态写成 suspended——不清理的话 rolling 自排程永远拉不起它
    （plan_due_tasks 直接跳过 suspended），规则改了也等于没改。

    只处理注册表标了 `no_auto_suspend` 的任务，且 suspend_reason 必须命中自动
    熔断文案；人工 `suspend`（原因自定义）一律不动。写入未确认的不计入返回值。
    """
    resumed: List[str] = []
    for tid, cfg in TASKS.items():
        if not cfg.get("no_auto_suspend"):
            continue
        state = load_circuit_state(tid)
        if state.get(_CB_READ_FAILED):
            continue
        if not (
            state.get("circuit_broken")
            or str(state.get("status") or "").lower() == "suspended"
        ):
            continue
        reason = str(state.get("suspend_reason") or "")
        if not any(marker in reason for marker in _AUTO_TRIP_REASON_MARKERS):
            continue
        st = resume_task(
            tid,
            reason="常驻任务（no_auto_suspend）不再适用 8 次上限自动熔断，自动恢复上线",
        )
        if st and not st.get(_CB_READ_FAILED):
            resumed.append(tid)
    return resumed


def resume_all_tasks(reason: str = "人工全量重新上线") -> List[str]:
    """重新上线所有处于熔断停用状态的任务。"""
    resumed = []
    for tid in TASKS.keys():
        if is_task_suspended(tid):
            st = resume_task(tid, reason=reason)
            if not st.get(_CB_READ_FAILED):
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

    if state.pop(_CB_READ_FAILED, None):
        # 状态读取失败时绝不写回初始化状态：可能覆盖 Redis 侧真实的熔断标记
        print(f"⚠️ [CIRCUIT_BREAKER] [{task_id}] 状态读取失败，跳过本次状态写入（fail-closed）",
              file=sys.stderr)
        return state, False

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
        _local_ok, confirmed = save_circuit_state(task_id, state)
        if not confirmed:
            print(f"⚠️ [CIRCUIT_BREAKER] [{task_id}] 成功状态权威写入未确认（远端可能仍是旧失败态）",
                  file=sys.stderr)
        return state, False

    # 任务失败
    state["last_fail_ts"] = now_ts

    # 常驻任务（registry 标记 no_auto_suspend）不参与 8 次上限自动熔断。
    # 例：telecom-exchange 0点场抢兑「错过即损失整场」，自动停用等于永久停跑；
    # 它会由 rolling 自排程每天按时拉起，失败原因写进当日结果即可。
    # 手动 `circuit_breaker.py suspend` 仍然有效（trip_circuit_breaker 不经此处）。
    no_auto_suspend = not task_allows_auto_suspend(task_id)

    if no_auto_suspend:
        # 常驻任务：只记账，不自动停用、也不排框架重试阶梯（心跳 get-due-retries
        # 会按 next_retry_at 拉起任务，多出来的白天跑与自排程打架）。节奏完全
        # 交给 rolling 的 due_at；手工 suspend 留下的 status/circuit_broken 不动。
        state["next_retry_at"] = None
        _local_ok, confirmed = save_circuit_state(task_id, state)
        if not confirmed:
            print(f"⚠️ [CIRCUIT_BREAKER] [{task_id}] 常驻任务失败计数权威写入未确认",
                  file=sys.stderr)
        print(
            f"🛡️ [常驻任务] [{task_id}] 今日第 {attempts} 次失败"
            f"（上限 {MAX_DAILY_ATTEMPTS} 仅作参考），该任务为每日必跑"
            f"（no_auto_suspend），不自动熔断、不排框架重试，交由自排程继续下一场次。"
        )
    elif attempts >= MAX_DAILY_ATTEMPTS:
        # 达到 8 次上限，立即触发熔断停用！
        reason = f"单日连续失败已达 {MAX_DAILY_ATTEMPTS} 次上限（时域风控/持续故障熔断）"
        state["status"] = "suspended"
        state["circuit_broken"] = True
        state["suspended_at"] = now_iso
        state["suspend_reason"] = reason
        state["next_retry_at"] = None
        # 停用结果记录与文案必须在权威写入确认之后才落盘/输出——否则 Redis
        # SET 失败时日报与操作人员仍收到「已停用」结论（PR #34 第十四轮评审）
        _local_ok, confirmed = save_circuit_state(task_id, state)
        if confirmed:
            just_tripped = True
            save_suspended_result_record(task_id, reason)
            print(f"🛑 [CIRCUIT_BREAKER] 任务 [{task_id}] 今日已累计失败 {attempts}/{MAX_DAILY_ATTEMPTS} 次，触发熔断停用！停止后续执行。")
        else:
            print(f"⚠️ [CIRCUIT_BREAKER] [{task_id}] 熔断状态权威写入未确认，不报告停用（fail-closed）",
                  file=sys.stderr)
            state[_CB_READ_FAILED] = True
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
        _local_ok, confirmed = save_circuit_state(task_id, state)
        if not confirmed:
            print(f"⚠️ [CIRCUIT_BREAKER] [{task_id}] 重试状态权威写入未确认（远端可能仍是旧值）",
                  file=sys.stderr)
    return state, just_tripped


def _safe_attempts(state: Dict[str, Any]) -> int:
    """attempts 字段类型保护：迁移/手工写入可能留下非数字值（如 '7次'），
    int() 直抛 ValueError 会让 get-due-retries/check-retry CLI traceback 退出、
    自动重试链路静默停摆（PR #34 终局自审指认）。畸形值按 0 处理。"""
    try:
        return int(state.get("attempts") or 0)
    except (TypeError, ValueError):
        return 0


def _safe_next_retry(state: Dict[str, Any]) -> float:
    """next_retry_at 字段类型保护（同 _safe_attempts）。"""
    try:
        return float(state.get("next_retry_at") or 0)
    except (TypeError, ValueError):
        return 0.0


def get_due_retries(task_ids: Optional[List[str]] = None) -> List[str]:
    """查询今日已失败、未熔断且当前已到达分时段重试时刻（next_retry_at <= now）的任务列表。"""
    today = _bjt_today()
    now_ts = _bjt_now_ts()
    pool = task_ids if task_ids is not None else list(TASKS.keys())
    due = []
    for tid in pool:
        state = load_circuit_state(tid)
        # 读取失败 fail-closed：不调度
        if state.get(_CB_READ_FAILED):
            continue
        # 已熔断停用的任务不参与重试
        if bool(state.get("circuit_broken")) or str(state.get("status") or "").lower() == "suspended":
            continue
        # 今日有过尝试且非成功
        if str(state.get("attempt_date") or "") == today and _safe_attempts(state) > 0:
            if str(state.get("last_ok_date") or "") == today:
                continue
            next_at = _safe_next_retry(state)
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
        if state.get(_CB_READ_FAILED):
            continue
        if bool(state.get("circuit_broken")) or str(state.get("status") or "").lower() == "suspended":
            continue
        if str(state.get("attempt_date") or "") == today and _safe_attempts(state) > 0:
            if str(state.get("last_ok_date") or "") == today:
                continue
            next_at = _safe_next_retry(state)
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

    # 规范化为任务 ID。脚本名（如 telecom.py）可能同时服务多个注册任务
    # （telecom.py = telecom 每日签到 + telecom-exchange 抢兑），必须映射到
    # 「全部」共用该脚本的任务——只取首个 id 匹配会把重试接力点到未失败的
    # 任务上，真正失败的任务反而无人接力（2026-11-05 复盘）。
    normalized: List[str] = []
    for t in tasks:
        if t.endswith(".py"):
            matched = [k for k, v in TASKS.items() if v.get("script") == t]
            if not matched:
                matched = [t[:-3]]
        else:
            matched = [t]
        for tid in matched:
            if tid not in normalized:
                normalized.append(tid)

    retryable: List[str] = []
    due_now: List[str] = []
    suspended: List[str] = []
    tripped: List[str] = []
    delays: List[int] = []

    for tid in normalized:
        state = load_circuit_state(tid)
        if state.get(_CB_READ_FAILED):
            suspended.append(tid)
            continue
        is_susp = bool(state.get("circuit_broken")) or str(state.get("status") or "").lower() == "suspended"
        att = _safe_attempts(state) if str(state.get("attempt_date") or "") == today else 0

        if is_susp:
            suspended.append(tid)
            continue

        # 重试评估器只面向「今日确有失败」的任务：昨日/陈旧状态（attempt_date
        # 非今日）不算失败——否则从未参与今日执行的任务（如 stale 的 telecom）
        # 会被误判为可重试并立即到期，触发 0s 延时接力空转（2026-11-05 复盘）。
        if att <= 0 or str(state.get("last_ok_date") or "") == today:
            continue

        if att >= max_attempts:
            if not task_allows_auto_suspend(tid):
                # 常驻任务：达到上限也不补熔断，交由 rolling 自排程继续下一场次
                retryable.append(tid)
                continue
            # 达到上限，补触发熔断；仅在熔断写入确认完成后才报 tripped，
            # 二次读取失败拒写时归入 suspended（fail-closed 不调度），
            # 不得虚报 SUSPENDED_TASKS（PR #34 第十二轮评审指认）
            st = trip_circuit_breaker(tid, reason=f"单日累计失败达 {max_attempts} 次上限，自动熔断停用")
            if st.get(_CB_READ_FAILED):
                suspended.append(tid)
            else:
                tripped.append(tid)
            continue

        retryable.append(tid)
        next_at = _safe_next_retry(state)
        # next_retry_at 缺失/零值（如从旧 notify 键迁移、discord_notify 从不写
        # 该字段）≠「立即到期」：与 get_due_retries 的 next_at>0 闸门对齐，
        # 不得跳过退避梯子把当日配额快速打光（PR #34 终局自审指认）。
        # 无排定时刻的任务仍计入 retryable（可重试），但不进 due_now。
        if next_at > 0 and next_at <= now_ts:
            due_now.append(tid)
        elif next_at > now_ts:
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


def _redis_channel_status() -> str:
    """探测 Upstash Redis 通道可用性（状态表格的数据源健康提示）。

    未配置凭据时 load_kv_state 静默降级为本地文件——本地没有 CI 缓存文件时
    全表显示「尚未执行」，与真实 CI 状态完全脱节。表格必须明示数据源，
    否则会把「读不到状态」误读成「任务没跑过」（2026-11-19 用户指认）。
    """
    try:
        from common import _upstash_redis_env
        url, token = _upstash_redis_env()
        if not url or not token:
            return "⚠️ 未配置 UPSTASH_REDIS_REST_URL/TOKEN，仅显示本地缓存（CI 真实状态不可见）"
        ok, res = upstash_redis_command(["PING"])
        # ok=True 只表示 HTTP 200；必须确认响应 result=="PONG" 才显示在线
        # （PR #34 full review 指认：禁止无依据的乐观文案）
        if ok and isinstance(res, dict) and res.get("result") == "PONG":
            return "☁️ Upstash Redis 在线（权威状态）+ 本地缓存"
        return "⚠️ Upstash Redis 不可达或响应异常，仅显示本地缓存（可能滞后于 CI 真实状态）"
    except Exception as exc:
        return f"⚠️ Redis 通道探测异常（{type(exc).__name__}），仅显示本地缓存"


def cli_status(task_id: Optional[str] = None) -> None:
    """格式化打印指定任务或全量任务的重试与熔断状态表格。"""
    today = _bjt_today()
    now_ts = _bjt_now_ts()
    targets = [task_id] if task_id else list(TASKS.keys())

    print(f"\n{'='*75}")
    print(f"📊 任务重试与熔断状态列表（当前北京时间日期: {today}）")
    print(f"数据源: {_redis_channel_status()}")
    print(f"{'='*75}")
    print(f"{'任务 ID':<20} {'状态':<14} {'今日尝试':<10} {'下次重试':<14} {'上次成功':<12}")
    print(f"{'-'*75}")

    for tid in targets:
        st = load_circuit_state(tid)
        if st.get(_CB_READ_FAILED):
            # 读取失败：如实标注「状态不可读」，不得渲染成「尚未执行/0 次」
            # 误导用户以为任务从未跑过（PR #34 终局自审指认）
            print(f"{tid:<20} {'❓ 状态不可读':<14} {'—':<10} {'—':<14} {'—':<12}")
            continue
        is_susp = bool(st.get("circuit_broken")) or str(st.get("status") or "").lower() == "suspended"
        att = _safe_attempts(st) if str(st.get("attempt_date") or "") == today else 0
        last_ok = str(st.get("last_ok_date") or "—")
        next_at = _safe_next_retry(st)

        if is_susp:
            status_desc = "🛑 熔断停用"
            next_desc = "等待修复"
        elif last_ok == today:
            status_desc = "✅ 今日成功"
            next_desc = "—"
        elif att > 0:
            status_desc = "⚠️ 失败待试"
            if next_at <= 0:
                # 失败但没有重试时刻（状态被部分覆盖/写入中断）：不能显示
                # 「到期就绪」误导立即重试，如实标注缺失
                next_desc = "未排定"
            elif next_at <= now_ts:
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

