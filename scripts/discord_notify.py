#!/usr/bin/env python3
# new Env("Discord Webhook 通知")
"""Discord Webhook 通知模块：单任务完成即时推送（成功/失败双维度卡片）。

daily_orchestrator.py 每个任务完成瞬间调用 notify_task_progress，按结果推
成功卡（templates/discord_success.json）或失败卡（templates/discord_failure.json）。
统一汇总推送已下线（2026-08-28）：任务级即时播报取代统一报告。

卡片字段（简约版，无耗时 / 无输出摘要）：
  成功卡：账号(脱敏) / 连签进度 / 奖励明细 / 当前资产 / 上次签到成功日期
  失败卡：失败原因 / 账号(脱敏) / 连签进度 / 当前资产 / 上次签到成功日期(距今N天)
排版采用 description 正文行（加粗标签 + 值），不用 fields 网格——
inline 字段在窄屏/多列时挤压错位，正文行渲染更干净。

「上次签到成功日期 / 连续失败次数」按 task_id 记 KV 状态：
  Redis cat_checkin:state:notify:<task_id> + 本地 .notify_state_<task_id>.json
  （common.load_kv_state / save_kv_state 双通道，best-effort 绝不影响推送）。

Environment:
  DISCORD_WEBHOOK_URL  Discord Webhook 地址；未设置时使用下方内置默认 URL。
所有推送均为 best-effort：任何异常只打印警告，绝不阻塞/中断主流程。
"""
from __future__ import annotations

import datetime
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# 内置默认 Webhook（env DISCORD_WEBHOOK_URL 优先；更换地址时改 env 或此处）
DEFAULT_WEBHOOK_URL = (
    "https://discord.com/api/webhooks/1542881396656316459/"
    "tUZ1qvAHLHYmUOzakWTmoApidntcJsVYFd4cVhgr-znGwUcTWZbwmqEkaz9tHIqfpRdM"
)

COLOR_OK = 3066993      # 绿
COLOR_FAIL = 15158332   # 红

# Discord embed 限制：标题 ≤ 256、字段 value ≤ 1024、总 payload ≤ 6000
REASON_MAX_LEN = 200

BJT = datetime.timezone(datetime.timedelta(hours=8))

# 脱敏账号标识：各脚本统一经 common.mask_str 输出，特征是含 ** 掩码的短 token
_MASKED_TOKEN_RE = re.compile(r"[A-Za-z0-9_+\-.@]*[A-Za-z0-9_+\-.]\*{2,}[A-Za-z0-9_+\-.@]*")
# 账号标识行标记（命中优先从这些行取账号）
_ACCOUNT_MARKERS = ("用户", "账号", "用户名", "会员", "uid", "email", "邮箱", "昵称", "nickname")
# 凭证类行不参与账号提取（掩码后的 Token/令牌不是账号名）
_CREDENTIAL_LINE_KEYWORDS = ("refresh", "new rt", "rt =", "新 token", "令牌", "authorization", "session=")


def webhook_url() -> str:
    return (os.getenv("DISCORD_WEBHOOK_URL") or "").strip() or DEFAULT_WEBHOOK_URL


def _load_template(name: str, fallback: Dict[str, Any]) -> Dict[str, Any]:
    """读取指定模板 JSON；缺失/损坏时回退内置模板（与 email 模板同策略）。"""
    try:
        tpl = json.loads((TEMPLATE_DIR / name).read_text(encoding="utf-8"))
        if isinstance(tpl, dict):
            # 剥离模板内的说明性键（如 _comment），Discord API 拒绝未知字段
            return {k: v for k, v in tpl.items() if not k.startswith("_")}
        return fallback
    except Exception:
        return fallback


def _render(obj: Any, replacements: Dict[str, str]) -> Any:
    """递归替换模板中所有字符串值里的 {{PLACEHOLDER}} 占位符。"""
    if isinstance(obj, str):
        for key, value in replacements.items():
            obj = obj.replace(key, value)
        return obj
    if isinstance(obj, dict):
        return {k: _render(v, replacements) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_render(v, replacements) for v in obj]
    return obj


def _coerce_embed_colors(payload: Dict[str, Any]) -> None:
    """模板渲染后 color 为字符串，Discord 要求 embed.color 必须是整数。"""
    for embed in payload.get("embeds", []) or []:
        color = embed.get("color")
        if isinstance(color, str) and color.lstrip("-").isdigit():
            embed["color"] = int(color)


def _post_webhook(payload: Dict[str, Any]) -> bool:
    """POST 到 Discord Webhook。common.Http 自带 429/5xx 指数退避重试。"""
    try:
        _coerce_embed_colors(payload)
        import common as _common
        resp = _common.Http().request(
            "POST",
            webhook_url(),
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            timeout=15,
        )
        if 200 <= resp.code < 300:
            return True
        print(f"⚠️ Discord 推送失败: HTTP {resp.code} {(resp.text or '')[:200]}")
    except Exception as exc:
        print(f"⚠️ Discord 推送异常: {exc}")
    return False


def _timestamp_bjt() -> str:
    return datetime.datetime.now(BJT).isoformat()


def _bjt_today() -> str:
    return datetime.datetime.now(BJT).strftime("%Y-%m-%d")


# === 输出 → 卡片字段提取 ===

def _extract_fields(output: str) -> Dict[str, str]:
    """复用 daily_report 的启发式字段提取（连签/奖励/资产等）。"""
    try:
        from daily_report import _extract_fields as _ef
        data = _ef(output or "")
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _extract_accounts(output: str) -> str:
    """提取脱敏账号标识。优先取带 用户/账号/UID 等标记的行，多账号显示第一个 + 总数。

    每行只取第一个掩码 token（modelscope 的 user_tag 是「昵称 UID:x*** [Cookie]」，
    昵称在前；逐 token 计数会把同一账号的 UID 误算成一个账号）。
    """
    marker_hits: List[str] = []
    other_hits: List[str] = []
    seen: set[str] = set()
    for line in (output or "").splitlines():
        low = line.lower()
        if any(k in low for k in _CREDENTIAL_LINE_KEYWORDS):
            continue
        m = _MASKED_TOKEN_RE.search(line)
        if not m:
            continue
        tok = m.group(0).strip("._-")
        if len(tok) < 2 or tok in seen:
            continue
        seen.add(tok)
        if any(k in low for k in _ACCOUNT_MARKERS):
            marker_hits.append(tok)
        else:
            other_hits.append(tok)
    picked = marker_hits or other_hits
    if not picked:
        return "—"
    if len(picked) == 1:
        return picked[0]
    return f"{picked[0]} 等 {len(picked)} 个账号"


def _streak_text(fields: Dict[str, str], output: str) -> str:
    """连签进度：连续 N 天（+ 下一里程碑提示）。"""
    parts: List[str] = []
    streak = (fields.get("streak") or "").strip()
    if streak:
        parts.append(f"连续 {streak}")
    m = re.search(r"再连签\s*(\d+)\s*天可额外领\s*(.+?)[)）]\s*$", output or "", re.M)
    if m:
        parts.append(f"再签 {m.group(1)} 天可领 {m.group(2).strip()}")
    return " · ".join(parts) if parts else "—"


def _reward_text(fields: Dict[str, str]) -> str:
    """奖励明细：获得 X · 兑换/赠送 · 剩余 Y 天 · 多账号汇总。"""
    parts: List[str] = []
    if fields.get("reward"):
        parts.append("获得 " + " · ".join(fields["reward"].split(" | ")))
    if fields.get("exchange"):
        parts.append(str(fields["exchange"]))
    if fields.get("remaining"):
        parts.append(f"剩余 {fields['remaining']}")
    if fields.get("summary"):
        parts.append(str(fields["summary"]))
    return " · ".join(parts) if parts else "—"


def _assets_text(fields: Dict[str, str]) -> str:
    """当前资产：余额/积分/Token 等各站计量单位聚合。"""
    assets = (fields.get("assets") or "").strip()
    return assets.replace(" | ", " · ") if assets else "—"


# 强错误特征（HTTP 状态码/异常/失效等）与汇总行特征（失败原因要取真因，不要「执行完毕」汇总）
_STRONG_ERROR_RE = re.compile(
    r"(HTTP\s?\d{3}|Traceback|Error|Exception|失效|超时|无法|登录失败|执行异常|退出码)", re.I
)
_SUMMARY_LINE_RE = re.compile(r"(执行完毕|总结|共有\s*\d+\s*个|成功\s*\d+\s*/\s*\d+)")


def _one_line_error(output: str) -> str:
    """失败原因单行摘要：优先含强错误特征的非汇总行，再回退末尾有效行，压平空白后截断。"""
    lines = [ln.strip() for ln in (output or "").splitlines() if ln.strip()]
    line = ""
    for ln in reversed(lines):
        if _STRONG_ERROR_RE.search(ln) and not _SUMMARY_LINE_RE.search(ln):
            line = ln
            break
    if not line:
        try:
            from daily_report import _last_meaningful_line
            line = _last_meaningful_line(output or "")
        except Exception:
            line = ""
    if not line:
        candidates = [ln for ln in reversed(lines) if not _SUMMARY_LINE_RE.search(ln)]
        line = candidates[0] if candidates else (lines[-1] if lines else "")
    line = re.sub(r"\s+", " ", line).strip()
    if not line:
        return "未知错误（详见 CI 日志）"
    return line[:REASON_MAX_LEN] + ("…" if len(line) > REASON_MAX_LEN else "")


# === 按 task_id 的通知状态（上次成功日期 / 连续失败次数） ===

def _state_paths(task_id: str) -> tuple[str, str]:
    prefix = (os.getenv("CAT_CHECKIN_REDIS_PREFIX") or "cat_checkin:").rstrip(":")
    return f"{prefix}:state:notify:{task_id}", f".notify_state_{task_id}.json"


def _load_notify_state(task_id: str) -> Dict[str, Any]:
    try:
        from common import load_kv_state
        redis_key, state_file = _state_paths(task_id)
        data = load_kv_state(redis_key, state_file)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_notify_state(task_id: str, state: Dict[str, Any]) -> None:
    try:
        from common import save_kv_state
        redis_key, state_file = _state_paths(task_id)
        save_kv_state(redis_key, state_file, state)
    except Exception as exc:
        print(f"⚠️ Discord 通知状态保存失败: {exc}")


def _days_since(date_str: str) -> Optional[int]:
    try:
        d = datetime.datetime.strptime(date_str.strip(), "%Y-%m-%d").date()
        return (datetime.datetime.now(BJT).date() - d).days
    except Exception:
        return None


def _format_last_ok(date_str: str, with_days: bool) -> str:
    """上次成功日期展示：今天/昨天直接标注，失败卡上再加距今天数。"""
    text = date_str
    days = _days_since(date_str)
    if days == 0:
        text += "（今天）"
    elif days == 1:
        text += "（昨天）"
    elif with_days and days is not None and days > 0:
        text += f"（距今 {days} 天）"
    return text


def _md_escape(text: str) -> str:
    """转义动态值中的 markdown 控制符：脱敏值里的 *** 会被 Discord 当加粗语法吃掉。"""
    return re.sub(r"([*_~`\\])", r"\\\1", text or "")


def _success_description(account: str, streak: str, reward: str, assets: str, last_ok: str) -> str:
    lines = [
        f"👤 **账号**　{account}",
        f"🔥 **连签**　{streak}",
        f"🎁 **奖励**　{reward}",
        f"💰 **资产**　{assets}",
        f"📅 **上次成功**　{last_ok}",
    ]
    return "\n".join(lines)


def _failure_description(reason: str, account: str, streak: str, assets: str, last_ok: str) -> str:
    lines = [
        f"❗ **原因**　{reason}",
        f"👤 **账号**　{account}",
        f"🔥 **连签**　{streak}",
        f"💰 **资产**　{assets}",
        f"📅 **上次成功**　{last_ok}",
    ]
    return "\n".join(lines)


# === 内置默认模板（templates/ 下同名 JSON 优先） ===

DEFAULT_SUCCESS_TEMPLATE = {
    "username": "cat_checkin",
    "embeds": [{
        "title": "✅ {{TASK_NAME}} · {{STATUS_TITLE}}",
        "color": "{{COLOR}}",
        "description": "{{DESCRIPTION}}",
        "footer": {"text": "cat_checkin · {{SCRIPT}}"},
        "timestamp": "{{TIMESTAMP}}",
    }],
}

DEFAULT_FAILURE_TEMPLATE = {
    "username": "cat_checkin",
    "embeds": [{
        "title": "🚨 {{TASK_NAME}} · {{STATUS_TITLE}}",
        "color": "{{COLOR}}",
        "description": "{{DESCRIPTION}}",
        "footer": {"text": "cat_checkin · {{SCRIPT}}"},
        "timestamp": "{{TIMESTAMP}}",
    }],
}


def notify_task_progress(
    task_id: str,
    name: str,
    script: str,
    ok: bool,
    output: str = "",
    persist: bool = True,
) -> bool:
    """单任务完成即时推送：成功推成功卡、失败推失败卡（简约字段，无耗时/无输出摘要）。

    persist=False 时不读写通知状态（--test 自测用，避免污染真实 task_id 的记录）。
    """
    fields = _extract_fields(output)
    account = _md_escape(_extract_accounts(output))
    streak = _md_escape(_streak_text(fields, output))
    reward = _md_escape(_reward_text(fields))
    assets = _md_escape(_assets_text(fields))

    state = _load_notify_state(task_id) if persist else {}
    prev_ok_date = str(state.get("last_ok_date") or "").strip()
    try:
        prev_fail_streak = int(state.get("fail_streak") or 0)
    except (TypeError, ValueError):
        prev_fail_streak = 0

    today = _bjt_today()
    new_state: Dict[str, Any] = {"updated_at": _timestamp_bjt()}

    if ok:
        # 成功卡展示「上一次」成功日期（本次成功已由卡片本身表达），可确认连签连续性
        last_ok_text = _md_escape(_format_last_ok(prev_ok_date, with_days=False) if prev_ok_date else "首次记录")
        description = _success_description(account, streak, reward, assets, last_ok_text)
        status_title = "签到成功"
        new_state["last_ok_date"] = today
        new_state["fail_streak"] = 0
        tpl_file, tpl = "discord_success.json", DEFAULT_SUCCESS_TEMPLATE
    else:
        fail_n = prev_fail_streak + 1
        status_title = f"签到失败（连续第 {fail_n} 次）" if fail_n > 1 else "签到失败"
        last_ok_text = _md_escape(_format_last_ok(prev_ok_date, with_days=True) if prev_ok_date else "无成功记录")
        description = _failure_description(_md_escape(_one_line_error(output)), account, streak, assets, last_ok_text)
        new_state["last_ok_date"] = prev_ok_date
        new_state["fail_streak"] = fail_n
        tpl_file, tpl = "discord_failure.json", DEFAULT_FAILURE_TEMPLATE

    replacements = {
        "{{TASK_NAME}}": str(name or task_id),
        "{{SCRIPT}}": str(script or ""),
        "{{STATUS_TITLE}}": status_title,
        "{{COLOR}}": str(COLOR_OK if ok else COLOR_FAIL),
        "{{DESCRIPTION}}": description,
        "{{TIMESTAMP}}": _timestamp_bjt(),
    }

    tpl = _load_template(tpl_file, tpl)
    sent = _post_webhook(_render(tpl, replacements))
    if persist:
        # 状态反映任务执行事实（与推送是否送达无关），失败也要累计连续失败次数
        _save_notify_state(task_id, new_state)
    return sent


def main() -> None:
    """CLI 自测：python3 discord_notify.py --test 连发一条成功卡 + 一条失败卡。"""
    ok_output = (
        "👤 用户信息: t***t@gmail.com\n"
        "🎉 账号 打卡成功！今日获得: 2,000,000 (2.00M) Tokens，连续 3 天\n"
        "📅 连签进度: 连续 3 天 (再连签 4 天可额外领 10,000,000 (10.00M) Tokens)\n"
        "🎁 打卡赠送额度: 4,000,000 (4.00M) Tokens (有效期至 2026-09-27)\n"
    )
    fail_output = (
        "账号 x***3@gmail.com\n"
        "❌ 账号 签到失败: HTTP 401, msg: session expired (Session Cookie 已失效)\n"
        "🚨 执行完毕，共有 1 个账号签到失败\n"
    )
    sent1 = notify_task_progress(
        task_id="selftest", name="自测站点 签到", script="selftest.py",
        ok=True, output=ok_output, persist=False,
    )
    sent2 = notify_task_progress(
        task_id="selftest", name="自测站点 签到", script="selftest.py",
        ok=False, output=fail_output, persist=False,
    )
    print("✅ 测试消息已发送（成功卡 + 失败卡）" if (sent1 and sent2) else "❌ 测试消息发送失败")
    sys.exit(0 if (sent1 and sent2) else 1)


if __name__ == "__main__":
    main()
