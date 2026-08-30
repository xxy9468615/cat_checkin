#!/usr/bin/env python3
# new Env("Discord Webhook 通知")
"""Discord Webhook 通知模块：频道1 失败即时提醒（2026-08-29 双通道拆分）。

daily_orchestrator.py 每个任务失败/超时/异常的瞬间调用 notify_task_result 推
失败卡（templates/discord_failure.json，红色🔴）；任务成功但命中黄色预警
（无感续期失败 / 凭据即将过期，alert_levels.classify 分级）时推黄色提示卡
（templates/discord_warn.json，同任务同日仅一次）；纯成功只更新状态、不推送——
避免正常任务信息干扰。每日任务执行情况日报走邮件通道（unified_report.py +
daily_report.py HTML 卡片 + 今日概览小结），浏览与归档体验优于 Discord。

失败卡字段（B 标准版）：
  逐账号失败明细 + 按错误类型的针对性处置建议 + 重跑指引（是否建议重跑/
  当日尝试次数）+ 账号(脱敏) + 当前资产 + 上次签到成功日期。

通知状态按 task_id 记 KV（common.load_kv_state / save_kv_state 双通道）：
  Redis cat_checkin:state:notify:<task_id> + 本地 .notify_state_<task_id>.json
  字段：last_ok_date / fail_streak / ok_streak / attempts / attempt_date /
       warn_date / warn_texts（黄色预警去重与留痕）。

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
from typing import Any, Dict, List, Optional, Tuple

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
COLOR_PENDING = 9807270 # 灰
COLOR_WARN = 0xF59E0B   # 琥珀（黄色预警：成功但带提示）

# Discord embed 限制：description ≤ 4096、总 payload ≤ 6000
FAIL_TEXT_MAX = 160

BJT = datetime.timezone(datetime.timedelta(hours=8))
_WEEKDAY_CN = ("周一", "周二", "周三", "周四", "周五", "周六", "周日")

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


def _assets_text(fields: Dict[str, str]) -> str:
    """当前资产：余额/积分/Token 等各站计量单位聚合。"""
    assets = (fields.get("assets") or "").strip()
    return assets.replace(" | ", " · ") if assets else "—"


# 强错误特征（HTTP 状态码/异常/失效等）与汇总行特征（失败原因要取真因，不要「执行完毕」汇总）
_FAILURE_LINE_RE = re.compile(r"(❌|失败|失效|错误|Error|Exception|超时|无法|HTTP\s?\d{3})", re.I)
_SUMMARY_LINE_RE = re.compile(r"(执行完毕|总结|成功\s*\d+\s*/\s*\d+|========|^\s*--- )")
# 失败行前置噪音（emoji/序号/「账号」标签/「签到失败：」动词短语）剥离，只留可读根因
_FAIL_LINE_NOISE_RE = re.compile(r"^[❌⚠️✅🚨]*\s*(?:\[\d+\s*/\s*\d+\]\s*)?(?:账号\s*)?(?:(?:签到|打卡)?失败[:：]\s*)?")
_FAIL_INDEX_RE = re.compile(r"\[(\d+)\s*/\s*\d+\]")

# 错误类型 → (针对性处置建议, 是否可重跑, 重跑说明)；按序首个命中生效
_ERROR_HINTS = [
    (r"daily_active|冷却",
     "日活奖励未到账：24h 滚动冷却中，Cookie 登录态正常，下次运行自动到账，无需处理",
     False, "无需重跑（24h 冷却，下次运行自动到账）"),
    (r"已经打过卡|已打卡|already[_ ]?claimed|重复打卡|请勿重复|今日已打卡",
     "站点提示今日已打卡：本次为重复执行，无需处理，下轮运行自动恢复绿色",
     False, "无需重跑（今日已打卡）"),
    (r"HTTP\s?40[13]|失效|过期|未登录|session|cookie",
     "登录凭证疑似失效：请在浏览器重新登录该站点，并更新 GitHub Secrets 中对应的 Cookie/Token",
     True, "更新凭证后重跑"),
    (r"验证码|captcha|challenge|pow",
     "验证码求解失败：站点风控可能升级，建议人工登录该站点一次后再观察",
     True, "人工登录一次后重跑"),
    (r"超时|timeout", "执行超时：站点响应缓慢或网络受限，下一轮运行将自动重试",
     True, "可重跑（多为瞬时网络问题）"),
    (r"代理|proxy|socks", "代理通道不可用：请检查 AGENTROUTER_SS_CONFIG 或备用代理配置",
     True, "修复代理后重跑"),
]


def _failure_items(output: str, max_items: int = 3) -> List[Tuple[str, str]]:
    """逐账号失败明细：扫描输出中的真实失败行（❌ 行优先，⚠️ 警告行兜底）。

    返回 [(序号 tag 如 '#2' 或 '', 清理后的单行原因)]；汇总行/分隔线不参与，
    同文去重，最多 max_items 条。
    """
    primary: List[str] = []
    backup: List[str] = []
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line or _SUMMARY_LINE_RE.search(line):
            continue
        if "⚠️" in line:
            backup.append(line)
        elif _FAILURE_LINE_RE.search(line):
            primary.append(line)
    items: List[Tuple[str, str]] = []
    seen: set[str] = set()
    for line in primary + backup:
        m = _FAIL_INDEX_RE.search(line)
        tag = f"#{m.group(1)}" if m else ""
        text = _FAIL_LINE_NOISE_RE.sub("", line).strip()
        if len(text) > FAIL_TEXT_MAX:
            text = text[:FAIL_TEXT_MAX] + "…"
        if text in seen:
            continue
        seen.add(text)
        items.append((tag, text))
        if len(items) >= max_items:
            break
    return items


def _error_hint(items: List[Tuple[str, str]]) -> str:
    """按失败文本匹配处置建议；混合失败（如冷却 + 凭证失效并存）给最多两条不同建议。"""
    joined = " ".join(text for _, text in items)
    hints: List[str] = []
    for pattern, hint, _, _ in _ERROR_HINTS:
        if re.search(pattern, joined, re.I) and hint not in hints:
            hints.append(hint)
            if len(hints) >= 2:
                break
    return "；".join(hints)


def _retry_advice(items: List[Tuple[str, str]]) -> Tuple[bool, str]:
    """是否建议重跑 + 说明（首个命中错误类型；无命中默认可重跑排查）。"""
    joined = " ".join(text for _, text in items)
    for pattern, _, retryable, reason in _ERROR_HINTS:
        if re.search(pattern, joined, re.I):
            return retryable, reason
    return True, "可手动重跑排查"


def _failed_accounts(output: str, info: Optional[Dict[str, Any]] = None) -> str:
    """从失败明细行提取失败账号（带 [i/n] 序号），与成功账号区分开。

    优先使用 report_fields 按任务定制的 fail_lines（账号名/原因更准），
    无结构化结果时回退 _failure_items 启发式。
    """
    tags: List[str] = []
    if info and info.get("fail_lines"):
        for ln in info["fail_lines"][:4]:
            m = _MASKED_TOKEN_RE.search(ln)
            label = f"{m.group(0).strip('._-')}" if m else _FAIL_LINE_NOISE_RE.sub("", ln).strip()[:18]
            label = label.strip()
            if label and label not in tags:
                tags.append(label)
        if tags:
            return "、".join(tags[:4])
    for tag, text in _failure_items(output, max_items=6):
        m = _MASKED_TOKEN_RE.search(text)
        label = f"{tag} {m.group(0).strip('._-')}" if m else tag
        label = label.strip()
        if label and label not in tags:
            tags.append(label)
    if not tags:
        return ""
    return "、".join(tags[:4])


# === 按 task_id 的通知状态（上次成功日期 / 连续失败 / 连续成功 / 当日尝试次数） ===

def _state_paths(task_id: str) -> Tuple[str, str]:
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


def _date_offset(day: str, days: int) -> str:
    try:
        d = datetime.datetime.strptime(day.strip(), "%Y-%m-%d").date()
        return (d + datetime.timedelta(days=days)).strftime("%Y-%m-%d")
    except Exception:
        return ""


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


# === 频道1：失败提醒卡（B 标准版） ===

def _failure_description(
    items: List[Tuple[str, str]],
    hint: str,
    retryable: bool,
    retry_reason: str,
    attempts: int,
    failed_acct: str,
    account: str,
    assets: str,
    last_ok: str,
) -> str:
    lines: List[str] = []
    if len(items) == 1:
        tag, text = items[0]
        lines.append(f"❗ **原因**　{(tag + ' · ') if tag else ''}{text}")
    elif items:
        lines.append("❗ **失败明细**")
        lines += [f"　{tag} {text}".strip() for tag, text in items]
    else:
        lines.append("❗ **原因**　未知错误（进程非零退出但无失败输出，详见 Actions 日志）")
    if hint:
        lines.append(f"💡 **建议**　{hint}")
    retry_word = "无需重跑" if not retryable else "建议重跑"
    lines.append(f"🔁 **重跑**　{retry_word}（{retry_reason}）· 当日已尝试 {attempts} 次")
    lines.append(f"👤 **账号**　{failed_acct or account}")
    lines.append(f"💰 **资产**　{assets}")
    lines.append(f"📅 **上次成功**　{last_ok}")
    return "\n".join(lines)


DEFAULT_FAILURE_TEMPLATE = {
    "username": "cat_checkin",
    "embeds": [{
        "title": "🚨 {{TASK_NAME}} · {{STATUS_TITLE}}",
        "color": "{{COLOR}}",
        "description": "{{DESCRIPTION}}",
        "footer": {"text": "cat_checkin · {{TASK_ID}} · {{SCRIPT}}"},
        "timestamp": "{{TIMESTAMP}}",
    }],
}


# === 频道1：黄色提示卡（任务成功但带提示：续期失败 / 凭据即将过期） ===

DEFAULT_WARN_TEMPLATE = {
    "username": "cat_checkin",
    "embeds": [{
        "title": "🟡 {{TASK_NAME}} · {{STATUS_TITLE}}",
        "color": "{{COLOR}}",
        "description": "{{DESCRIPTION}}",
        "footer": {"text": "cat_checkin · {{TASK_ID}} · {{SCRIPT}}"},
        "timestamp": "{{TIMESTAMP}}",
    }],
}


def notify_task_result(
    task_id: str,
    name: str,
    script: str,
    ok: bool,
    output: str = "",
    persist: bool = True,
) -> bool:
    """记录单任务执行结果并按需推送：失败实时推红色失败卡；成功带黄色提示时推提示卡
    （同任务同日仅推一次）；纯成功只更新状态不推送。

    persist=False 时不读写通知状态（--test 自测用，避免污染真实 task_id 的记录）。
    返回值：失败卡/提示卡是否发送成功（纯成功不推送恒返回 True，方便调用方记日志）。
    """
    state = _load_notify_state(task_id) if persist else {}
    prev_ok_date = str(state.get("last_ok_date") or "").strip()
    try:
        prev_fail_streak = int(state.get("fail_streak") or 0)
    except (TypeError, ValueError):
        prev_fail_streak = 0
    try:
        prev_ok_streak = int(state.get("ok_streak") or 0)
    except (TypeError, ValueError):
        prev_ok_streak = 0

    today = _bjt_today()
    # 当日尝试次数：跨日自动重置
    if str(state.get("attempt_date") or "") == today:
        try:
            attempts = int(state.get("attempts") or 0) + 1
        except (TypeError, ValueError):
            attempts = 1
    else:
        attempts = 1

    info: Optional[Dict[str, Any]] = None
    try:
        import report_fields
        # 按任务定制解析（与统一日报同源）：资产覆盖 2libra 金币/agentrouter 额度/
        # ai_router USD/CloudStudio 机时等全局启发式抓不到的字段
        info = report_fields.extract_for(script, output or "")
        assets = report_fields.assets_text(info) or "—"
    except Exception:
        assets = _assets_text(_extract_fields(output))

    new_state: Dict[str, Any] = {
        "updated_at": _timestamp_bjt(),
        "attempt_date": today,
        "attempts": attempts,
    }

    if not ok:
        fail_n = prev_fail_streak + 1
        new_state["last_ok_date"] = prev_ok_date
        new_state["fail_streak"] = fail_n
        new_state["ok_streak"] = 0

        items_raw = _failure_items(output)
        retryable, retry_reason = _retry_advice(items_raw)
        status_title = f"签到失败（连续第 {fail_n} 天）" if fail_n > 1 else "签到失败"
        last_ok_text = _md_escape(_format_last_ok(prev_ok_date, with_days=True) if prev_ok_date else "无成功记录")
        description = _failure_description(
            [(t, _md_escape(x)) for t, x in items_raw],
            _md_escape(_error_hint(items_raw)),
            retryable,
            _md_escape(retry_reason),
            attempts,
            _md_escape(_failed_accounts(output, info)),
            _md_escape(_extract_accounts(output)),
            _md_escape(assets),
            last_ok_text,
        )
        replacements = {
            "{{TASK_NAME}}": str(name or task_id),
            "{{TASK_ID}}": str(task_id),
            "{{SCRIPT}}": str(script or ""),
            "{{STATUS_TITLE}}": status_title,
            "{{COLOR}}": str(COLOR_FAIL),
            "{{DESCRIPTION}}": description,
            "{{TIMESTAMP}}": _timestamp_bjt(),
        }
        # 防轰炸：心跳轮询下同日反复失败会重复推卡——当日第 3 次尝试起静默
        # （状态照常累计，次日 attempts 跨日重置后恢复推送）
        if attempts > 2:
            print(f"ℹ️ 任务 {task_id} 当日已推送过失败卡（attempts={attempts}），本次静默")
            sent = True
        else:
            tpl = _load_template("discord_failure.json", DEFAULT_FAILURE_TEMPLATE)
            sent = _post_webhook(_render(tpl, replacements))
    else:
        # 成功：只更新状态（连签连续性由 last_ok_date 是否为昨天决定），不推绿卡
        new_state["last_ok_date"] = today
        new_state["fail_streak"] = 0
        new_state["ok_streak"] = prev_ok_streak + 1 if prev_ok_date == _date_offset(today, -1) else 1
        sent = True

        # 🟡 黄色预警：任务成功但带提示（无感续期失败 / 凭据即将过期，alert_levels 分级）。
        # 防轰炸：心跳轮询一天跑多次，同任务同日只推第一张提示卡，后续静默（状态照记）
        cls: Dict[str, Any] = {"level": "ok", "warns": []}
        try:
            import alert_levels
            cls = alert_levels.classify(script, True, output or "")
        except Exception as exc:
            print(f"⚠️ 分级判定失败（按绿色处理）: {exc}")
        if cls.get("warns"):
            new_state["warn_date"] = today
            new_state["warn_texts"] = list(cls["warns"])[:5]
            if str(state.get("warn_date") or "") == today:
                print(f"ℹ️ 任务 {task_id} 今日已推送过提示卡（warn_date={state.get('warn_date')}），本次静默")
            else:
                description = "\n".join(
                    f"⚠️ {_md_escape(w)}" for w in cls["warns"][:4]
                )
                description += f"\n💰 **资产**　{assets}"
                replacements = {
                    "{{TASK_NAME}}": str(name or task_id),
                    "{{TASK_ID}}": str(task_id),
                    "{{SCRIPT}}": str(script or ""),
                    "{{STATUS_TITLE}}": "签到成功，但有提示",
                    "{{COLOR}}": str(COLOR_WARN),
                    "{{DESCRIPTION}}": description,
                    "{{TIMESTAMP}}": _timestamp_bjt(),
                }
                tpl = _load_template("discord_warn.json", DEFAULT_WARN_TEMPLATE)
                sent = _post_webhook(_render(tpl, replacements))

    if persist:
        # 状态反映任务执行事实（与推送是否送达无关），失败也要累计
        _save_notify_state(task_id, new_state)
    return sent


def notify_unconfigured(
    task_id: str,
    name: str,
    script: str,
    output: str = "",
    persist: bool = True,
) -> bool:
    """凭据未配置（⚪ 非故障）：不推红色失败卡、不计 fail_streak、不动 last_ok_date。

    新任务代码先进 main、Secret 还没配时的场景——历史上每次都以红色失败卡 +
    无意义自动重跑收场。现只推一张黄色「未配置」提示卡（同任务同日仅一次），
    附证据行与配置指引，提醒尽快配置凭据。
    """
    state = _load_notify_state(task_id) if persist else {}
    today = _bjt_today()
    # 保留既有状态字段（last_ok_date / fail_streak / ok_streak / attempts），
    # 只追加未配置标记——未配置既不是故障也不是成功
    new_state: Dict[str, Any] = dict(state)
    new_state.update({
        "updated_at": _timestamp_bjt(),
        "attempt_date": today,
        "last_unconf_date": today,
    })

    try:
        import alert_levels
        evidence = alert_levels.detect_unconfigured(output) or "（未捕获到具体证据行）"
    except Exception:
        evidence = "（未捕获到具体证据行）"

    sent = True
    if str(state.get("last_unconf_date") or "") == today:
        print(f"ℹ️ 任务 {task_id} 今日已推送过「未配置」提示卡（last_unconf_date={state.get('last_unconf_date')}），本次静默")
    else:
        description = "\n".join([
            "ℹ️ **状态**　凭据未配置，本次按跳过处理（非故障，不计失败、不触发重跑）",
            f"❗ **证据**　{_md_escape(evidence)}",
            "💡 **处置**　在仓库 Secrets 配置对应凭据后验证：`gh workflow run checkin.yml -f tasks=" + str(task_id) + "`",
        ])
        replacements = {
            "{{TASK_NAME}}": str(name or task_id),
            "{{TASK_ID}}": str(task_id),
            "{{SCRIPT}}": str(script or ""),
            "{{STATUS_TITLE}}": "凭据未配置，已跳过",
            "{{COLOR}}": str(COLOR_WARN),
            "{{DESCRIPTION}}": description,
            "{{TIMESTAMP}}": _timestamp_bjt(),
        }
        tpl = _load_template("discord_warn.json", DEFAULT_WARN_TEMPLATE)
        sent = _post_webhook(_render(tpl, replacements))

    if persist:
        _save_notify_state(task_id, new_state)
    return sent


def main() -> None:
    """CLI 自测：python3 discord_notify.py --test 发一条失败卡（多账号混合样例）。"""
    fail_output = (
        "【ModelScope 签到】\n"
        "  [1/3] a***1 UID:1***6 [Cookie] 签到成功，今日已领取 200 魔粒\n"
        "  [2/3] b***2 UID:1***7 [Cookie] 交易记录无今日 daily_active（Cookie 可能已失效需手动刷新）\n"
        "  [3/3] c***3 UID:1***8 签到失败：HTTP 401, msg: session expired\n"
        "  国内站总结：成功 1/3\n"
        "🚨 执行完毕，共有 2 个账号签到失败：\n"
    )
    sent = notify_task_result(
        task_id="selftest", name="自测站点 签到", script="selftest.py",
        ok=False, output=fail_output, persist=False,
    )
    print("✅ 测试失败卡已发送" if sent else "❌ 测试消息发送失败")
    sys.exit(0 if sent else 1)


if __name__ == "__main__":
    main()
