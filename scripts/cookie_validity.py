#!/usr/bin/env python3
"""Cookie/凭据有效期自动识别 —— 全任务共享引擎（唯一事实来源）。

设计动机（2026-10-11）：此前各任务的到期识别散落在各自脚本里反复重写
（52pojie / glados / railgun / juejin / nodeseek / smzdm / 2libra 各一套），
口径互不一致、部分任务产出过「假 0 天告警」。本模块收敛为单一实现，
任务侧只做三件事：学习（learn_*）→ 跟踪（update_state）→ 渲染（build_tag）。

证据优先级（真实到期证据优先，无证据不产出假倒计时）：
1. 本轮响应 Set-Cookie / CookieJar 的真实 Expires/Max-Age（learn_from_response
   / learn_from_jar；可用 credential_match 只认任务声明的凭据 cookie）；
2. state 历史学习值 cookie_expire_ts（跨运行积累，update_state 维护）；
3. 粘贴 Cookie 自带的到期证据：浏览器 JSON 导出 / Netscape 文件 / JWT exp /
   koa:sess _expire / sid_guard 签发+TTL（expire_from_cookie_str 结构化识别）；
4. 兜底估算：任务声明硬寿命窗口（fallback_lifetime_days）时按首次使用时间
   （first_seen_ts）倒计时；未声明则如实报「有效期未知（已使用 N 天）」，
   杜绝 52pojie 教训里「估算耗尽但登录态仍存活」的假 0 天告警。

输出标签（与 alert_levels `_COOKIE_DAYS_RE`、report_fields 解析保持兼容）：
  🔑 Cookie 剩余 N 天（YYYY-MM-DD 到期）              # 证据充分且剩余 ≥ 7 天
  ⚠️ Cookie 剩余 N 天（YYYY-MM-DD 到期，请尽快更新）   # 剩余 < 7 天
  🔑 Cookie 剩余 N 天                                  # 兜底窗口倒计时（无确切日期）
  🔑 Cookie 有效期未知（已成功运行 N 天，未观察到期证据） # 无证据 + mark_ok 天数 < 老化基线
  ⚠️ Cookie 有效期未知（已成功运行 N 天，超出 M 天估算窗口，建议预防性更新）
  ⚠️ Cookie 有效期未知（已成功运行 N 天，达到 M 天老化基线，建议预防性更新）
                                                       # 按成功执行天数反推已老化（黄卡锚点）

用法示例（任务脚本内）：
    import cookie_validity as cv
    learned = cv.learn_from_response(resp)          # 每次关键响应后
    learned.update(cv.learn_from_jar(h.jar))
    state = cv.update_state(state, cookie_str, learned)
    cv.mark_ok(state)                               # 签到成功：记录成功运行日（反推寿命依据）
    save_kv_state(redis_key, state_file, state)     # 与任务原有 state 一并保存
    tag = cv.build_tag(state, learned, credential_match=lambda n: n == "BDUSS")
    print(f"👤 用户行{tag}")
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from http.cookiejar import http2time
from typing import Any, Callable, Dict, List, Optional

try:  # 与任务脚本共用北京时区渲染；common 不可用时静默降级
    from common import BJT
except Exception:  # pragma: no cover
    BJT = timezone(timedelta(hours=8))

# 剩余天数低于该阈值时用 ⚠️（与 alert_levels「剩 ≤1 天才黄卡」互补：提前一周提醒）
WARN_REMAINING_DAYS = 7
DAY_SEC = 86400

# 无解析有效期凭据的老化预警基线（天）：成功运行天数达到该值且仍无任何到期
# 证据 → 升级 ⚠️ 建议预防性更新（2026-10-31 用户指令：按成功执行天数反推有效期
# 实现预警；COOKIE_UNKNOWN_AGING_WARN_DAYS 可覆盖）
UNKNOWN_AGING_WARN_DAYS = int((os.getenv("COOKIE_UNKNOWN_AGING_WARN_DAYS") or "45").strip() or 45)
# ok_dates 明细保留窗口（天）：累计计数另存 ok_days_total，不受窗口裁剪影响
OK_DATES_KEEP = 120

# 凭据匹配回调类型：lambda name: bool；None 表示不过滤（全量 cookie 皆可为证据）
CredentialMatch = Optional[Callable[[str], bool]]

# 常见「签发型」cookie 名 → 内嵌证据解析器（按结构识别，站点无关）
_KOA_SESS_RE = re.compile(r"^koa:sess(?:$|_=)", re.IGNORECASE)
_SID_GUARD_RE = re.compile(r"sid_guard", re.IGNORECASE)


# ---------------------------------------------------------------------------
# 底层解析：单字段 / 单条 Set-Cookie
# ---------------------------------------------------------------------------
def _b64u_decode(seg: str) -> bytes:
    padded = seg + "=" * (-len(seg) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return base64.b64decode(padded)  # 个别站点（NodeSeek pjwt）用标准 base64 字符集


def parse_jwt_payload(value: str) -> Optional[dict]:
    """解析 JWT payload（dict 或 None）。

    标准 JWT payload 在第 2 段；个别站点（如 NodeSeek pjwt）把 payload 放在第 1 段，
    两段都尝试，以先解析成功者为准。非 JWT / 解析失败一律 None。
    """
    parts = (value or "").strip().split(".")
    if len(parts) < 2:
        return None
    for seg in (parts[1], parts[0]):
        try:
            data = json.loads(_b64u_decode(seg))
            if isinstance(data, dict):
                return data
        except Exception:
            continue
    return None


def _norm_epoch(v: Any) -> Optional[int]:
    """epoch 秒/毫秒归一化为秒；非法或非正数返回 None。"""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    v = int(v)
    if v <= 0:
        return None
    return v // 1000 if v > 10**12 else v


def parse_jwt_exp(value: str) -> Optional[int]:
    """JWT payload.exp → epoch 秒（无 exp 字段返回 None）。"""
    exp = (parse_jwt_payload(value) or {}).get("exp")
    return _norm_epoch(exp)


def parse_jwt_issued_ts(value: str) -> Optional[int]:
    """JWT payload 的签发时间（ts / iat）→ epoch 秒（供窗口型会话推算）。"""
    payload = parse_jwt_payload(value) or {}
    return _norm_epoch(payload.get("ts")) or _norm_epoch(payload.get("iat"))


def parse_koa_sess_expire(value: str) -> Optional[int]:
    """Koa session cookie（koa:sess）base64 JSON 的 _expire 毫秒 → epoch 秒。"""
    try:
        raw = urllib.parse.unquote(value.strip())
        data = json.loads(base64.b64decode(raw + "==").decode("utf-8"))
        return _norm_epoch(data.get("_expire"))
    except Exception:
        return None


def parse_sid_guard_expire(value: str) -> Optional[int]:
    """sid_guard=value|签发ts|TTL秒 → 到期 epoch（抖音系会话字段）。"""
    m = re.search(r"(\d{9,13})\|(\d{1,9})", value or "")
    if not m:
        return None
    issue = _norm_epoch(int(m.group(1)))
    ttl = int(m.group(2))
    if issue and 0 < ttl <= 10**8:
        return issue + ttl
    return None


def parse_cookie_date(text: str) -> Optional[int]:
    """Set-Cookie 日期串（RFC 7231 / Netscape 连字符格式）→ epoch 秒。"""
    if not text:
        return None
    try:
        ts = http2time(text.strip())
        return int(ts) if ts else None
    except Exception:
        return None


def parse_set_cookie_expiry(set_cookie: str) -> Optional[int]:
    """单条 Set-Cookie 标头的 Expires / Max-Age 属性 → epoch 秒（会话 cookie 无则 None）。"""
    m = re.search(r";\s*expires\s*=\s*([^;]+)", set_cookie or "", re.IGNORECASE)
    if m:
        return parse_cookie_date(m.group(1))
    m = re.search(r";\s*max-age\s*=\s*(-?\d+)", set_cookie or "", re.IGNORECASE)
    if m:
        max_age = int(m.group(1))
        return int(time.time()) + max_age if max_age > 0 else None
    return None


# ---------------------------------------------------------------------------
# 底层解析：整段粘贴 Cookie 的显式到期字段
# ---------------------------------------------------------------------------
def _export_candidates(cookie_str: str, domain_hint: str) -> list:
    """浏览器 JSON 导出 / Netscape 文件格式的 (name, expire_ts) 候选列表。"""
    s = (cookie_str or "").strip()
    cands = []
    hint = (domain_hint or "").lower()
    if s.startswith("[") or s.startswith("{"):
        try:
            data = json.loads(s)
        except Exception:
            return cands
        for it in (data if isinstance(data, list) else [data]):
            if not isinstance(it, dict):
                continue
            dom = str(it.get("domain") or "").lower()
            if hint and dom and hint not in dom:
                continue
            ts = _norm_epoch(
                it.get("expirationDate") or it.get("expires") or it.get("expiry")
            )
            if ts:
                cands.append((str(it.get("name") or ""), ts))
        return cands
    for line in s.splitlines():
        cols = line.split("\t")
        if len(cols) < 7:
            continue
        try:
            ts = _norm_epoch(float(cols[4]))
        except ValueError:
            continue
        if ts and (not hint or hint in cols[0].lower()):
            cands.append((cols[5].strip(), ts))
    return cands


def _value_expire(name: str, value: str, window_days: Optional[int]) -> Optional[int]:
    """单个 cookie 字段值的内嵌到期证据（结构化识别，与站点名解耦）。"""
    if _KOA_SESS_RE.match(name or ""):
        ts = parse_koa_sess_expire(value)
        if ts:
            return ts
    if _SID_GUARD_RE.search(name or ""):
        ts = parse_sid_guard_expire(value)
        if ts:
            return ts
    if value and value.count(".") == 2 and "=" not in value:
        # JWT 形状：优先 exp；无 exp 但有签发时间且有声明窗口 → 签发+窗口
        ts = parse_jwt_exp(value)
        if ts:
            return ts
        if window_days:
            issued = parse_jwt_issued_ts(value)
            if issued:
                return issued + int(window_days) * DAY_SEC
    return None


def expire_from_cookie_str(
    cookie_str: str,
    window_days: Optional[int] = None,
    credential_match: CredentialMatch = None,
    domain_hint: str = "",
) -> Optional[int]:
    """从粘贴的 Cookie 串提取内嵌到期证据 → epoch 秒（无证据返回 None）。

    覆盖四类格式：普通 k=v 串（JWT/koa:sess/sid_guard 值）、浏览器 JSON 导出、
    Netscape 文件。多条证据取最大值（凭据通常活得最久）。
    """
    s = (cookie_str or "").strip()
    if not s:
        return None
    expiries = []
    if not (s.startswith("[") or s.startswith("{") or "\t" in s):
        for part in s.split(";"):
            if "=" not in part:
                continue
            k, v = part.strip().split("=", 1)
            name = k.strip()
            if credential_match and not credential_match(name):
                continue
            ts = _value_expire(name, v.strip(), window_days)
            if ts:
                expiries.append(ts)
    cands = _export_candidates(s, domain_hint)
    if credential_match:
        cands = [(n, ts) for n, ts in cands if credential_match(n)]
    expiries.extend(ts for _, ts in cands)
    return max(expiries) if expiries else None


# ---------------------------------------------------------------------------
# 学习：从本轮请求/响应提取真实到期证据
# ---------------------------------------------------------------------------
def learn_from_set_cookies(
    set_cookies: Any, credential_match: CredentialMatch = None
) -> Dict[str, int]:
    """从已收集的 Set-Cookie 字符串（str / list / 多标头串接）提取到期映射。"""
    out: Dict[str, int] = {}
    items: list = []
    if isinstance(set_cookies, (list, tuple)):
        items = list(set_cookies)
    elif set_cookies:
        items = [set_cookies]
    for sc in items:
        for chunk in str(sc).replace("\n", "\r").split("\r"):
            chunk = chunk.strip()
            if not chunk or "=" not in chunk:
                continue
            name = chunk.split("=", 1)[0].strip()
            if credential_match and not credential_match(name):
                continue
            ts = parse_set_cookie_expiry(chunk)
            if ts:
                out[name] = max(out.get(name, 0), ts)
    return out


def learn_from_response(resp: Any, credential_match: CredentialMatch = None) -> Dict[str, int]:
    """从响应 Set-Cookie 标头提取 {cookie名: 到期epoch}（urllib / curl_cffi 兼容）。

    urllib 的 headers 支持 get_all；curl_cffi 的 headers 可能是 dict（值 str 或 list）。
    会话 cookie（无 Expires/Max-Age）不算证据。任何异常静默返回 {}。
    """
    out: Dict[str, int] = {}
    if resp is None:
        return out
    try:
        headers = getattr(resp, "headers", None)
        if headers is None:
            return out
        raw_list: list = []
        get_all = getattr(headers, "get_all", None)
        if callable(get_all):
            raw_list = [x for x in (get_all("Set-Cookie") or []) if x]
        else:
            val = headers.get("Set-Cookie") or headers.get("set-cookie")
            if isinstance(val, (list, tuple)):
                raw_list = [x for x in val if x]
            elif val:
                raw_list = [val]
        out = learn_from_set_cookies(raw_list, credential_match)
    except Exception:
        pass
    return out


def learn_from_jar(jar: Any, credential_match: CredentialMatch = None) -> Dict[str, int]:
    """从 CookieJar（h.jar / curl_cffi _raw_cookies.jar）提取带显式 expires 的到期映射。"""
    out: Dict[str, int] = {}
    if jar is None:
        return out
    try:
        for c in jar:
            name = getattr(c, "name", "") or ""
            if not name or (credential_match and not credential_match(name)):
                continue
            ts = _norm_epoch(getattr(c, "expires", None))
            if ts:
                out[name] = ts
    except Exception:
        pass
    return out


def merge_learned(*maps: Dict[str, int]) -> Dict[str, int]:
    """合并多个学习结果（同名取更大者）。"""
    out: Dict[str, int] = {}
    for m in maps:
        for k, v in (m or {}).items():
            if isinstance(v, (int, float)) and v > 0:
                out[k] = max(out.get(k, 0), int(v))
    return out


# ---------------------------------------------------------------------------
# 跟踪：state 维护（指纹感知 + 证据持久化）
# ---------------------------------------------------------------------------
def update_state(
    state: Dict[str, Any],
    cookie_str: str,
    learned: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """滚动跟踪 state（原地更新并返回）。

    - cookie 指纹变更（用户更新 Secrets）→ 重置 first_seen_ts 并清除旧到期证据，
      避免旧 Cookie 的证据污染新 Cookie 的估算；成功运行日跟踪（ok_*）同步重置——
      ok_days 度量的是「当前这枚 Cookie」的服务天数，跨凭据累计会让老化信号失真
      （滚动保活凭据每次 Set-Cookie 都换指纹，天然不适用老化预警，与本表 update_state
      重置语义一致）；
    - learned 有真实证据 → 写 cookie_expire_ts（滑动续期只增不减）。
    """
    now = int(time.time())
    fp = hashlib.md5((cookie_str or "").encode("utf-8")).hexdigest()
    if state.get("cookie_md5") != fp:
        state["cookie_md5"] = fp
        state["first_seen_ts"] = now
        state.pop("cookie_expire_ts", None)
        state.pop("ok_days_total", None)
        state.pop("ok_first_date", None)
        state.pop("ok_last_date", None)
        state.pop("ok_dates", None)
    if not state.get("first_seen_ts"):
        state["first_seen_ts"] = now
    learned_ts = max((learned or {}).values()) if learned else 0
    if learned_ts > 0:
        prev = state.get("cookie_expire_ts") or 0
        state["cookie_expire_ts"] = int(max(learned_ts, prev))
    elif state.get("cookie_expire_ts") and state["cookie_expire_ts"] <= now:
        # 旧证据已到期但登录态仍存活（窗口假设被推翻）→ 清除，走「未知」分支
        state.pop("cookie_expire_ts", None)
    state["validity_checked_at"] = now
    return state


def resolve_expire_ts(
    state: Dict[str, Any],
    cookie_str: str = "",
    learned: Optional[Dict[str, int]] = None,
    credential_match: CredentialMatch = None,
    window_days: Optional[int] = None,
    domain_hint: str = "",
    now: Optional[float] = None,
) -> Optional[float]:
    """证据优先级合流：本轮学习值 > state 历史值 > 粘贴内嵌证据。已过期证据视为无效。"""
    now = now if now is not None else time.time()
    learned_ts = max((learned or {}).values()) if learned else 0
    for cand in (
        learned_ts,
        state.get("cookie_expire_ts"),
        expire_from_cookie_str(cookie_str, window_days, credential_match, domain_hint),
    ):
        try:
            ts = float(cand)
        except (TypeError, ValueError):
            continue
        if ts > now:
            return ts
    return None


# ---------------------------------------------------------------------------
# 渲染：统一标签（与 alert_levels / report_fields 的解析口径兼容）
# ---------------------------------------------------------------------------
def remaining_days(expire_ts: float, now: Optional[float] = None) -> int:
    """到期时间 → 剩余整天数（向下取整，≥0）。"""
    now = now if now is not None else time.time()
    return max(0, int((float(expire_ts) - now) / DAY_SEC))


def mark_ok(state: Dict[str, Any], now: Optional[float] = None) -> Dict[str, Any]:
    """记录一次成功运行日（无解析有效期凭据按成功执行天数反推寿命的依据）。

    写入状态键：
    - ok_first_date：首次成功运行日（YYYY-MM-DD，BJT）
    - ok_last_date：最近成功运行日
    - ok_days_total：累计成功运行天数（同日多次运行只计 1）
    - ok_dates：近期成功日期明细（保留 OK_DATES_KEEP 条，供排障核对）

    任务在签到成功后、save_kv_state 前调用；持久化走既有 KV 数据库双通道
    （本地 JSON + Upstash Redis）。与 update_state 一样只改传入 dict。"""
    now = now if now is not None else time.time()
    today = datetime.fromtimestamp(now, BJT).strftime("%Y-%m-%d")
    dates = state.get("ok_dates")
    dates = [d for d in dates if isinstance(d, str)] if isinstance(dates, list) else []
    if today not in dates:
        dates.append(today)
        try:
            state["ok_days_total"] = int(state.get("ok_days_total") or 0) + 1
        except (TypeError, ValueError):
            state["ok_days_total"] = 1
    state["ok_dates"] = dates[-OK_DATES_KEEP:]
    state["ok_first_date"] = state.get("ok_first_date") or today
    state["ok_last_date"] = today
    return state


def ok_run_days(state: Dict[str, Any], now: Optional[float] = None) -> int:
    """成功运行天数：优先累计计数 ok_days_total；历史状态无计数时
    以 first_seen_ts/saved_ts 为起点按日历天数近似（旧数据兼容口径）。"""
    try:
        total = int(state.get("ok_days_total") or 0)
    except (TypeError, ValueError):
        total = 0
    if total > 0:
        return total
    first_seen = state.get("first_seen_ts") or state.get("saved_ts")
    if isinstance(first_seen, (int, float)) and first_seen > 0:
        now = now if now is not None else time.time()
        return max(0, int((now - first_seen) / DAY_SEC))
    return 0


def build_tag(
    state: Dict[str, Any],
    cookie_str: str = "",
    learned: Optional[Dict[str, int]] = None,
    credential_match: CredentialMatch = None,
    window_days: Optional[int] = None,
    domain_hint: str = "",
    fallback_lifetime_days: Optional[int] = None,
    label: str = "Cookie",
    now: Optional[float] = None,
) -> str:
    """渲染有效期标签（签到流程此刻已验证登录态存活）。

    证据链见模块 docstring；无兜底窗口且无任何证据时如实报「有效期未知
    （已使用 N 天）」，绝不产出无依据的倒计时或假 0 天告警。
    """
    now = now if now is not None else time.time()
    ts = resolve_expire_ts(
        state, cookie_str, learned, credential_match, window_days, domain_hint, now
    )
    if ts:
        rem = remaining_days(ts, now)
        date_txt = datetime.fromtimestamp(ts, BJT).strftime("%Y-%m-%d")
        if rem < WARN_REMAINING_DAYS:
            return f" | ⚠️ {label} 剩余 {rem} 天（{date_txt} 到期，请尽快更新）"
        return f" | 🔑 {label} 剩余 {rem} 天（{date_txt} 到期）"

    first_seen = state.get("first_seen_ts")
    if not isinstance(first_seen, (int, float)) or first_seen <= 0:
        # 兼容历史任务的自建键名（smzdm/52pojie 的 saved_ts：Cookie 首次启用时刻）
        first_seen = state.get("saved_ts")
    ok_days = ok_run_days(state, now)
    if isinstance(first_seen, (int, float)) and first_seen > 0:
        used_days = max(0, int((now - first_seen) / DAY_SEC))
        if fallback_lifetime_days:
            rem = max(
                0, int((first_seen + int(fallback_lifetime_days) * DAY_SEC - now) / DAY_SEC)
            )
            if rem > 0:
                if rem < WARN_REMAINING_DAYS:
                    return f" | ⚠️ {label} 剩余 {rem} 天（请尽快更新）"
                return f" | 🔑 {label} 剩余 {rem} 天"
            # 超出估算窗口仍存活：寿命下限已破，随时可能失效 → 升级 ⚠️
            # （「有效期未知」字面为 report_fields 解析锚点，不得改动）
            return (
                f" | ⚠️ {label} 有效期未知"
                f"（已成功运行 {ok_days or used_days} 天，超出 {fallback_lifetime_days} 天估算窗口，建议预防性更新）"
            )
        # 无兜底窗口：按成功运行天数反推——达到老化基线 → ⚠️ 建议预防性更新
        # （alert_levels 以「有效期未知（已成功运行 N 天 … 建议预防性更新」为黄卡锚点）
        if ok_days >= UNKNOWN_AGING_WARN_DAYS:
            return (
                f" | ⚠️ {label} 有效期未知"
                f"（已成功运行 {ok_days} 天，达到 {UNKNOWN_AGING_WARN_DAYS} 天老化基线，建议预防性更新）"
            )
        if ok_days > 0:
            return f" | 🔑 {label} 有效期未知（已成功运行 {ok_days} 天，未观察到期证据）"
        return f" | 🔑 {label} 有效期未知（已使用 {used_days} 天，未观察到期证据）"
    return ""


def tag_for(
    cookie_str: str,
    state: Optional[Dict[str, Any]] = None,
    learned: Optional[Dict[str, int]] = None,
    **kwargs,
) -> str:
    """一步式便捷入口：update_state + build_tag（state 为 None 时用临时状态）。"""
    st = state if state is not None else {}
    update_state(st, cookie_str, learned)
    return build_tag(st, cookie_str=cookie_str, learned=learned, **kwargs)


# ---------------------------------------------------------------------------
# 自测
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    now = int(time.time())
    jwt = base64.urlsafe_b64encode(
        json.dumps({"exp": now + 50 * DAY_SEC}).encode()
    ).decode().rstrip("=")
    tok = f"hdr.{jwt}.sig"
    state = update_state({}, f"token={tok}")
    print(tag_for(f"token={tok}", state, label="Token"))
    sess = base64.b64encode(
        json.dumps({"_expire": (now + 20 * DAY_SEC) * 1000}).encode()
    ).decode()
    print(tag_for(f"koa:sess={sess}; other=x", {}))
    sc = f"a=1; Expires=Wed, {datetime.fromtimestamp(now + 10 * DAY_SEC, BJT).strftime('%d %b %Y %H:%M:%S')} GMT; Path=/"
    print(learn_from_response(type("R", (), {"headers": {"Set-Cookie": sc}})()))
    print("OK")
