#!/usr/bin/env python3
# cron: 50 16 * * *
# new Env("AgentRouter 签到")
"""AgentRouter (https://agentrouter.org / 备用域名 https://ps.air-outer.com) 每日自动签到脚本。

站点为 New API 面板（QuantumNous/new-api 定制构建）——实测协议（2026-08-21）：

⚠️ 本部署「签到 = 登录」：该站未注册任何独立签到 API
   （POST /api/user/checkin、/api/user/check_in 等均 404），前端也无签到按钮，
   登录成功即触发服务端签到（登录响应携带 checked_in=true 提示「签到成功，新增额度已到账」）。
   因此本脚本的核心动作就是每日 POST /api/user/login。

域名说明：agentrouter.org 经 CDN 代理，ps.air-outer.com 直连阿里云源站；
  两者登录行为一致（同一账号体系），CI 数据中心 IP 下备用域名 WAF 策略可能更宽松，
  默认走 AGENTROUTER_API_URL（CI 配置为 ps.air-outer.com）。

认证约定（实测）：
- 登录：POST /api/user/login?turnstile=   body {"username","password"}（密码明文直传）
  → 200 {"data":{...,"checked_in":true,...},"success":true} + Set-Cookie session=<30天有效期>
  checked_in=true   → 本次登录完成/已确认今日签到（「签到成功」）
  checked_in=false  → 今日已签到过（幂等放行）
- 用户信息：GET /api/user/self 需 Cookie: session=… + 强制头 New-API-User: <uid>
  （缺失 New-API-User 会 401「未提供 New-Api-User」）——用于展示真实余额。
- 登录前先 GET / 预热收集 Aliyun WAF（acw_tc）前置 cookie，降低数据中心 IP 风控拦截概率。

支持环境变量：
  AGENTROUTER_EMAIL      单账号登录邮箱（必填）
  AGENTROUTER_PASSWORD   单账号登录密码（必填）
  AGENTROUTER_ACCOUNTS   多账号，换行或 && 分隔，格式 email:password
  AGENTROUTER_API_URL    接口基础地址（默认 https://ps.air-outer.com，可改回 https://agentrouter.org）
  AGENTROUTER_STATE_FILE 本地 state 文件（默认 .agentrouter_state.json）
  AGENTROUTER_PROXY      SOCKS5 代理出口（如 socks5://127.0.0.1:1080），
                         用于绕过 CI 数据中心 IP 被 Aliyun WAF 滑块拦截的问题；
                         需配合 pip install pysocks 使用
  说明：本部署签到只能通过登录触发；如需展示余额，登录后自动用 session 查询 /api/user/self，
  无需额外配置。session 与 uid 会持久化到本地 + Upstash Redis 供诊断。
"""
import json
import os
import re
import sys
from http.cookiejar import Cookie
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from common import Http, env, env_seq, load_kv_state, main_guard, mask_str, save_kv_state

PREFIX = "AGENTROUTER_"
DEFAULT_API_URL = "https://ps.air-outer.com"

# 指纹方案（阿里 WAF 对 urllib 裸 TLS/socks5 链路识别打标，浏览器指纹放行）：
#   chrome124 — curl_cffi 最新 Chrome TLS1.3/HTTP2 指纹，实测对 aliyun_waf 放行。
# 走 common.Http(impersonate=...) 链路，仍复用预置护栏 Cookie 与代理出口环境变量。
_FINGERPRINT = os.getenv(f"{PREFIX}FINGERPRINT", "chrome124").strip() or "chrome124"

# 预置 Cookie（护栏）：把已通过 Aliyun WAF 质询的 acw_tc / session 等整串 Cookie
# 注入 CookieJar，登录请求自动携带，绕开挑战页（需出口 IP 与该 Cookie 匹配才有效）。
_PRESET_COOKIE = os.getenv(f"{PREFIX}COOKIE", "").strip() or os.getenv(f"{PREFIX}COOKIES", "").strip()

# 会话状态持久化文件（本地缓存，权威源为 Upstash Redis）
STATE_FILE = Path(os.getenv("AGENTROUTER_STATE_FILE", ".agentrouter_state.json"))
REDIS_KEY = f"{os.getenv('CAT_CHECKIN_REDIS_PREFIX', 'cat_checkin:')}agentrouter:state"

# 常规浏览器请求头（HAR 实测）
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0"
)


def _load_state() -> dict:
    """从 Upstash Redis 与本地 state 文件双层加载持久化的 session/uid 映射"""
    return load_kv_state(REDIS_KEY, STATE_FILE)


def _save_state(state: dict) -> None:
    """持久化 session/uid 映射到本地 state 文件与 Upstash Redis（双通道）"""
    save_kv_state(REDIS_KEY, STATE_FILE, state)


def _session_from_jar(h: Http) -> str:
    """从 Http 的 CookieJar 提取 session cookie 值"""
    for c in h.jar:
        if isinstance(c, Cookie) and c.name == "session":
            return c.value or ""
    return ""


def _seed_preset_cookies(h: Http) -> int:
    """注入预置护栏 Cookie（acw_tc 等）到 CookieJar。

    阿里 WAF 通过质询后签发的 acw_tc cookie 相当于护栏通行证：请求带它则直接放行，
    不再吐挑战页。用 AGENTROUTER_COOKIE（完整浏览器 Cookie 串）预埋进 jar。
    注意：acw_tc 绑定出口 IP 与域名，出口变化后需重新获取（失效表现为重出挑战页）。
    返回注入条数。
    """
    if not _PRESET_COOKIE:
        return 0
    count = 0
    for raw in _PRESET_COOKIE.split(";"):
        raw = raw.strip()
        if not raw or "=" not in raw:
            continue
        name, _, value = raw.partition("=")
        name, value = name.strip(), value.strip()
        if not name or not value:
            continue
        for existing in list(h.jar):
            if isinstance(existing, Cookie) and existing.name == name:
                h.jar.clear(existing.domain, existing.path, existing.name)
        c = Cookie(
            version=0, name=name, value=value,
            port=None, port_specified=False,
            domain=".air-outer.com", domain_specified=True, domain_initial_dot=False,
            path="/", path_specified=True,
            secure=True, expires=None, discard=True,
            comment=None, comment_url=None,
            rest={}, rfc2109=False,
        )
        h.jar.set_cookie(c)
        count += 1
    print(f"🛡️ 预置护栏 Cookie 注入 {count} 条 (acw_tc/session; 需与当前出口 IP 匹配)")
    return count


def _browser_cookies(h: Http, sess) -> None:
    """将 Http 的 CookieJar（含预置护栏 cookie）迁移到 curl_cffi 会话，供指纹链路复用。"""
    from http.cookiejar import Cookie as CJ_Cookie
    try:
        sess.cookies.clear()
    except Exception:
        pass
    for c in h.jar:
        if not isinstance(c, CJ_Cookie):
            continue
        try:
            sess.cookies.set(
                c.name, c.value or "",
                domain=c.domain, path=getattr(c, "path", "/"),
                secure=bool(getattr(c, "secure", True)),
            )
        except Exception:
            continue


def _fingerprint_session(h: Http):
    """基于 Http 实例构建 curl_cffi 指纹会话，并透传同一代理出口（socks5/http）。"""
    from curl_cffi import requests as cr
    sess_kwargs = {"impersonate": _FINGERPRINT, "timeout": 15}
    ep = getattr(h, "proxy_endpoint", None)
    proxy_url = getattr(ep, "url", "") if ep else ""
    if proxy_url:
        sess_kwargs["proxies"] = {"http": proxy_url, "https": proxy_url}
    elif getattr(h, "has_proxy", False):
        # 无 endpoint 但标记有代理（sockshandler 全局 patch 类）——回退本机代理
        sess_kwargs["proxies"] = {"http": "socks5://127.0.0.1:1080",
                                  "https": "socks5://127.0.0.1:1080"}
    return cr.Session(**sess_kwargs)


def perform_login(h: Http, base: str, username: str, password: str) -> tuple[int, str, dict]:
    """浏览器指纹链路登录：POST /api/user/login?turnstile=，返回 (状态码, 原始文本, json)。

    登录成功后 Set-Cookie session 由底座 CookieJar 自动捕获；护栏 cookie 由 _browser_cookies 注入。
    该链路透传 AGENTROUTER_PROXY 代理出口，保证出口 IP 与护栏 cookie 匹配。
    """
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "User-Agent": _UA,
        "Origin": base,
        "Referer": f"{base}/login",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }
    sess = _fingerprint_session(h)
    try:
        _browser_cookies(h, sess)
        # 预热首页，收集 Aliyun WAF（acw_tc）前缀 cookie——curl_cffi 指纹链路下同样需要
        try:
            sess.get(base + "/", headers={"User-Agent": _UA,
                                          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                          "Referer": base}, timeout=10)
        except Exception:
            pass
        resp = sess.post(base + "/api/user/login?turnstile=",
                         headers=headers,
                         json={"username": username, "password": password})
        return resp.status_code, resp.text, dict(resp.headers)
    finally:
        sess.close()


def perform_get(h: Http, url: str, headers: dict) -> tuple[int, str]:
    """浏览器指纹链路 GET，返回 (status, text)。配合 perform_login 使用，实现 /api/user/self 等。"""
    sess = _fingerprint_session(h)
    try:
        _browser_cookies(h, sess)
        resp = sess.get(url, headers=headers)
        return resp.status_code, resp.text
    finally:
        sess.close()


def _warmup(h: Http, base: str) -> None:
    """预热首页：收集 acw_tc 等 Aliyun WAF 前置 cookie，降低风控拦截概率。"""
    try:
        h.request("GET", f"{base}/", headers={
            "User-Agent": _UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": base,
        })
    except Exception:
        pass


def _login(h: Http, username: str, password: str, base: str) -> tuple[bool, str, str, str, str]:
    """登录并触发每日签到。

    返回 (是否已确认今日签到, checked_in 原始值, uid, session, access_token)。
    签到语义：登录成功即算今日签到完成（本部署签到=登录）：
      checked_in=true  → 本次签到完成今日签到（或今日已确认）
      checked_in=false → 今日已签到过（幂等）

    优先浏览器指纹链路（curl_cffi chrome124，绕 Aliyun WAF 指纹识别），
    失败或库缺失时回退原 urllib + socks5 链路。
    """
    from common import Http as _Http

    # ---------- 指纹链路 ----------
    if _FINGERPRINT:
        try:
            from curl_cffi import requests as cr  # noqa: F401
        except Exception:
            print("⚠️ curl_cffi 不可用，回退到原始 urllib 登录链路")
        else:
            code, text, hdrs = perform_login(h, base, username, password)
            data = {}
            try:
                data = json.loads(text)
            except Exception:
                data = {}
            if code == 200 and isinstance(data, dict) and data.get("success"):
                user_data = data.get("data") or {}
                if isinstance(user_data, dict) and user_data.get("id"):
                    uid = str(user_data["id"])
                    checked_in = bool(user_data.get("checked_in"))
                    session = _session_from_jar(h)
                    access_token = user_data.get("access_token") or ""
                    return True, checked_in, uid, session, access_token
            # 指纹链路未成功：记录原因后回退 urllib 链路
            err_hint = text[:200].replace("\n", " ")
            print(f"⟳ 指纹链路未成功 (HTTP {code}): {err_hint}")
            # fallthrough → urllib

    # ---------- 原始 urllib + socks5 链路 ----------
    _warmup(h, base)
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "User-Agent": _UA,
        "Origin": base,
        "Referer": f"{base}/login",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }
    resp = h.request("POST", f"{base}/api/user/login?turnstile=", headers=headers,
                     json_data={"username": username, "password": password})
    data = resp.json({})

    if resp.code != 200 or not isinstance(data, dict) or not data.get("success"):
        err_msg = data.get("message") if isinstance(data, dict) else ""
        text = resp.text[:500] if resp.text else ""
        hint = ""

        # ① Aliyun WAF 挑战页（滑块验证码）——浏览器出口 IP 或指纹仍被标记
        if "aliyun_waf" in text or "aliyunCaptcha" in text or "访问验证" in text:
            hint = (
                "（Aliyun WAF 挑战页仍出现——已尝试浏览器指纹链路；若仍拦截，"
                "说明出口 IP 或护栏 cookie 失效，需更新 AGENTROUTER_COOKIE）"
            )
        elif "Turnstile" in err_msg or "turnstile" in text.lower():
            hint = "（站点已启用 Turnstile 挑战校验，需要有效 turnstile token，无法自动登录）"
        elif resp.code in (401, 403) or "风控" in err_msg or "验证" in err_msg:
            hint = "（疑似被登录风控拦截，请人工确认账号状态或稍后重试）"
        elif err_msg and "两步" in str(err_msg):
            hint = "（该账号启用了两步验证，无法自动登录）"

        raise RuntimeError(f"登录失败 (HTTP {resp.code}): {err_msg or resp.text[:120]}{hint}")

    user_data = data.get("data") or {}
    if not isinstance(user_data, dict) or not user_data.get("id"):
        raise RuntimeError(f"登录响应异常: {resp.text[:200]}")

    uid = str(user_data["id"])
    checked_in = bool(user_data.get("checked_in"))
    session = _session_from_jar(h)
    access_token = user_data.get("access_token") or ""

    # 登录成功即本场今日签到（本部署签到=登录）
    sign_confirmed = True
    return sign_confirmed, checked_in, uid, session, access_token


def _fetch_self(h: Http, base: str, uid: str, token: str = "") -> dict:
    """GET /api/user/self 取真实余额。该站强制要求 Cookie + New-API-User 头。

    优先浏览器指纹链路（与登录一致，避免 urllib 指纹被 WAF 拦）；失败回退 urllib。
    session cookie 已由 CookieJar 自动携带。
    """
    headers = {
        "Accept": "application/json, text/plain, */*",
        "User-Agent": _UA,
        "Origin": base,
        "Referer": f"{base}/console",
        "New-API-User": uid,
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}" if not token.startswith("Bearer ") else token
    if _FINGERPRINT:
        try:
            from curl_cffi import requests as cr  # noqa: F401
        except Exception:
            pass
        else:
            try:
                code, text = perform_get(h, f"{base}/api/user/self", headers)
                data = json.loads(text) if text else {}
                if code == 200 and isinstance(data, dict) and data.get("success") and isinstance(data.get("data"), dict):
                    return data["data"]
                print(f"ℹ️ 指纹链路 self 未成功 (HTTP {code})，回退 urllib")
            except Exception as e:
                print(f"ℹ️ 指纹链路 self 异常 {e}，回退 urllib")
    resp = h.request("GET", f"{base}/api/user/self", headers=headers)
    data = resp.json({})
    if resp.code == 200 and isinstance(data, dict) and data.get("success") and isinstance(data.get("data"), dict):
        return data["data"]
    return {}


def _load_accounts() -> list[dict]:
    """解析账号凭据列表（email:password）。"""
    accounts = []

    # 1. 优先扫描序号配对的 EMAIL_1 / PASSWORD_1 序列
    emails = env_seq(PREFIX, "email", required=False) or env_seq(PREFIX, "username", required=False)
    passwords = env_seq(PREFIX, "password", required=False)
    for u, p in zip(emails, passwords):
        u, p = u.strip(), p.strip()
        if u and p:
            accounts.append({"username": u, "password": p})

    # 2. 扫描 ACCOUNTS 序列或兼容旧 ACCOUNTS 变量（换行 / && 切分）
    raw_accs = env_seq(PREFIX, "accounts", required=False) or env_seq(PREFIX, "account", required=False)
    for chunk in raw_accs:
        chunk = chunk.strip()
        if not chunk:
            continue
        if ":" in chunk:
            user_part, _, pass_part = chunk.partition(":")
            item = {"username": user_part.strip(), "password": pass_part.strip()}
            if item not in accounts:
                accounts.append(item)
        else:
            print(f"⚠️ 忽略无法解析的账号条目（需 email:password 格式）: {mask_str(chunk)}")

    return accounts


def _run_one(idx: int, total: int, account: dict, base: str) -> str:
    """执行单个账号：登录（即签到）→ 展示余额。"""
    username = account.get("username", "").strip()
    password = account.get("password", "").strip()

    if not (username and password):
        raise RuntimeError(f"账号{idx} 缺少邮箱或密码，请配置 {PREFIX}EMAIL / {PREFIX}PASSWORD 或 {PREFIX}ACCOUNTS")

    proxy = os.getenv(f"{PREFIX}PROXY", "").strip()
    h = Http(proxy=proxy, impersonate=_FINGERPRINT)
    _seed_preset_cookies(h)   # 预埋 acw_tc/session 护栏 Cookie，绕开 Aliyun WAF 挑战页

    # --- 1. 登录 = 签到 ---
    sign_confirmed, checked_in, uid, session, token = _login(h, username, password, base)

    if not sign_confirmed:
        raise RuntimeError("登录成功但未能确认今日签到状态，请检查账号状态")

    if checked_in:
        sign_msg = "签到成功"
    else:
        sign_msg = "今日已签到过"

    # --- 2. 展示真实余额（session 由 CookieJar 自动携带 + 强制 New-API-User 头） ---
    quota_desc = ""
    if session and uid:
        try:
            self_data = _fetch_self(h, base, uid, token)
            quota = self_data.get("quota")
            used = self_data.get("used_quota")
            if quota is not None:
                try:
                    quota_desc = f" | 💰 余额额度：{float(quota):,.0f}"
                    if used is not None:
                        quota_desc += f"（已用 {float(used):,.0f}）"
                except (TypeError, ValueError):
                    quota_desc = ""

            # 持久化 session/uid（诊断与后续展示用）；键名脱敏——明文邮箱不进 Redis/本地文件
            state = _load_state()
            state[f"login:{mask_str(username)}"] = session
            state[f"uid:{mask_str(username)}"] = uid
            _save_state(state)
        except Exception as e:
            print(f"ℹ️ 余额展示跳过: {e}")

    user_tag = mask_str(uid) if uid else mask_str(username)
    line = f"[{idx}/{total}] 账号：{user_tag} | {sign_msg}{quota_desc}"
    print(line)
    return line


def main():
    accounts = _load_accounts()
    if not accounts:
        raise RuntimeError(
            f"未配置凭据：请配置 {PREFIX}EMAIL 与 {PREFIX}PASSWORD（本部署签到=登录，二者必填），"
            f"或多账号 {PREFIX}ACCOUNTS（email:password）"
        )

    base = os.getenv(f"{PREFIX}API_URL", DEFAULT_API_URL).strip().rstrip("/")

    print("【AgentRouter 签到】")
    print(f"共 {len(accounts)} 个账号 | API: {base}")

    results = []
    for idx, acc in enumerate(accounts, 1):
        try:
            line = _run_one(idx, len(accounts), acc, base)
            results.append((True, line))
        except Exception as e:
            line = f"[{idx}/{len(accounts)}] 签到失败：{e}"
            print(line)
            results.append((False, line))

    ok_count = sum(1 for ok, _ in results if ok)
    print(f"\n========== 签到总结 ==========\n成功 {ok_count}/{len(accounts)}")
    if ok_count != len(accounts):
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
