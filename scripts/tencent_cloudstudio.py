#!/usr/bin/env python3
# cron: 55 9 * * *
# new Env("Tencent CloudStudio 签到")
"""Tencent CloudStudio (cloudstudio.net) 每日签到脚本。

协议逆向结论（2026-08-24 首版；2026-09-20 HAR 全链路复刻升级）：
- 认证体系：业务活动与账单端点强制依赖 Cookie 会话（cloudstudio-session）。
  控制台生成的个人访问令牌（API Key / OpenToken）归属于 Open API 开放生态/应用管理体系，
  传入业务接口会被网关判定为工作空间容器专用的 Workspace Token 而报 1044 错误，无法用于活动签到。
- CSRF 双站同源算法（djb2 变体 Vq()：t=5381; t+=(t<<5)+charCode; &0x7fffffff）：
    * cloudstudio.net   → X-XSRF-TOKEN = Vq(cloudstudio-session)
    * cloud.tencent.com → csrfCode     = Vq(skey)
  两处算法完全一致、仅输入不同；前端拦截器与 qcloud 开放平台授权页均按此派生，
  脚本本地复刻，无需人工从 DevTools 复制任何 CSRF 值。
- 凭据分层（强 → 弱，均为滚动续期）：
  1) 【既有】完整 cloudstudio.net Cookie（KEYCLOAK_IDENTITY / KEYCLOAK_SESSION 长期 SSO 票据
     + cloudstudio-session）：每次运行先请求 /api/public/login，经 Keycloak OIDC 静默换新
     30 天期 session（KEYCLOAK_IDENTITY 为 1 年期 Serialized-ID）；签到成功后再把本次链路
     全部 Set-Cookie（含 KEYCLOAK_*）合并持久化到 Upstash Redis，跨 CI 滚动续期。
  2) 【新增】qcloud 主站登录态（skey + uin，cloud.tencent.com 长效凭据）：
     无需任何 cloudstudio.net Cookie 即可从零铸造会话。HAR 复刻的完整开放平台授权链：
       GET  /api/public/login                    → 302 Keycloak OIDC auth（种 AUTH_SESSION_ID/KC_RESTART）
       GET  /auth/realms/.../broker/qcloud/login → 303 Location 携带 state
       POST cloud.tencent.com/open/ajax/open?action=grant&uin&csrfCode=Vq(skey)
            （Cookie: skey + uin；body: app_id=100036548734, grant_list=[0,11,15,23]）
            → {"authCode","signature"}
       GET  .../broker/qcloud/endpoint?code&signature&state
            → 302 /api/public/oauth/callback → 302 /api/public/post-login
            → Set-Cookie cloudstudio-session(+team) 与 KEYCLOAK_* 长期票据
     实测最小必需字段集：Cookie `skey` + `uin`（uin 可带 o 前缀），URL 查询参数 `uin` 需为裸数字。
     两者缺一即 "登录态验证失败，请重新登录"（NOT-LOGINED）。
- 签到两段式（与前端一致）：
  1. GET  /api/billing/activityTask/SIGN_IN_2025Q3?lastRecord=true 查记录状态
     （NOT_STARTED/IN_PROGRESS/COMPLETED/FAILED/REWARDING/REWARDED/REWARD_FAILED）
  2. 可领取（COMPLETED/REWARD_FAILED）→ POST /api/billing/activityTask/SIGN_IN_2025Q3/_reward
     今日记录已 REWARDED → 幂等放行；rewardNum 单位为亿分之一机时（1e8 = 1 机时）
- 资源汇总：GET /api/billing/resource/_summary（total/used/remaining）；
  明细列表沿用 GET /api/billing/resource/package?pageNumber=0&pageSize=10。

支持环境变量：
  CLOUDSTUDIO_cookie    浏览器 Cookie（自动识别两种形态，必填其一）：
                        a) cloudstudio.net 完整 Cookie（含 KEYCLOAK_* + cloudstudio-session）
                        b) cloud.tencent.com 登录态（含 skey + uin）——走新增开放平台授权链
  CLOUDSTUDIO_COOKIE_1  序列多账号
  CLOUDSTUDIO_skey      qcloud 凭据分列写法（与 cookie 序列同序；仅填 skey 时需配 _uin）
  CLOUDSTUDIO_uin       qcloud uin（裸数字或 o 前缀均可）
  CLOUDSTUDIO_xsrf      X-XSRF-TOKEN 覆盖值（可选；缺省自动按 Vq(session) 派生）
"""
import datetime as dt
import hashlib
import os
import re
import sys
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from common import Http, env_seq, find, findall, load_kv_state, main_guard, mask_str, save_kv_state

PREFIX = "CLOUDSTUDIO_"
BASE = "https://cloudstudio.net/api"
ACTIVITY = "SIGN_IN_2025Q3"

# qcloud 开放平台授权链常量（HAR 复刻，2026-09-20）
QCLOUD_APP_ID = "100036548734"
QCLOUD_CLIENT_ID = "cloudstudio-apiserver-club"
QCLOUD_GRANT_LIST = ["0", "11", "15", "23"]
QCLOUD_GRANT_URL = "https://cloud.tencent.com/open/ajax/open"


def _get_proxy() -> str:
    return (os.getenv("CLOUDSTUDIO_PROXY") or "").strip()


def derive_xsrf(session: str) -> str:
    """复刻前端 Vq()：djb2 变体哈希 session cookie → X-XSRF-TOKEN。

    同一算法亦用于 qcloud 主站的 csrfCode（输入改取 skey），见 derive_csrf(skey)。
    """
    t = 5381
    for ch in session:
        t += (t << 5) + ord(ch)
    return str(t & 2147483647)


def derive_csrf(skey: str) -> str:
    """复刻 qcloud 开放平台授权页：csrfCode = Vq(skey)（与 derive_xsrf 同算法）。"""
    return derive_xsrf(skey)


def extract_qcloud_credential(raw_cookie: str) -> Tuple[str, str]:
    """从任意 Cookie 串/裸值中提取 qcloud 主站登录态 (skey, uin)。

    支持三种形态：
      1. 完整浏览器 Cookie（含 skey= 与 uin=oXXXX 字段）
      2. 裸 skey 值（无 = 号，通常以 V1.0 或长随机串开头）
      3. "skey=...; uin=..." 键值对片段
    uin 自动剥离可选 o 前缀（授权 URL 查询参数要求裸数字，Cookie 里则两种都接受）。
    提取不到 skey 或 uin 时返回 ("", "")。
    """
    raw = (raw_cookie or "").strip()
    if not raw:
        return "", ""
    skey = ""
    uin = ""
    if "=" in raw:
        m = re.search(r"(?:^|;\s*)skey=([^;\s]+)", raw, re.IGNORECASE)
        if m:
            skey = m.group(1).strip()
        m = re.search(r"(?:^|;\s*)uin=([^;\s]+)", raw, re.IGNORECASE)
        if m:
            uin = m.group(1).strip()
    else:
        # 裸值：仅当不含分隔符且不像 session 形态时视为 skey
        first = raw.split(";")[0].strip()
        m = re.match(r"^(?:o)?(\d{5,15})$", first)
        if m:
            uin = first  # 纯数字 → 当作 uin
        else:
            skey = first
    uin = uin.strip()
    if uin.lower().startswith("o") and uin[1:].isdigit():
        uin = uin[1:]
    return skey, uin


_SESSION_STRUCT_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"(\.[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}){0,2}$"
)


def _looks_like_session(value: str) -> bool:
    """判断裸值是否像 cloudstudio-session（而非裸 skey 等其他不透明串）。

    cloudstudio-session 的结构是 2~3 段 UUID 点连接（uuid.uuid.uuid），旧版为 `s:` 前缀；
    qcloud skey 为 base64url 风格（A-Za-z0-9-_，不含点）。两者都是不透明长串，仅凭长度
    无法区分，故用结构特征消歧——避免裸 skey 被误认为会话。
    """
    v = (value or "").strip()
    if not v:
        return False
    if v.startswith(("s:", "s%3A")):
        return True
    return bool(_SESSION_STRUCT_RE.match(v))


def _has_session_field(raw_cookie: str) -> bool:
    """Cookie 串中是否以字段名显式声明了 cloudstudio-session（用户已明确指认，直接信任）。"""
    return bool(re.search(r"(?:^|;\s*)cloudstudio-session=", raw_cookie or "", re.IGNORECASE))


def normalize_credential(raw_cookie: str) -> Dict[str, str]:
    """判定凭据形态：优先 cloudstudio 会话，其次 qcloud 主站登录态。

    返回 {"kind": "cloudstudio"|"qcloud"|"", "skey": str, "uin": str, ...}。
    判定不看单一字段是否出现，而看「该形态是否足以完成一次换票」：
      - cloudstudio：显式 cloudstudio-session 字段，或裸会话值（含 s: / 点分隔结构），
        或同时存在 KEYCLOAK_IDENTITY 与 KEYCLOAK_SESSION
      - qcloud     ：skey 与 uin 同时可提取
    裸值消歧：cloudstudio-session 为 uuid.uuid.uuid（含点），skey 为 base64url 风格（含 -/_、
    不含点），两者都是不透明长串，仅凭长度无法区分，故对裸值做结构判定；带字段名的值直接信任。
    """
    raw = (raw_cookie or "").strip()
    session = extract_session(raw)
    if session and not _has_session_field(raw) and not _looks_like_session(session):
        session = ""  # 裸 skey 等非会话值不得被当作 cloudstudio 会话
    has_kc = bool(
        re.search(r"(?:^|;\s*)KEYCLOAK_IDENTITY=", raw, re.IGNORECASE)
        and re.search(r"(?:^|;\s*)KEYCLOAK_SESSION=", raw, re.IGNORECASE)
    )
    if session or has_kc:
        return {"kind": "cloudstudio", "session": session, "skey": "", "uin": ""}
    skey, uin = extract_qcloud_credential(raw)
    if skey and uin:
        return {"kind": "qcloud", "session": "", "skey": skey, "uin": uin}
    return {"kind": "", "session": "", "skey": skey, "uin": uin}


def mask_credential(raw_cookie: str) -> str:
    """凭据形态脱敏描述（供日志/报错展示，绝不回显原始值）。"""
    info = normalize_credential(raw_cookie)
    if info["kind"] == "cloudstudio":
        return f"cloudstudio 会话（session={mask_str(info['session'], 8, 4)}）"
    if info["kind"] == "qcloud":
        return f"qcloud 登录态（skey={mask_str(info['skey'], 4, 2)}，uin={mask_str(info['uin'], 3, 2)}）"
    return "无法识别的凭据形态"


def extract_session(raw_cookie: str) -> str:
    """兼容裸 session 值、含 cloudstudio-session= 的键值对 或 完整浏览器 Cookie 字符串。"""
    raw = raw_cookie.strip()
    if not raw:
        return ""
    m = re.search(r"(?:^|;\s*)cloudstudio-session=([^;\s]+)", raw, re.IGNORECASE)
    if m:
        return m.group(1).rstrip(";")
    if raw.startswith("s:") or raw.startswith("s%3A"):
        return raw.split(";")[0].strip()
    if ";" not in raw and not re.search(r"^[a-zA-Z0-9_-]+=", raw):
        return raw
    return ""


def _merge_cookie_str(base: str, jar: Any) -> str:
    """合并已有 Cookie 串与 urllib CookieJar 中的最新 Set-Cookie（同名覆盖）。"""
    cookie_dict: Dict[str, str] = {}
    if base:
        for part in base.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k.strip():
                    cookie_dict[k.strip()] = v.strip()
    for c in jar or ():
        if getattr(c, "name", None) and getattr(c, "value", None):
            cookie_dict[c.name] = c.value
    return "; ".join(f"{k}={v}" for k, v in cookie_dict.items())


def _set_session_in_cookie(cookie_str: str, session: str) -> str:
    """强制覆写 cookie 串中的 cloudstudio-session 值（无则追加），保留其余票据。"""
    parts = [
        p.strip()
        for p in (cookie_str or "").split(";")
        if "=" in p
        and p.strip().split("=", 1)[0].strip()
        and p.strip().split("=", 1)[0].strip().lower() != "cloudstudio-session"
    ]
    parts.append(f"cloudstudio-session={session}")
    return "; ".join(parts)


def try_keycloak_sso(raw_cookie: str) -> Tuple[bool, str, str]:
    """尝试利用包含 KEYCLOAK_IDENTITY / KEYCLOAK_SESSION 长期票据的完整 Cookie 静默重换 session。

    返回 (是否成功, 新 session, 合并了本次 SSO 全部 Set-Cookie 的完整 Cookie 串)。
    合并结果即使换票失败也返回——其中 KEYCLOAK_* 票据的更新对后续重试仍有价值。
    """
    if not raw_cookie or "=" not in raw_cookie:
        return False, "", raw_cookie or ""
    h = Http(follow_redirects=True, proxy=_get_proxy())
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Referer": "https://cloudstudio.net/",
        "Cookie": raw_cookie,
    }
    url = "https://cloudstudio.net/api/public/login?client_id=cloudstudio-apiserver-club"
    r = h.request("GET", url, headers=headers)
    merged = _merge_cookie_str(raw_cookie, h.jar)
    for c in h.jar:
        if c.name == "cloudstudio-session" and c.value:
            return True, c.value, merged
    print(
        f"    [diag] SSO 未取到新 session（HTTP {r.code}，最终 URL: {r.url}）——"
        "KEYCLOAK 长期票据可能已失效或被要求交互式重新登录"
    )
    return False, "", merged


def mint_session_from_qcloud(skey: str, uin: str) -> Tuple[bool, str, str]:
    """用 qcloud 主站登录态（skey + uin）从零铸造 cloudstudio.net 会话。

    HAR 复刻的开放平台授权链（全部实测通过，2026-09-20）：
      1. GET  /api/public/login                            → 302 Keycloak OIDC auth
      2. GET  Keycloak auth 页                             → 种 AUTH_SESSION_ID / KC_RESTART
      3. GET  /auth/realms/.../broker/qcloud/login         → 303 Location 含 state
      4. POST cloud.tencent.com/open/ajax/open (grant)     → authCode + signature
      5. GET  .../broker/qcloud/endpoint?code&signature&state（携带 Keycloak 会话 Cookie）
                                                           → 302 oauth/callback → 302 post-login
                                                             Set-Cookie cloudstudio-session(+team) 与 KEYCLOAK_*
    全程用一个 no-redirect Http 实例显式逐跳推进：既能在 broker 步读取 Location 中的 state，
    又能让 CookieJar 捕获链路每一跳的 Set-Cookie（含 KEYCLOAK_* 长期票据）。

    返回 (是否成功, 新 session, 合并全部 Set-Cookie 的 Cookie 串)。
    失败时返回 ("", 已捕获的 Cookie 串)，调用方据此给出精确诊断。
    """
    skey = (skey or "").strip()
    uin = (uin or "").strip()
    if not skey or not uin:
        return False, "", ""
    if uin.lower().startswith("o") and uin[1:].isdigit():
        uin = uin[1:]
    proxy = _get_proxy()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Referer": "https://cloudstudio.net/",
    }
    h = Http(follow_redirects=False, proxy=proxy)

    def _jar_str() -> str:
        return _merge_cookie_str("", h.jar)

    # 1) 发起 OIDC 登录：拿 Keycloak 授权页地址
    r = h.request(
        "GET",
        f"https://cloudstudio.net/api/public/login?client_id={QCLOUD_CLIENT_ID}&channel=ide-popup",
        headers=headers,
    )
    auth_url = r.headers.get("Location", "") if r.headers else ""
    if r.code not in (301, 302, 303, 307, 308) or not auth_url:
        print(f"    [diag] qcloud 换票第 1 步失败：/api/public/login HTTP {r.code}，未取到 Keycloak 授权地址")
        return False, "", _jar_str()

    # 2) 打开 Keycloak 授权页：种下 AUTH_SESSION_ID / KC_RESTART，并解析 qcloud broker 登录链
    r = h.request("GET", auth_url, headers=headers)
    if r.code != 200:
        print(f"    [diag] qcloud 换票第 2 步失败：Keycloak 授权页 HTTP {r.code}")
        return False, "", _jar_str()
    m = re.search(r'data-link="([^"]*broker/qcloud/login[^"]*)"', r.text)
    if not m:
        print("    [diag] qcloud 换票第 2 步失败：Keycloak 授权页未找到 broker/qcloud/login 链接")
        return False, "", _jar_str()
    broker_link = urllib.parse.urljoin("https://cloudstudio.net/", m.group(1).replace("&amp;", "&"))

    # 3) 进入 qcloud broker：303 跳转的 Location 携带 state（后续回调必须原样带回）
    r = h.request("GET", broker_link, headers=headers)
    loc = r.headers.get("Location", "") if r.headers else ""
    st = re.search(r"[?&]state=([^&]+)", loc)
    if r.code not in (301, 302, 303, 307, 308) or not st:
        print(f"    [diag] qcloud 换票第 3 步失败：broker/qcloud/login HTTP {r.code}，未取到 state")
        return False, "", _jar_str()
    state = st.group(1)

    # 4) 授权换 authCode：csrfCode = Vq(skey)，Cookie 最小集 = skey + uin
    redirect_url = (
        "https://cloudstudio.net/pages/login/loading.html"
        "?t_url_opener=https://cloudstudio.net/auth/realms/cloudstudio/broker/qcloud/endpoint"
    )
    grant_url = f"{QCLOUD_GRANT_URL}?action=grant&uin={uin}&csrfCode={derive_csrf(skey)}"
    grant_headers = {
        **headers,
        "Referer": "https://cloud.tencent.com/open/authorize",
        "Origin": "https://cloud.tencent.com",
        "X-Requested-With": "XMLHttpRequest",
        "Cookie": f"skey={skey}; uin=o{uin}",
    }
    r = h.request(
        "POST", grant_url, headers=grant_headers,
        json_data={
            "scope": "login",
            "app_id": QCLOUD_APP_ID,
            "open_access_token": "",
            "pre_auth_code": "",
            "redirect_url": redirect_url,
            "grant_list": QCLOUD_GRANT_LIST,
        },
    )
    gj = r.json({}) or {}
    gd = gj.get("data") if isinstance(gj, dict) else None
    auth_code = (gd or {}).get("authCode", "") if isinstance(gd, dict) else ""
    signature = (gd or {}).get("signature", "") if isinstance(gd, dict) else ""
    if r.code != 200 or not auth_code or not signature:
        code = gj.get("code") if isinstance(gj, dict) else ""
        msg = (gj.get("msg") if isinstance(gj, dict) else "") or ""
        print(
            f"    [diag] qcloud 换票第 4 步失败：grant HTTP {r.code} code={code} "
            f"msg={mask_str(msg, 24, 0) if msg else '(空)'}——skey/uin 可能已失效"
        )
        return False, "", _jar_str()

    # 5) 带 state 回调 broker endpoint：自动跟随 302 链，落地 cloudstudio-session 与 KEYCLOAK_*
    endpoint_url = (
        f"https://cloudstudio.net/auth/realms/cloudstudio/broker/qcloud/endpoint"
        f"?code={auth_code}&signature={signature}&state={urllib.parse.quote(state, safe='')}"
    )
    r = h.request("GET", endpoint_url, headers=headers)
    # 逐跳跟随剩余重定向（oauth/callback → post-login → 落地页）
    hops = 0
    while r.code in (301, 302, 303, 307, 308) and hops < 5:
        nxt = r.headers.get("Location", "") if r.headers else ""
        if not nxt:
            break
        nxt = urllib.parse.urljoin("https://cloudstudio.net/", nxt)
        r = h.request("GET", nxt, headers=headers)
        hops += 1

    merged = _jar_str()
    session = ""
    for c in h.jar:
        if c.name == "cloudstudio-session" and c.value:
            session = c.value
    if session:
        return True, session, merged
    print(
        f"    [diag] qcloud 换票第 5 步失败：回调链未下发 cloudstudio-session"
        f"（HTTP {r.code}，最终 URL: {r.url}）"
    )
    return False, "", merged


def _cookie_issue_hint(raw_cookie: str) -> str:
    """根据 Secrets 中 Cookie 的形态给出精确的失效原因与修复指引。"""
    raw = (raw_cookie or "").strip()
    if not raw:
        return (
            "CLOUDSTUDIO_cookie 未配置。两种推荐凭据任选其一："
            "a) cloud.tencent.com 登录态（skey + uin，最省事——从浏览器任一 cloud.tencent.com "
            "请求的 Cookie 请求头复制 skey 与 uin 两项即可）；"
            "b) cloudstudio.net 完整 Cookie（含 KEYCLOAK_IDENTITY、KEYCLOAK_SESSION 与 "
            "cloudstudio-session 三项）"
        )

    info = normalize_credential(raw)
    skey, uin = info.get("skey", ""), info.get("uin", "")

    # 仅识别到 qcloud 半套凭据：指出缺哪一项
    if not info["kind"] and (skey or uin):
        have = "skey" if skey else "uin"
        miss = "uin" if skey else "skey"
        return (
            f"凭据中只识别到 qcloud 的 {have}，缺少 {miss}，无法走开放平台授权链换票。"
            "请从浏览器任一 cloud.tencent.com 请求的 Cookie 请求头同时复制 skey 与 uin"
            "（uin 形如 o1234567890，脚本会自动剥离 o 前缀）"
        )

    if info["kind"] == "qcloud":
        return (
            "qcloud 登录态（skey/uin）已无法完成开放平台授权换票——skey 可能已在浏览器端"
            "退出登录或过期。请重新登录 cloud.tencent.com 后复制最新的 skey 与 uin 更新 Secrets"
        )

    if "=" not in raw:
        return (
            "Secrets 中只有裸 cloudstudio-session 值，无法进行 Keycloak SSO 自动续票"
            "（30 天后必失效）。推荐改用 qcloud 登录态（skey + uin，同样可自动换票且更易获取），"
            "或复制 cloudstudio.net 完整浏览器 Cookie：必须包含 "
            "KEYCLOAK_IDENTITY、KEYCLOAK_SESSION 与 cloudstudio-session 三项"
            "（KEYCLOAK_* 路径限定在 /auth/realms/cloudstudio/，需从 Network 面板任一请求"
            "的 Cookie 请求头整串复制，或在 Application→Cookies 中逐条合并）"
        )
    if "KEYCLOAK_IDENTITY" not in raw:
        return (
            "完整 Cookie 中缺少 KEYCLOAK_IDENTITY 长期票（1 年期 SSO 票据，路径 "
            "/auth/realms/cloudstudio/）。document.cookie 读不到路径限定的 Cookie，"
            "请从 Network 面板任一请求的 Cookie 请求头整串复制，或 "
            "Application→Cookies→cloudstudio.net 中合并 /auth/realms/cloudstudio "
            "路径下的 KEYCLOAK_IDENTITY 与 KEYCLOAK_SESSION"
        )
    if "cloudstudio-session" not in raw:
        return "完整 Cookie 中缺少 cloudstudio-session，请重新登录后整串复制"
    return (
        "KEYCLOAK 长期票据已无法静默换票（可能已被服务端吊销或要求交互式重新登录）。"
        "请在浏览器重新登录 CloudStudio 后整串复制最新完整 Cookie 更新 Secrets，"
        "或改用更易维护的 qcloud 登录态（skey + uin）"
    )


def bj_now_str() -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")


def bj_date_of_iso(value: str) -> str:
    """ISO8601(UTC) → 北京时间日期串；解析失败返回空。"""
    if not value:
        return ""
    try:
        d = dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
            dt.timezone(dt.timedelta(hours=8))
        )
        return d.strftime("%Y-%m-%d")
    except ValueError:
        return ""


def _do_checkin_and_query(session: str, xsrf_override: str, cookie_str: str = "") -> Tuple[bool, str, Http]:
    xsrf = xsrf_override or derive_xsrf(session)
    cookie_val = _set_session_in_cookie(cookie_str, session) if cookie_str else f"cloudstudio-session={session}"
    headers = {
        "Cookie": cookie_val,
        "X-XSRF-TOKEN": xsrf,
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "https://cloudstudio.net/",
    }
    h = Http(proxy=_get_proxy())

    # === 1. 签到两段式：先查今日记录，再决定是否领取 ===
    today = bj_now_str()[:10]
    # 优先新接口（全量任务列表），兼容旧接口（按 ACTIVITY ID 查询）
    q = h.request("GET", f"{BASE}/billing/activityTask?lastRecord=true", headers=headers)

    if q.code in (401, 403) or q.code in (301, 302, 303, 307, 308):
        return False, f"AUTH_EXPIRED_{q.code}", h
    qjson = q.json({}) or {}
    if qjson.get("code") in (1022, 1044):
        return False, f"AUTH_EXPIRED_{qjson.get('code')}", h

    status, record = "", {}
    if q.code == 200:
        data = qjson.get("data")
        records = []
        if isinstance(data, list):
            for task in data:
                if task.get("taskId") == ACTIVITY:
                    records = task.get("records") or []
                    break
        elif isinstance(data, dict):
            records = data.get("records") or []
        if records:
            record = records[0]
            status = record.get("status", "")
            # completeTime 非今日的旧记录视为未签（跨日残留）
            if bj_date_of_iso(record.get("completeTime", "")) != today:
                status, record = "", {}

    if status in ("REWARDED", "REWARDING"):
        reward = float(record.get("rewardNum", 0)) / 100000000
        status_line = (
            f"今日已签到过（本次奖励 {reward:.2f} 机时）"
            if reward > 0
            else "今日已签到过"
        )
    else:
        # COMPLETED / REWARD_FAILED / 未查到记录：直接领取，以响应为准
        s = h.request(
            "POST", f"{BASE}/billing/activityTask/{ACTIVITY}/_reward",
            headers=headers, json_data={},
        )
        if s.code in (401, 403) or s.code in (301, 302, 303, 307, 308):
            return False, f"AUTH_EXPIRED_{s.code}", h
        sjson = s.json({}) or {}
        if sjson.get("code") in (1022, 1044):
            return False, f"AUTH_EXPIRED_{sjson.get('code')}", h
        if s.code >= 400 or s.code < 0:
            msg = find(r'"msg":"(.*?)"', s.text, s.text[:120])
            raise RuntimeError(f"签到接口 HTTP {s.code}: {msg}")
        sdata = sjson.get("data")
        records = []
        if isinstance(sdata, list):
            for task in sdata:
                if task.get("taskId") == ACTIVITY:
                    records = task.get("records") or []
                    break
        elif isinstance(sdata, dict):
            records = sdata.get("records") or []
        rec = records[0] if records else {}
        reward = float(rec.get("rewardNum", 0) or 0) / 100000000
        fail_msg = rec.get("failMessage") or sjson.get("msg") or ""
        if reward > 0:
            status_line = f"签到成功，获得 {reward:.2f} 机时"
        elif rec.get("status") in ("REWARDED", "REWARDING"):
            status_line = "今日已签到过"
        else:
            raise RuntimeError(f"签到未到账: status={rec.get('status')} {fail_msg}"[:160])

    # nick 仅用于报告展示
    nick = "?"
    u = h.request("GET", f"{BASE}/user/info", headers=headers)
    if u.code == 200:
        ujson = u.json({})
        auth = (ujson.get("data") or {}).get("authenticationUserInfo") or {} if isinstance(ujson, dict) else {}
        nick = auth.get("nickName") or find(r'"nickName":"(.*?)"', u.text, "?")

    # === 3. 资源汇总 + 明细 ===
    p_resp = h.request(
        "GET", f"{BASE}/billing/resource/package?pageNumber=0&pageSize=10", headers=headers
    )
    pkg_list = []
    json_data = p_resp.json({})
    if isinstance(json_data, dict) and isinstance(json_data.get("data"), dict) \
            and isinstance(json_data["data"].get("list"), list):
        for item in json_data["data"]["list"]:
            pkg_list.append({
                "name": item.get("name", ""),
                "total": float(item.get("total", 0)) / 100000000,
                "used": float(item.get("used", 0)) / 100000000,
                "exp": str(item.get("expiredTime", "")).replace("T", " ").replace(".000+00:00", ""),
            })

    summary = h.request("GET", f"{BASE}/billing/resource/_summary", headers=headers)
    sum_total = sum_remain = None
    sdata = (summary.json({}) or {}).get("data") or {}
    pkg = sdata.get("package") if isinstance(sdata, dict) else None
    if isinstance(pkg, dict):
        sum_total = float(pkg.get("total", 0)) / 100000000
        sum_remain = float(pkg.get("remaining", 0)) / 100000000

    # === 4. 报告输出 ===
    bj_now = bj_now_str()
    lines = [f"用户 {mask_str(nick)} {status_line}"]
    if not pkg_list:
        lines.append("暂无可用资源包")
    else:
        groups = {}
        total_rem_sum = 0.0
        total_cap_sum = 0.0
        for item in pkg_list:
            name, total_val, used_val, exp = item["name"], item["total"], item["used"], item["exp"]
            rem = max(0.0, total_val - used_val)
            total_rem_sum += rem
            total_cap_sum += total_val
            g = groups.setdefault(name, {"count": 0, "total": 0.0, "used": 0.0,
                                         "exps": [], "active_exps": []})
            g["count"] += 1
            g["total"] += total_val
            g["used"] += used_val
            if exp:
                g["exps"].append(exp)
                if rem > 0 and exp >= bj_now:
                    g["active_exps"].append(exp)

        tot_cap_str = f"{int(total_cap_sum)}" if total_cap_sum.is_integer() else f"{total_cap_sum:.2f}"
        lines.append(f"可用资源总计：剩余 {total_rem_sum:.2f} / {tot_cap_str} 机时")
        if sum_total is not None:
            lines.append(f"服务端汇总：剩余 {sum_remain:.2f} / {sum_total:.2f} 机时")

        for name, g in groups.items():
            rem = max(0.0, g["total"] - g["used"])
            valid_exps = g["active_exps"] or g["exps"]
            earliest_exp = min(valid_exps) if valid_exps else ""
            exp_date = earliest_exp.split(" ")[0] if earliest_exp else ""
            count = g["count"]
            tot = g["total"]
            exp_info = (
                f"，最早 {exp_date} 到期" if (count > 1 and exp_date)
                else (f"，{exp_date} 到期" if exp_date else "")
            )
            tot_str = f"{int(tot)}" if tot.is_integer() else f"{tot:.2f}"
            lines.append(f"• {name} ({count}个包): 剩余 {rem:.2f}/{tot_str} 机时{exp_info}")

    return True, "\n".join(lines), h


def _mint_and_checkin(skey: str, uin: str, xsrf_override: str) -> Tuple[bool, str, str]:
    """qcloud 凭据路径：skey+uin 铸会话 → 签到 → 返回 (ok, 报告, cookie 串)。

    换票成功后立即把新会话交给签到链路；KEYCLOAK_* 长期票据随返回值一并
    持久化，下次运行即可退化到更轻的 SSO 静默续票。
    """
    ok, session, merged = mint_session_from_qcloud(skey, uin)
    if not ok or not session:
        return False, "", merged
    print(f"    🔑 qcloud 授权换票成功，新 session: {session[:12]}***")
    cok, report, h = _do_checkin_and_query(session, xsrf_override, merged)
    if not cok:
        # 换票成功但业务接口仍拒绝：把新会话回递给调用方做一次 SSO 复核
        return False, "", _merge_cookie_str(_set_session_in_cookie(merged, session), h.jar)
    return True, report, _merge_cookie_str(_set_session_in_cookie(merged, session), h.jar)


def _run_one(raw_cookie: str, xsrf_override: str, idx: int, total: int) -> Tuple[bool, str]:
    prefix_label = f"[{idx}/{total}] " if total > 1 else ""
    state_file = f".cloudstudio_state_{idx}.json"
    redis_key = f"cat_checkin:state:cloudstudio_{idx}"
    saved_state = load_kv_state(redis_key, state_file) or {}
    saved_cookie = str(saved_state.get("cookie") or "").strip()
    saved_session = str(saved_state.get("session") or "").strip()  # 兼容旧版仅存 session 的状态
    saved_env_hash = str(saved_state.get("env_hash") or "").strip()
    saved_skey = str(saved_state.get("skey") or "").strip()
    saved_uin = str(saved_state.get("uin") or "").strip()
    raw_session = extract_session(raw_cookie)
    env_hash = hashlib.md5(raw_cookie.encode("utf-8")).hexdigest() if raw_cookie else ""

    # 起始凭据：env 更新感知（用户更新了 Secrets → 新 env 优先）；否则滚动 state 优先
    if raw_cookie and env_hash and env_hash != saved_env_hash:
        print(f"{prefix_label}🆕 检测到环境变量凭据已更新，优先使用最新配置")
        base_cookie = raw_cookie
    else:
        base_cookie = saved_cookie or raw_cookie

    info = normalize_credential(base_cookie)
    qcloud_skey = info.get("skey") or saved_skey
    qcloud_uin = info.get("uin") or saved_uin

    # ---- 分支 A：qcloud 主站登录态（skey + uin）→ 开放平台授权链铸会话 ----
    if info["kind"] == "qcloud" or (not extract_session(base_cookie) and qcloud_skey and qcloud_uin):
        print(f"{prefix_label}🔐 使用 qcloud 登录态（skey+uin）铸造 CloudStudio 会话...")
        ok, report, merged = _mint_and_checkin(qcloud_skey, qcloud_uin, xsrf_override)
        if ok:
            session = extract_session(merged)
            save_kv_state(
                redis_key, state_file,
                {"cookie": merged, "session": session, "skey": qcloud_skey, "uin": qcloud_uin,
                 "env_hash": env_hash, "updated_at": bj_now_str()},
            )
            return True, f"{prefix_label}{report}"
        # 铸票失败：若 state 中还留有上一轮的有效会话，降级尝试一次
        if not saved_cookie or extract_session(saved_cookie) == "":
            raise RuntimeError(f"qcloud 换票失败且无可用历史会话。{_cookie_issue_hint(raw_cookie)}")
        print(f"{prefix_label}🔄 qcloud 换票失败，回退上一轮会话再试...")
        base_cookie = saved_cookie
        info = normalize_credential(base_cookie)

    # ---- 分支 B：cloudstudio 会话 Cookie（既有链路，保留不动） ----
    session = extract_session(base_cookie) or raw_session
    if not session and saved_session:
        # 旧版状态迁移：只有裸 session（KEYCLOAK 长期票已丢失，保底使用）
        session = saved_session
        base_cookie = f"cloudstudio-session={saved_session}"

    if not session:
        raise RuntimeError(f"CLOUDSTUDIO_cookie 未找到可用凭据。{_cookie_issue_hint(raw_cookie)}")

    # 主动 Keycloak 续票（滚动续期核心）：每次运行先用长期票据静默换新 session，
    # 让 30 天期 session 永远保持新鲜；换票失败只打诊断，不影响本次签到（当前 session 仍有效）
    if "=" in base_cookie:
        sso_ok, sso_session, merged = try_keycloak_sso(base_cookie)
        if sso_ok and sso_session:
            print(f"{prefix_label}🔑 SSO 主动续票成功，使用新 session: {sso_session[:12]}***")
            session = sso_session
            base_cookie = merged
        elif not session:
            base_cookie = merged

    ok, report, h = _do_checkin_and_query(session, xsrf_override, base_cookie)
    if not ok and report.startswith("AUTH_EXPIRED"):
        # 回退 1：环境变量中的 session（用户可能刚更新过）
        if raw_session and raw_session != session:
            print(f"{prefix_label}🔄 session 失效（{report}），回退使用环境变量中的 session...")
            ok, report, h = _do_checkin_and_query(raw_session, xsrf_override, raw_cookie)
            if ok:
                session = raw_session
        # 回退 2：Keycloak SSO 重新换票
        if not ok and report.startswith("AUTH_EXPIRED") and "=" in (base_cookie or ""):
            print(f"{prefix_label}🔄 正在通过 Keycloak SSO 重新换票...")
            sso_ok, new_session, merged = try_keycloak_sso(base_cookie)
            if sso_ok and new_session and new_session != session:
                print(f"{prefix_label}🔑 SSO 换票成功: {new_session[:12]}***，重新签到...")
                ok, report, h = _do_checkin_and_query(new_session, xsrf_override, merged)
                if ok:
                    session = new_session
                    base_cookie = merged
        # 回退 3：qcloud 凭据仍然可用 → 走开放平台授权链重铸（覆盖 KEYCLOAK 票据也被吊销的场景）
        if not ok and report.startswith("AUTH_EXPIRED") and qcloud_skey and qcloud_uin:
            print(f"{prefix_label}🔄 SSO 换票仍失败，改用 qcloud 授权链重新铸票...")
            q_ok, q_report, merged = _mint_and_checkin(qcloud_skey, qcloud_uin, xsrf_override)
            if q_ok:
                ok, report = True, q_report
                session = extract_session(merged)
                base_cookie = merged

    if not ok:
        raise RuntimeError(f"Cookie 已失效且自动续票失败。{_cookie_issue_hint(raw_cookie)}")

    # 签到成功：合并本次链路全部 Set-Cookie（含 KEYCLOAK_* 长期票与可能滚动的 session）
    # 持久化——下次运行 SSO 主动续票直接复用长期票据，这是 cookie 长期存活的关键
    merged_full = _merge_cookie_str(_set_session_in_cookie(base_cookie, session), h.jar)
    state_payload = {
        "cookie": merged_full,
        "session": extract_session(merged_full) or session,
        "env_hash": env_hash,
        "updated_at": bj_now_str(),
    }
    # qcloud 凭据一并持久化：CI 下 Secrets 通常只配一次，滚动 state 是换票主力
    if qcloud_skey and qcloud_uin:
        state_payload["skey"] = qcloud_skey
        state_payload["uin"] = qcloud_uin
    save_kv_state(redis_key, state_file, state_payload)

    return True, f"{prefix_label}{report}"


def _persist_last_credit_ts(task_id: str) -> None:
    """把本次签到成功时刻写入通知状态（心跳 12h 滚动冷却的调度状态来源）。

    与 modelscope 的 last_credit_ts 通道同构（{prefix}:state:notify:{task_id}）；
    TASK_ID 缺失（本地手动运行）时跳过，冷却判定由 orchestrator 读取。
    """
    if not task_id:
        return
    try:
        prefix = (os.getenv("CAT_CHECKIN_REDIS_PREFIX") or "cat_checkin:").rstrip(":")
        state_file = f".notify_state_{task_id}.json"
        state = load_kv_state(f"{prefix}:state:notify:{task_id}", state_file)
        state["last_credit_ts"] = time.time()
        state["updated_at"] = int(time.time())
        save_kv_state(f"{prefix}:state:notify:{task_id}", state_file, state)
        print("  [sched] last_credit_ts → now（12h 滚动冷却重新计时）")
    except Exception as exc:
        print(f"  ⚠️ last_credit_ts 持久化失败: {exc}")


def _build_credentials() -> List[str]:
    """汇总凭据来源，保持多账号有序：优先 CLOUDSTUDIO_cookie 序列，
    其次由 CLOUDSTUDIO_skey/_uin 分列序列合成，最后回退未编号单变量。

    返回规范化后的凭据串列表（cookie 原串 或 "skey=..; uin=.." 合成串）。
    两者都未配置时抛错——换票两条路径都需要凭据。
    """
    cookies = env_seq(PREFIX, "cookie", required=False)
    skeys = env_seq(PREFIX, "skey", required=False)
    uins = env_seq(PREFIX, "uin", required=False)

    if cookies:
        return [c.strip() for c in cookies if c.strip()]

    creds: List[str] = []
    for i, skey in enumerate(skeys):
        skey = skey.strip()
        if not skey:
            continue
        uin = uins[i].strip() if i < len(uins) else ""
        # 单账号无 uin 时，允许 skey 串自带 uin（如 "skey=..; uin=.."）
        if uin:
            creds.append(f"skey={skey}; uin={uin}")
        else:
            creds.append(skey)
    return creds


def main():
    print("【Tencent CloudStudio 签到】")
    proxy = _get_proxy()
    if proxy:
        print(f"代理出口: {mask_str(proxy, 6, 3)}")
    creds = _build_credentials()
    if not creds:
        raise RuntimeError(f"未配置任何凭据。{_cookie_issue_hint('')}")
    xsrfs = env_seq(PREFIX, "xsrf", required=False)

    total = len(creds)
    results: List[Tuple[bool, str]] = []

    for idx, c in enumerate(creds, 1):
        c = c.strip()
        if not c:
            continue
        xsrf = xsrfs[idx - 1].strip() if (idx - 1) < len(xsrfs) else ""
        try:
            ok, msg = _run_one(c, xsrf, idx, total)
            print(msg)
            results.append((ok, msg))
        except Exception as e:
            prefix_label = f"[{idx}/{total}] " if total > 1 else ""
            err_msg = f"{prefix_label}签到失败：{e}"
            print(err_msg)
            results.append((False, err_msg))

    ok_count = sum(1 for ok, _ in results if ok)
    if total > 1:
        print(f"\n========== 签到总结 ==========\n成功 {ok_count}/{total}")

    if ok_count > 0:
        _persist_last_credit_ts((os.getenv("TASK_ID") or "").strip())

    if ok_count != total:
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
