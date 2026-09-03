#!/usr/bin/env python3
# cron: 0 9 * * *
# new Env("天翼云盘 签到")
"""天翼云盘（cloud.189.cn）每日签到、三次抽奖与个人/家庭容量统计。

功能：
1. 账号密码盲登（encryptConf.do 取公钥 → unifyLoginForPC 取登录参数 →
   loginSubmit.do RSA 加密提交 → getSessionForPC 换 sessionKey；
   与 wes-lin/cloud189-sdk 同源，纯标准库实现，免抓包，每次运行重新登录）
2. 复用仓库境内 CN 代理出口（SMZDM_PROXY / 52POJIE_PROXY 等）与多候选容灾轮换，
   彻底解决境外 CI Runner 直连阻断/超时（>300s）问题。
3. 每日签到（mkt/userSign.action + sessionKey，TELEANDROID 客户端头）
4. 三次抽奖（drawPrizeMarketDetails：摇一摇/相册/流动空间）
5. 个人/家庭容量统计（portal/getUserSpaceInfo.action）

环境变量（按账号二选一，密码模式最优，免抓包、每次运行自动重登）：
- CLOUD189_USERNAME_1 / CLOUD189_PASSWORD_1 ...（手机号+密码盲登，推荐）
- CLOUD189_COOKIE_1 ...（网页全套 Cookie，COOKIE_LOGIN_USER 为核心票）
- CLOUD189_PROXY / CLOUD189_BACKUP_PROXIES（CN 代理出口，默认复用仓库现有 CN 出口）

注：
1. 网页 Cookie（COOKIE_LOGIN_USER）为服务端会话票，约 1 天即失效，
   无法保活/续期，社区各签到项目（51.ruyo.net / cqpcy / BlueSkyXN 等）
   均改用「手机号+密码」每次运行重新登录来绕过 Cookie 过期；默认请走密码模式。
2. 网页 localStorage 的 accessToken 与客户端会话体系不通用
   （getSessionForPC 对各 appId 均报 UserInvalidOpenToken），勿再尝试。
"""
from __future__ import annotations

import base64
import os
import random
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from common import (
    Http,
    ProxyEndpoint,
    env_seq,
    format_dead_proxy_alert,
    get_all_proxy_endpoints,
    main_guard,
    mask_str,
    parse_proxies_text,
)

WEB_URL = "https://cloud.189.cn"
API_URL = "https://api.cloud.189.cn"
AUTH_URL = "https://open.e.189.cn"
APP_ID = "8025431004"
ACCOUNT_TYPE = "02"
RETURN_URL = "https://m.cloud.189.cn/zhuanti/2020/loginErrorPc/index.html"
UA_WEB = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"
)
UA_MOBILE = (
    "Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 "
    "Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 "
    "clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6"
)
REFERER_SIGN = "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1"
LOTTERY_TASKS = ["TASK_SIGNIN", "TASK_SIGNIN_PHOTOS", "TASK_2022_FLDFS_KJ"]


def _resp_dict(resp: Any) -> Dict[str, Any]:
    try:
        j = resp.json({})
    except Exception:
        return {}
    return j if isinstance(j, dict) else {}


# ---------- 代理候选与调度（复用仓库 CN 代理出口） ----------

def _get_candidate_proxies() -> List[ProxyEndpoint]:
    """获取天翼云盘可用的 CN 代理出口列表（优先复用仓库 SMZDM / 52POJIE 等境内代理通道）。"""
    # 严格仅拉取 CN 境内代理出口，排除 AGENTROUTER_BACKUP_PROXIES 等境外代理；最多保留前 3 个候选节点
    endpoints = get_all_proxy_endpoints(task_prefix="CLOUD189", include_self_hosted=True, include_backups=False)
    if endpoints:
        return endpoints[:3]
    raw = (
        os.getenv("CLOUD189_PROXY")
        or os.getenv("52POJIE_PROXY")
        or os.getenv("WUAI_PROXY")
        or os.getenv("SMZDM_PROXY")
        or os.getenv("SMZDM_BACKUP_PROXIES")
        or ""
    )
    return parse_proxies_text(raw, default_name_prefix="CN代理")[:3]


# ---------- 登录（RSA 盲登，与 wes-lin/cloud189-sdk 同源，纯标准库） ----------

def _asn1_tlv(data: bytes, off: int) -> Tuple[int, bytes, int]:
    """极简 DER TLV 读取：返回 (tag, value, next_offset)。"""
    tag = data[off]
    off += 1
    ln = data[off]
    off += 1
    if ln & 0x80:
        nbytes = ln & 0x7F
        ln = int.from_bytes(data[off:off + nbytes], "big")
        off += nbytes
    return tag, data[off:off + ln], off + ln


def _parse_x509_pubkey(b64_der: str) -> Tuple[int, int]:
    """从 SubjectPublicKeyInfo base64 中解析 (n, e)。"""
    der = base64.b64decode(b64_der)
    _, body, _ = _asn1_tlv(der, 0)            # 外层 SEQUENCE：body 为内部内容，重新从 0 起算
    _, _, off = _asn1_tlv(body, 0)            # SEQUENCE（算法标识）
    _, bits, off = _asn1_tlv(body, off)       # BIT STRING（公钥位串）
    if bits and bits[0] == 0:
        bits = bits[1:]
    _, seq, _ = _asn1_tlv(bits, 0)            # SEQUENCE {n, e}
    _, n_raw, off2 = _asn1_tlv(seq, 0)
    _, e_raw, _ = _asn1_tlv(seq, off2)
    return int.from_bytes(n_raw, "big"), int.from_bytes(e_raw, "big")


def _rsa_encrypt_hex(pub_key: str, text: str) -> str:
    """PKCS#1 v1.5 公钥加密，返回 hex（与 SDK rsaEncrypt(..., 'hex') 一致）。"""
    n, e = _parse_x509_pubkey(pub_key)
    k = (n.bit_length() + 7) // 8
    msg = text.encode()
    pad_len = k - 3 - len(msg)
    if pad_len < 8:
        raise RuntimeError("RSA 明文过长")
    padding = bytes(random.randrange(1, 256) for _ in range(pad_len))
    block = b"\x00\x02" + padding + b"\x00" + msg
    cipher = pow(int.from_bytes(block, "big"), e, n)
    return cipher.to_bytes(k, "big").hex()


def _inject_cookie(h: Http, cookie: str) -> None:
    """把浏览器 Cookie 头注入 jar（域 .189.cn，兼容本地会话校验）。"""
    from http.cookiejar import Cookie

    for pair in cookie.split(";"):
        kv = pair.strip()
        if not kv or "=" not in kv:
            continue
        name, val = kv.split("=", 1)
        h.jar.set_cookie(Cookie(
            version=0, name=name.strip(), value=val.strip(),
            port=None, port_specified=False, domain=".189.cn", domain_specified=True,
            domain_initial_dot=True, path="/", path_specified=True, secure=False,
            expires=int(time.time()) + 86400 * 90, discard=False, comment=None,
            comment_url=None, rest={}, rfc2109=False,
        ))


def _login(h: Http, username: str, password: str) -> str:
    """密码盲登，返回 sessionKey（后续接口的鉴权凭证）。"""
    print("    [diag] 正在获取加密配置 (encryptConf.do)...", flush=True)
    # 1. 加密配置（公钥 + 前缀）
    r = h.request(
        "POST",
        f"{AUTH_URL}/api/logbox/config/encryptConf.do",
        headers={"User-Agent": UA_WEB, "Referer": AUTH_URL},
        form={"appId": APP_ID},
        timeout=10,
        retries=1,
    )
    if r.code != 200:
        raise RuntimeError(f"获取公钥失败（HTTP {r.code}）：{r.text[:80]}")
    enc = _resp_dict(r).get("data") or {}
    pub_key = enc.get("pubKey", "")
    pre = enc.get("pre") or "{RSA}"
    if not pub_key:
        raise RuntimeError(f"公钥内容为空（HTTP {r.code}）：{r.text[:80]}")

    print("    [diag] 正在获取统一登录表单参数 (unifyLoginForPC.action)...", flush=True)
    # 2. 登录表单参数（该页为服务端渲染，302 跳转至 open.e.189.cn）
    ts = int(time.time() * 1000)
    ret_encoded = quote(RETURN_URL, safe="")
    r = h.request(
        "GET",
        f"{WEB_URL}/api/portal/unifyLoginForPC.action?appId={APP_ID}&clientType=10020&returnURL={ret_encoded}&timeStamp={ts}",
        headers={
            "User-Agent": UA_WEB,
            "Referer": f"{WEB_URL}/web/login.html",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        timeout=10,
        retries=1,
    )
    if r.code != 200:
        raise RuntimeError(f"获取登录页失败（HTTP {r.code}）：{r.text[:80]}")
    page = r.text or ""

    def _find(patterns: List[str], name: str) -> str:
        for p in patterns:
            mm = re.search(p, page)
            if mm:
                val = mm.group(1).strip()
                if val:
                    return val
        title_m = re.search(r"<title>(.*?)</title>", page, re.IGNORECASE)
        title = title_m.group(1).strip() if title_m else "无标题"
        raise RuntimeError(f"登录页缺少字段 [{name}]（页面标题: {title}，长度: {len(page)}，内容片段: {page[:120]!r}）")

    captcha_token = _find([
        r"captchaToken['\"]\s*value=['\"]([^'\"]+)['\"]",
        r"value=['\"]([^'\"]+)['\"]\s*name=['\"]captchaToken['\"]",
        r"id=['\"]captchaToken['\"]\s*value=['\"]([^'\"]+)['\"]",
    ], "captchaToken")
    lt = _find([
        r"\blt\s*=\s*['\"]([^'\"]+)['\"]",
        r"['\"]lt['\"]\s*:\s*['\"]([^'\"]+)['\"]",
    ], "lt")
    param_id = _find([
        r"\bparamId\s*=\s*['\"]([^'\"]+)['\"]",
        r"['\"]paramId['\"]\s*:\s*['\"]([^'\"]+)['\"]",
    ], "paramId")
    req_id = _find([
        r"\breqId\s*=\s*['\"]([^'\"]+)['\"]",
        r"['\"]reqId['\"]\s*:\s*['\"]([^'\"]+)['\"]",
    ], "reqId")

    print("    [diag] 正在提交 RSA 加密认证 (loginSubmit.do)...", flush=True)
    # 3. RSA 提交（字段与 platformlogin.js v20260109 对齐：密码字段名为 epd）
    form = {
        "apToken": "",
        "appKey": APP_ID,
        "pageKey": "normal",
        "accountType": ACCOUNT_TYPE,
        "userName": f"{pre}{_rsa_encrypt_hex(pub_key, username)}",
        "epd": f"{pre}{_rsa_encrypt_hex(pub_key, password)}",
        "validateCode": "",          # 图形验证码（未触发则留空）
        "smsValidateCode": "",       # 短信动态码（未触发则留空）
        "captchaToken": captcha_token,
        "returnUrl": RETURN_URL,
        "mailSuffix": "",            # 手机号登录无后缀
        "dynamicCheck": "FALSE",
        "clientType": "10020",
        "cb_SaveName": "3",
        "isOauth2": "false",
        "state": "",
        "paramId": param_id,
    }
    r = h.request(
        "POST",
        f"{AUTH_URL}/api/logbox/oauth2/loginSubmit.do",
        headers={"User-Agent": UA_WEB, "Referer": AUTH_URL, "lt": lt, "REQID": req_id},
        form=form,
        timeout=10,
        retries=1,
    )
    res = _resp_dict(r)
    if str(res.get("result")) != "0":
        msg = str(res.get("msg") or r.code)
        raise RuntimeError(f"登录失败（{msg}）——可能触发验证码或密码错误")

    # 4. 换取 sessionKey 并种下 COOKIE_LOGIN_USER 会话票
    # 注意：必须请求 api.cloud.189.cn 的 GET 接口（Client Open API 凭据消费端点）；
    # 若请求 cloud.189.cn/api/portal/getSessionForPC.action（Web Portal 端点），
    # 会因缺少先验 Web Cookie 而报 HTTP 400 cookieUserSession is null or invalid
    print("    [diag] 正在换取移动端 sessionKey (api.cloud.189.cn/getSessionForPC.action)...", flush=True)
    to_url = res.get("toUrl") or RETURN_URL
    suffix = "clientType=TELEMAC&version=1.0.0&channelId=web_cloud.189.cn"
    r = h.request(
        "GET",
        f"{API_URL}/getSessionForPC.action?{suffix}&redirectURL={quote(to_url, safe='')}",
        headers={"User-Agent": UA_WEB, "Accept": "application/json;charset=UTF-8"},
        timeout=10,
        retries=1,
    )
    sess = _resp_dict(r)
    sk = str(sess.get("sessionKey", ""))
    if sk:
        print("    [diag] 换取 sessionKey 成功", flush=True)
    else:
        err_hint = str(sess.get("res_message") or sess.get("errorMsg") or sess.get("message") or "")
        print(f"    [diag] getSessionForPC 未返回 sessionKey ({err_hint[:40]})", flush=True)
        raise RuntimeError(f"会话交换失败（{err_hint or r.text[:80]}）")
    return sk


# ---------- 签到 / 抽奖 / 容量 ----------

def _sign(h: Http, session_key: str = "") -> Tuple[str, bool]:
    """mkt/userSign.action：GET 即签到动作。返回 (文案, 是否达成)。"""
    rand = int(time.time() * 1000)
    sk = f"&sessionKey={quote(session_key, safe='')}" if session_key else ""
    resp = h.request(
        "GET",
        f"{WEB_URL}/mkt/userSign.action?rand={rand}&clientType=TELEANDROID"
        f"&version=6.2&model=PCRT00{sk}",
        headers={"User-Agent": UA_MOBILE, "Referer": REFERER_SIGN},
        timeout=15,
    )
    d = _resp_dict(resp)
    if resp.code != 200 or "netdiskBonus" not in d:
        raw = str(d.get('errorMsg') or d.get('msg') or '')
        hint = ""
        if not session_key and "cookieUserSession" in raw:
            hint = ("；疑似 Cookie 过期（天翼 Cookie 约 1 天失效，无法续期），"
                    "请改用密码模式 CLOUD189_USERNAME_1 / CLOUD189_PASSWORD_1")
        return f"签到失败（HTTP {resp.code} {raw[:40]}）{hint}", False
    bonus = d.get("netdiskBonus", 0)
    if d.get("isSign") in (True, "true", "True"):
        return f"今日已签到（可得 {bonus}M 空间）", True
    return f"【成功】+{bonus}M 空间", True


def _lotteries(h: Http, session_key: str = "") -> str:
    """三次抽奖：description=奖品，errorCode=次数不足/未中奖。"""
    prizes: List[str] = []
    sk = f"&sessionKey={quote(session_key, safe='')}" if session_key else ""
    for task in LOTTERY_TASKS:
        resp = h.request(
            "GET",
            f"https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action"
            f"?taskId={task}&activityId=ACT_SIGNIN{sk}",
            headers={"User-Agent": UA_MOBILE, "Referer": REFERER_SIGN},
            timeout=15,
        )
        d = _resp_dict(resp)
        desc = d.get("description")
        if desc:
            prizes.append(str(desc))
    return " · ".join(prizes) if prizes else "无可用次数"


def _space(h: Http) -> str:
    """个人/家庭容量（portal/getUserSizeInfo.action，XML 应答）。"""
    import xml.etree.ElementTree as ET

    def _gb(v: Any) -> str:
        try:
            return f"{int(v) / 1024 / 1024 / 1024:.2f}G"
        except (TypeError, ValueError):
            return "?"

    resp = h.request(
        "GET",
        f"{WEB_URL}/api/portal/getUserSizeInfo.action",
        headers={"User-Agent": UA_WEB, "Referer": f"{WEB_URL}/"},
        timeout=15,
    )
    if resp.code != 200:
        return "获取失败"
    try:
        root = ET.fromstring(resp.text)
    except Exception:
        return "获取失败"
    parts: List[str] = []
    for label, tag in (("个人", "cloudCapacityInfo"), ("家庭", "familyCapacityInfo")):
        node = root.find(tag)
        if node is None:
            continue
        used = node.findtext("usedSize") or "0"
        total = node.findtext("totalSize") or "0"
        if int(total or 0) > 0:
            parts.append(f"{label} {_gb(used)}/{_gb(total)}")
    return " · ".join(parts) if parts else "获取失败"


def _run_one(idx: int, total: int, username: str, password: str,
             cookie: str = "") -> Tuple[bool, str]:
    if idx > 1:
        time.sleep(random.uniform(2, 5))

    who = mask_str(username) if username else f"Cookie:{mask_str(cookie[:24])}"
    print(f"[{idx}/{total}] 👤 用户: 【{who}】", flush=True)

    candidates = _get_candidate_proxies()
    proxy_queue: List[Optional[ProxyEndpoint]] = list(candidates)
    # 若配置了代理，在列表末尾追加 None (直连) 作为兜底选项
    if None not in proxy_queue:
        proxy_queue.append(None)

    last_exc: Optional[Exception] = None
    sk = ""
    active_h: Optional[Http] = None

    for candidate in proxy_queue:
        p_name = candidate.display_name if candidate else "直连出网"
        print(f"  🌐 正在通过 CN 出口 [{p_name}] 建立连接...", flush=True)
        h = Http(follow_redirects=True, proxy=candidate.url if candidate else "")
        try:
            if username and password:
                sk = _login(h, username, password)
            elif cookie:
                _inject_cookie(h, cookie)
            active_h = h
            print(f"  ✅ CN 出口 [{p_name}] 会话建立就绪", flush=True)
            break
        except Exception as exc:
            last_exc = exc
            err_msg = str(exc)
            if candidate:
                print(f"  {format_dead_proxy_alert(candidate, err_msg)}", flush=True)
            else:
                print(f"  ⚠️ 直连连接失败: {err_msg}", flush=True)
            # 业务层明确的凭证错误或验证码拦截，不必继续重试其他代理
            if "账户名或密码错误" in err_msg or "密码错误" in err_msg or "验证码" in err_msg:
                raise exc

    if active_h is None:
        if last_exc:
            raise last_exc
        raise RuntimeError("网络连接失败，所有候选 CN 代理及直连均不可用")

    lines: List[str] = []
    ok = True
    sign_line, sign_ok = _sign(active_h, sk)
    lines.append(f"• 签到: {sign_line}")
    ok = ok and sign_ok
    lines.append(f"• 抽奖: {_lotteries(active_h, sk)}")
    lines.append(f"• 空间: {_space(active_h)}")
    for ln in lines:
        print(f"  {ln}", flush=True)
    return ok, "；".join(lines)


def main() -> None:
    usernames = env_seq("CLOUD189_", "username", required=False, default=[])
    passwords = env_seq("CLOUD189_", "password", required=False, default=[])
    cookies = env_seq("CLOUD189_", "cookie", required=False, default=[])
    total = max(min(len(usernames), len(passwords)), len(cookies))
    if total == 0:
        print("签到失败：缺少环境变量 CLOUD189_USERNAME/PASSWORD 或 CLOUD189_COOKIE")
        sys.exit(1)
    print(f"【天翼云盘 签到】共 {total} 个账号")
    failed = 0
    for idx in range(1, total + 1):
        username = usernames[idx - 1].strip() if idx <= len(usernames) else ""
        password = passwords[idx - 1].strip() if idx <= len(passwords) else ""
        cookie = cookies[idx - 1].strip() if idx <= len(cookies) else ""
        if not (username and password) and not cookie:
            continue
        try:
            ok, _ = _run_one(idx, total, username, password, cookie)
        except Exception as exc:  # noqa: BLE001
            ok = False
            print(f"❌ 账号 {idx} 处理失败: {exc}")
        if not ok:
            failed += 1
    print(f"✅ 全部 {total} 个账号处理完成 (成功 {total - failed}/{total})")
    if failed:
        print(f"❌ {failed} 个账号未达成签到")
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
