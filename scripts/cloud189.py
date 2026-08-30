#!/usr/bin/env python3
# cron: 0 9 * * *
# new Env("天翼云盘 签到")
"""天翼云盘（cloud.189.cn）每日签到、三次抽奖与个人/家庭容量统计。

功能：
1. 账号密码盲登（encryptConf.do 取公钥 → unifyLoginForPC 取登录参数 →
   loginSubmit.do RSA 加密提交 → getSessionForPC 换 sessionKey；
   与 wes-lin/cloud189-sdk 同源，纯标准库实现，免抓包，每次运行重新登录）
2. 每日签到（mkt/userSign.action + sessionKey，TELEANDROID 客户端头）
3. 三次抽奖（drawPrizeMarketDetails：摇一摇/相册/流动空间）
4. 个人/家庭容量统计（portal/getUserSpaceInfo.action）

环境变量（按账号二选一，密码模式最优）：
- CLOUD189_USERNAME_1 / CLOUD189_PASSWORD_1 ...（手机号+密码盲登，全自动）
- CLOUD189_COOKIE_1 ...（网页全套 Cookie，COOKIE_LOGIN_USER 为核心票）

注：网页 localStorage 的 accessToken 与客户端会话体系不通用
（getSessionForPC 对各 appId 均报 UserInvalidOpenToken），勿再尝试。
"""
from __future__ import annotations

import base64
import random
import re
import sys
import time
from typing import Any, Dict, List, Tuple
from urllib.parse import quote

from common import Http, env_seq, main_guard, mask_str

WEB_URL = "https://cloud.189.cn"
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
    _, body, off = _asn1_tlv(der, 0)          # SEQUENCE
    _, _, off = _asn1_tlv(body, off)          # SEQUENCE（算法标识）
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
    """密码盲登，返回 sessionKey（后续接口的鉴权凭证）。"""    # 1. 加密配置（公钥 + 前缀）
    r = h.request("POST", f"{AUTH_URL}/api/logbox/config/encryptConf.do",
                  headers={"User-Agent": UA_WEB, "Referer": AUTH_URL})
    enc = _resp_dict(r).get("data") or {}
    pub_key = enc.get("pubKey", "")
    pre = enc.get("pre") or "{RSA}"
    # 2. 登录表单参数（该页仍为服务端渲染）
    ts = int(time.time() * 1000)
    r = h.request(
        "GET",
        f"{WEB_URL}/api/portal/unifyLoginForPC.action?appId={APP_ID}"
        f"&clientType=10020&returnURL={quote(RETURN_URL, safe='')}&timeStamp={ts}",
        headers={"User-Agent": UA_WEB, "Referer": AUTH_URL},
    )
    page = r.text or ""

    def _find(pattern: str) -> str:
        mm = re.search(pattern, page)
        if not mm:
            raise RuntimeError("登录失败：登录页解析缺字段")
        return mm.group(1)

    captcha_token = _find(r"captchaToken' value='(.+?)'")
    lt = _find(r'lt = "(.+?)"')
    param_id = _find(r'paramId = "(.+?)"')
    req_id = _find(r'reqId = "(.+?)"')
    # 3. RSA 提交
    form = {
        "appKey": APP_ID,
        "accountType": ACCOUNT_TYPE,
        "validateCode": "",
        "captchaToken": captcha_token,
        "dynamicCheck": "FALSE",
        "clientType": "1",
        "cb_SaveName": "3",
        "isOauth2": "false",
        "returnUrl": RETURN_URL,
        "paramId": param_id,
        "userName": f"{pre}{_rsa_encrypt_hex(pub_key, username)}",
        "password": f"{pre}{_rsa_encrypt_hex(pub_key, password)}",
    }
    r = h.request(
        "POST", f"{AUTH_URL}/api/logbox/oauth2/loginSubmit.do",
        headers={"User-Agent": UA_WEB, "Referer": AUTH_URL, "lt": lt, "REQID": req_id},
        form=form,
    )
    res = _resp_dict(r)
    if str(res.get("result")) != "0":
        raise RuntimeError(f"登录失败（{res.get('msg', r.code)}）——可能触发验证码")
    # 4. 换 sessionKey
    suffix = (f"appId={APP_ID}&clientType=TELEPC&version=6.2"
              f"&channelId=web_cloud.189.cn&rand={int(time.time() * 1000)}")
    r = h.request(
        "POST",
        f"{WEB_URL}/api/portal/getSessionForPC.action?{suffix}"
        f"&redirectURL={quote(res.get('toUrl', ''), safe='')}",
        headers={"User-Agent": UA_WEB, "Referer": AUTH_URL},
    )
    sess = _resp_dict(r)
    sk = sess.get("sessionKey", "")
    if not sk:
        raise RuntimeError(f"会话交换失败（{str(sess)[:80]}）")
    return str(sk)


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
    )
    d = _resp_dict(resp)
    if resp.code != 200 or "netdiskBonus" not in d:
        return f"签到失败（HTTP {resp.code} {str(d.get('errorMsg') or d.get('msg') or '')[:40]}）", False
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
        "GET", f"{WEB_URL}/api/portal/getUserSizeInfo.action",
        headers={"User-Agent": UA_WEB, "Referer": f"{WEB_URL}/"},
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
    h = Http(follow_redirects=True)
    sk = ""
    if username and password:
        time.sleep(random.uniform(2, 8))
        sk = _login(h, username, password)
        who = mask_str(username)
    elif cookie:
        _inject_cookie(h, cookie)
        who = f"Cookie:{mask_str(cookie[:24])}"
    else:
        raise RuntimeError("缺少凭据")
    print(f"[{idx}/{total}] 👤 用户: 【{who}】")

    lines: List[str] = []
    ok = True
    sign_line, sign_ok = _sign(h, sk)
    lines.append(f"• 签到: {sign_line}")
    ok = ok and sign_ok
    lines.append(f"• 抽奖: {_lotteries(h, sk)}")
    lines.append(f"• 空间: {_space(h)}")
    for ln in lines:
        print(ln)
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
