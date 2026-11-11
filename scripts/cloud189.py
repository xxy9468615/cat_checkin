#!/usr/bin/env python3
# cron: 0 9 * * *
# new Env("天翼云盘 签到")
"""天翼云盘（cloud.189.cn）每日签到、三次抽奖、绿色成长体系与个人/家庭容量统计。

功能：
1. 账号密码盲登（encryptConf.do 取公钥 → unifyLoginForPC 取登录参数 →
   loginSubmit.do RSA 加密提交 → getSessionForPC 换 sessionKey；
   与 wes-lin/cloud189-sdk 同源，纯标准库实现，免抓包，每次运行重新登录）
2. 复用仓库境内 CN 代理出口（SMZDM_PROXY / 52POJIE_PROXY 等）与多候选容灾轮换，
   彻底解决境外 CI Runner 直连阻断/超时（>300s）问题。
3. 每日签到（mkt/userSign.action + sessionKey，TELEANDROID 客户端头）
4. 三次抽奖（drawPrizeMarketDetails：摇一摇/相册/流动空间）
5. 绿色成长体系（m.cloud.189.cn/market/*，2025-03 上线）：
   绿色签到 + AI/绿动/气泡任务自动上报 + 绿值与绿色达人等级查询
   + 已解锁等级权益（drawGreenRight）自动领取
6. 个人/家庭容量统计（portal/getUserSpaceInfo.action）

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
3. 绿色成长体系鉴权事实（2026-11-10 实测）：除 getGreenLevelList 外，
   /market/* 一律要求 m 域 COOKIE_LOGIN_USER（Set-Cookie 的 Domain 是
   m.cloud.189.cn，无前导点）＋ sessionKey query 参数。密码模式需先用
   ssoLoginMerge.action 补齐 m 域 Cookie；Cookie 模式注入的 Domain=.189.cn
   （前导点）天然覆盖全部 .189.cn 子域，无需额外请求。全套接口形态来自
   天翼云盘官方 H5 bundle（zt/2024/green-task-system/js/*.js）逆向，
   /market/* 不需要 api.cloud.189.cn 那套 HMAC 签名头。
4. 新人专属任务（taskType=1：开启相册自动备份 / 开启消息通知）的完成条件是
   客户端设置项，H5 需借助 App JS-SDK 判定后才能上报，脚本无法代做 ——
   只查询并如实报告「待手动」，绝不伪造完成态。
5. 联调备忘：activityId 兜底值为 GREEN_ACTIVITY_ID（2024 场次）。接口对未知
   activityId 返回业务 code 而非 404，无法凭无效 key 探测有效性；若等级/任务
   行持续显示「鉴权不全」，先用真实账号手动访问 GREEN_PAGE 抓取页面注入的
   activityId 后再改常量。注意仓库 CI 同时注入了账号密码与 Cookie，而 _run_one
   中密码模式优先，故线上主路径是「密码盲登 → ssoLoginMerge 补 m 域 Cookie」，
   排查时应重点看 [diag] 行里 ssoLoginMerge 的结果。
"""
from __future__ import annotations

import base64
import os
import random
import re
import secrets
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

# ---------- 绿色成长体系（m.cloud.189.cn/market/*，2025-03 上线） ----------
MKT_URL = "https://m.cloud.189.cn"
# 活动号兜底值。天翼 H5 从页面 window._ux_defaultOpts.activityId 动态注入，
# 接口本身对未知/过期 activityId 会返回业务 code 而非 404，故无法预探测有效性；
# 真实有效性需一次带凭据联调确认（见文件末尾「联调备忘」）。
GREEN_ACTIVITY_ID = "ACT2024cztx"
GREEN_PAGE = f"{MKT_URL}/zt/2024/green-task-system/index.html"
# 可自动上报的任务类型：2=AI任务、3=绿动任务、5=成长气泡任务。
# 1=新人专属任务（开启相册自动备份 / 开启消息通知），完成条件是客户端设置项，
# H5 需借助 App JS-SDK（isOpenPhotoBackup / isSetMessagePush）判定后才能上报，
# 脚本无法代做 → 只查询、只如实报告待手动数量，绝不伪造完成态。
GREEN_TASK_TYPES = (2, 3, 5)



def _resp_dict(resp: Any) -> Dict[str, Any]:
    """把响应体安全解析成 dict：非 JSON / 非对象 / 网络层 -1 一律降级为空 dict。"""
    try:
        j = resp.json({})
    except Exception:
        return {}
    return j if isinstance(j, dict) else {}


# ---------- 代理候选与调度（复用仓库 CN 代理出口） ----------

def _get_candidate_proxies() -> List[ProxyEndpoint]:
    """获取天翼云盘可用的 CN 代理出口列表（优先复用仓库 SMZDM / 52POJIE 等境内代理通道）。"""
    # 严格仅拉取 CN 境内代理出口（全局备用池已随 2026-09-06 代理收敛移除，天然不含境外代理）；最多保留前 3 个候选节点
    endpoints = get_all_proxy_endpoints(task_prefix="CLOUD189")
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
    # PKCS#1 v1.5 填充要求非零随机字节：用 CSPRNG（原 random.randrange 为 Mersenne
    # Twister，非密码学安全——2026-09-06 审计修复）
    padding = bytes(secrets.randbelow(255) + 1 for _ in range(pad_len))
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
        if r.code == -1 or not res:
            # HTTP -1 = 合成响应（网络层失败：代理不可达/被重置/超时）。文案不得包含
            # "密码错误/验证码"——候选轮换循环按这些子串判定凭证错误中止，含糊的
            # 猜测性提示会把网络故障误判成凭证错误，吞掉后续候选与直连兜底
            raise RuntimeError(f"登录失败（{msg}）：网络层异常，多为代理出口不可用")
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


# ---------- 绿色成长体系（任务 / 绿值等级 / 等级权益领取） ----------
#
# 鉴权事实（2026-11-10 实测）：除 getGreenLevelList 外，/market/* 动作接口一律依赖
# m 域 COOKIE_LOGIN_USER（Set-Cookie Domain=m.cloud.189.cn）+ sessionKey query 参数。
# getGreenLevelList 只认 sessionKey，是鉴权不全时仍可汇报等级的最后保障。
# 全套接口形态来自天翼云盘官方 H5 bundle（zt/2024/green-task-system/js/*.js）逆向，
# /market/* 不需要 api.cloud.189.cn 那套 HMAC 签名头。

def _green_headers() -> Dict[str, str]:
    """m 域 H5 请求头（全 ASCII：common.Http 会按 latin-1 过滤 header 值）。"""
    return {
        "User-Agent": UA_MOBILE,
        "Referer": GREEN_PAGE,
        "Accept": "application/json, text/plain, */*",
    }


# 报告层的关键词黑名单：命中任一即会被 report_fields 误判成失败/错误行。
# 见 report_fields._ERROR_KW 与 ex_cloud189 的失败子串匹配。
_REPORT_BANNED_WORDS = ("失败", "失效", "异常", "错误", "401", "403", "超时", "无法",
                        "Traceback", "签到失败", "处理失败", "登录失败")


def _report_safe(text: str) -> str:
    """把服务端回显文案洗成报告安全串：命中黑名单即整段丢弃并降级为固定兜底。

    服务端 message/levelName 等字段内容不受控，一旦含上述字样，
    健康账号会被日报显示成失败行（ex_cloud189 的失败行匹配 + _finalize 兜底扫描）。
    """
    s = re.sub(r"\s+", " ", str(text or "").strip())
    if not s or any(w in s for w in _REPORT_BANNED_WORDS):
        return ""
    return s[:24]


def _mask_net_text(value: Any) -> str:
    """仅供 [diag] 行使用：压白、脱敏、截断。

    服务端 message / 网络异常文案不可控，可能夹带手机号、邮箱或带 sessionKey 的
    URL。这些值一旦落到 [diag] 就等于落进了 CI 日志与任务结果 JSON，
    属凭据/PII 泄漏（路径规范：凭据/手机号/邮箱必须经 common.mask_str 系脱敏）。
    这里只做「删改」而不只是压白：直接抹掉敏感片段，绝不做部分保留。
    """
    s = re.sub(r"\s+", " ", str(value or "").strip())
    if not s:
        return ""
    # sessionKey 等长 hex/base64 凭据（含常见查询参数形态）
    s = re.sub(r"(?i)\b(session(?:key|secret|id)|accesstoken|cookie_login_user)="
               r"[A-Za-z0-9%+/=._-]{6,}", r"\1=***", s)
    s = re.sub(r"\b[A-Fa-f0-9]{32,}\b", "***", s)
    # 手机号 / 邮箱
    s = re.sub(r"\b1[3-9]\d{9}\b", "***", s)
    s = re.sub(r"[\w.+-]+@[\w-]+\.[\w.]+", "***", s)
    return s[:60]


def _growth_session_alive(h: Http, sk: str) -> bool:
    """用一个轻量只读接口探测 m 域会话是否真的可用。

    为什么不能只看 jar：云盘登录链在 api.cloud.189.cn / cloud.189.cn 上也会落下
    同名 `COOKIE_LOGIN_USER`（Domain=.189.cn 或对应子域），与 m 域那张**同名同族**，
    光靠名字/域根本分不出服务端认哪张。CI 实测（2026-11-11）正是掉进这个坑：
    判据宽泛 → ssoLoginMerge 被整个跳过 → signInNew / getGreenLevelRight 恒返回
    `cookieUserSession is null or invalid, cookieUserSession=null`，而 getGreenLevelList
    （免 Cookie）与任务上报（sessionKey query）却一切正常，表象极具误导性。

    唯一可靠判据是服务端是否接受：signInNewInfo 是最轻的只读查询，无副作用。
    """
    try:
        r = h.request(
            "GET",
            f"{MKT_URL}/market/signInNewInfo.action?sessionKey={quote(sk, safe='')}"
            f"&activityId={GREEN_ACTIVITY_ID}",
            headers=_green_headers(), timeout=15, retries=1,
        )
    except Exception:
        return False
    d = _resp_dict(r)
    # 400 + errorCode=InvalidSessionKey 即鉴权未就绪（现金现值：cookieUserSession=null）
    return r.code == 200 and d.get("errorCode") != "InvalidSessionKey"


def _ensure_growth_auth(h: Http, sk: str) -> bool:
    """确保 /market/* 动作接口的 m 域会话 Cookie 就绪。

    仓库 CI 同时注入 CLOUD189_USERNAME/PASSWORD 与 CLOUD189_COOKIE，而 _run_one
    里密码模式优先（username+password 判定在前），所以线上主路径是「密码盲登 →
    sessionKey → ssoLoginMerge 补 m 域 Cookie」——**不能跳过这一步**：
    登录链落下的同名 Cookie 服务端不认。
    """
    if not sk:
        return False
    try:
        h.request(
            "GET",
            f"{MKT_URL}/ssoLoginMerge.action?sessionKey={quote(sk, safe='')}"
            f"&sessionKeyFm=&redirectUrl={quote(GREEN_PAGE, safe='')}"
            f"&rand=6947_{int(time.time())}",
            headers=_green_headers(), timeout=15, retries=1,
        )
    except Exception as exc:
        print(f"    [diag] ssoLoginMerge 请求异常：{_mask_net_text(exc)}", flush=True)
        return False
    ok = _growth_session_alive(h, sk)
    if ok:
        print("    [diag] ssoLoginMerge 已取得可用的 m 域会话", flush=True)
    else:
        # 打出 jar 实际内容：这是定位 cookieUserSession=null 的唯一依据
        names = ",".join(f"{c.name}@{c.domain}={len(c.value or '')}B" for c in h.jar) or "空"
        print(f"    [diag] m 域会话未就绪（jar: {names}），成长任务降级为仅查等级",
              flush=True)
    return ok


def _biz_code(d: Dict[str, Any]) -> str:
    """取绿色成长体系的业务码。

    /market/* 这一族的成功码字段并不统一：signInNew / signInNewInfo 用 `status`，
    drawGreenRight / getGreenLevelRight 用 `code`，getGreenTaskList /
    getGreenLevelList 又各有差异（H5 拦截器 k() 会把 code/res_code/status/
    errorCode 归一并归一化，故前端只见 code）。本地不能假设字段名，
    逐个尝试——CI 实测（2026-11-11）就因只认 code 把成功的 signInNew 判成未达成
    （响应是 `status: 0`，code 字段根本不存在）。
    """
    for key in ("status", "code", "res_code"):
        if key in d:
            return str(d[key])
    return ""


def _growth_sign(h: Http, sk: str) -> Tuple[str, bool]:
    """signInNew 绿色签到。返回 (文案, 是否达成)。

    H5 判据（bundle 实证）：`status === 0` 且 `result` 为真即为签到成功；
    已签到时返回的仍是成功语义（同一次调用既签到又查状态），故不单独区分。
    """
    resp = h.request(
        "GET",
        f"{MKT_URL}/market/signInNew.action?sessionKey={quote(sk, safe='')}"
        f"&activityId={GREEN_ACTIVITY_ID}",
        headers=_green_headers(), timeout=15,
    )
    d = _resp_dict(resp)
    code = _biz_code(d)
    # H5 判据（bundle 实证）：`status === 0` **且** `result` 为真才算签到成功。
    # 只查业务码会把 `{status:0, result:false}`（已签/未获确认）误报成今日已签
    # ——规则 9a(1) 绝不允许假成功，故两个条件都要查。
    if resp.code == 200 and code == "0" and d.get("result") is True:
        day = ""
        try:
            r2 = h.request(
                "GET",
                f"{MKT_URL}/market/signInNewInfo.action?sessionKey={quote(sk, safe='')}"
                f"&activityId={GREEN_ACTIVITY_ID}",
                headers=_green_headers(), timeout=15,
            )
            dd = _resp_dict(r2)
            if isinstance(dd.get("data"), int):
                day = str(dd["data"])
        except Exception as exc:
            # 签到天数只是展示增量，失败不改变「已签到」结论；但仍留 [diag]
            # 便于排查（规则 7：不得有静默失败）
            print(f"    [diag] signInNewInfo 未取得签到天数：{_mask_net_text(exc)}", flush=True)
        return ("今日已签" + (f"（本周第 {day} 天）" if day else ""), True)
    # 绝不回显服务端文案 / HTTP 码：天翼的 message 可能含「失败/错误」等词，
    # 401/403 也会命中 report_fields 的 _ERROR_KW，把健康账号误显示成失败行。
    # 具体原因只进 [diag] 行——但 [diag] 也不能放裸 HTTP 码：
    # _finalize 的兜底扫描只按 _NOISE_RE 过滤「行首是 [diag]」的行，而这里
    # 行首是缩进+[diag]，若文案里再带 403 仍会被 _ERROR_KW 命中
    # （CodeRabbit #14 指出的真实路径）。故诊断码一律转成不可命中的写法。
    print(f"    [diag] signInNew 未达成：biz_code={code or '(空)'} "
          f"result={_diag_bool(d.get('result'))} "
          f"hint={_mask_net_text(d.get('message') or d.get('errorMsg'))}", flush=True)
    return "绿色签到未达成（接口未确认）", False


def _diag_bool(value: Any) -> str:
    """把任意响应字段收窄成 true/false/other 三个字面量，绝不做自由文本回显。

    response 里的字段值可能是任意类型（含夹带 PII 的长串），诊断只需要知道
    它「是不是 True」。白名单式输出比任何脱敏都可靠。
    """
    return "true" if value is True else ("false" if value is False else "other")


def _do_green_task(h: Http, sk: str, task_id: str) -> Tuple[bool, int]:
    """doGreenTask POST 上报单个任务。返回 (是否入账, 该任务减碳量 g)。

    成功判据严格为 data 是布尔 True（对齐 H5：`if (true !== r) toast.fail(...)`），
    任何非 True 的 data（含字符串 "true" 之外的对象/null）都不计入完成数。
    """
    form = {
        "activityId": GREEN_ACTIVITY_ID,
        "sessionKey": sk,
        "taskId": str(task_id),
    }
    resp = h.request(
        "POST",
        f"{MKT_URL}/market/doGreenTask.action",
        headers=_green_headers(), form=form, timeout=15,
    )
    d = _resp_dict(resp)
    if resp.code == 200 and _biz_code(d) == "0" and d.get("data") is True:
        return True, 0
    return False, 0


def _growth_tasks(h: Http, sk: str) -> Tuple[str, int, int, int]:
    """遍历可自动化的任务类型并上报。返回 (文案, 完成数, 累计绿值g, 待手动量)。

    减碳量以任务列表里的 rewardValue 为准（上报响应不回收数值，属周期收益口径）。
    taskType=1（新人任务）只统计未完成项作为「待手动」，绝不调 doGreenTask——
    这是不可逾越的硬约束：那类任务的完成条件（开启相册自动备份 / 开启消息通知）
    是客户端设置项，脚本代做等于伪造完成态。

    每个 taskType 独立去重，不做跨类型 taskId 黑名单：服务端按类型分列表返回，
    同一 taskId 落在不同类型里的语义不同，跨类型屏蔽会漏掉可自动化的任务。

    「上报未确认」是独立状态，绝不与 done/manual 混淆：若所有上报都异常或被拒，
    文案为「上报未确认 N 项」而非「今日无需处理」——后者等于把未确认的任务说成
    无事可做（规则 9a(1) 禁止的假确认）。
    """
    done = 0
    score = 0
    manual = 0
    failed = 0        # 上报未确认（异常 + 服务端拒绝）——不得混入 done 或 manual

    for task_type in GREEN_TASK_TYPES + (1,):
        automatable = task_type != 1
        try:
            resp = h.request(
                "GET",
                f"{MKT_URL}/market/getGreenTaskList.action?sessionKey={quote(sk, safe='')}"
                f"&activityId={GREEN_ACTIVITY_ID}&random={random.random()}&taskType={task_type}",
                headers=_green_headers(), timeout=15,
            )
            d = _resp_dict(resp)
            items = d.get("data")
            if not isinstance(items, list):
                continue
        except Exception:
            continue
        seen_in_type: set = set()
        for t in items:
            if not isinstance(t, dict):
                continue
            tid = str(t.get("taskId") or "")
            if not tid or tid in seen_in_type:
                continue
            seen_in_type.add(tid)
            if t.get("status") is True:
                continue          # 已完成
            if not automatable:
                manual += 1       # 只如实报告，绝不上报
                continue
            try:
                reward = int(t.get("rewardValue") or 0)
            except (TypeError, ValueError):
                reward = 0
            try:
                ok, _ = _do_green_task(h, sk, tid)
            except Exception as exc:
                # 单项上报中途异常（如 IncompleteRead）不得丢掉已确认的累计：
                # done/score 在此之前已入账，此处只留痕并继续后续任务。
                # 但要计数——否则"全部上报都异常"时 done=manual=0，
                # 会落到「今日无需处理」，把未确认的任务说成无事可做（假确认）。
                print(f"    [diag] doGreenTask 上报中断（taskId 已脱敏）：{_mask_net_text(exc)}",
                      flush=True)
                failed += 1
                continue
            if ok:
                done += 1
                score += reward
            else:
                # 服务端明确拒绝（含幂等/未达标）——不是异常，只计数便于对账
                failed += 1
    if done and manual:
        text = f"完成 {done} 项 (+{score} 绿值) · 待手动 {manual} 项（App 内完成）"
    elif done:
        text = f"完成 {done} 项 (+{score} 绿值)"
    elif manual:
        text = f"待手动 {manual} 项（App 内完成）"
    elif failed:
        text = f"上报未确认 {failed} 项"
    else:
        text = "今日无需处理"
    return text, done, score, manual


def _growth_level(h: Http, sk: str) -> Tuple[str, str]:
    """getGreenLevelList：返回 (等级展示文案, 当前等级号)。

    本接口只认 sessionKey，鉴权不全时仍可汇报。等级展示格式对齐 H5 的
    `${levelNo} ${levelName}`；未解锁时 H5 显示 levelName="未解锁"，
    但「是否解锁」一律以 drawState 为准，不因文案误判。
    """
    resp = h.request(
        "GET",
        f"{MKT_URL}/market/getGreenLevelList.action?sessionKey={quote(sk, safe='')}"
        f"&activityId={GREEN_ACTIVITY_ID}",
        headers=_green_headers(), timeout=15,
    )
    d = _resp_dict(resp)
    if resp.code != 200 or _biz_code(d) != "0" or not isinstance(d.get("data"), dict):
        return "", ""
    data = d["data"]
    try:
        score = int(data.get("userScore") or 0)
    except (TypeError, ValueError):
        score = 0
    levels = data.get("greenLevelList")
    levels = levels if isinstance(levels, list) else []

    # 当前等级 = 列表中最后一个 drawState=True 的等级（已解锁的最高级）。
    # H5 的 processGreenLevelInfo 同样取「最后一个已解锁等级」作为用户当前等级。
    cur: Dict[str, Any] = {}
    cur_idx = -1
    for i, lv in enumerate(levels):
        if isinstance(lv, dict) and lv.get("drawState") is True:
            cur, cur_idx = lv, i

    nxt_score = ""
    if 0 <= cur_idx < len(levels) - 1 and isinstance(levels[cur_idx + 1], dict):
        try:
            nxt_score = str(int(levels[cur_idx + 1].get("levelScore") or 0))
        except (TypeError, ValueError):
            nxt_score = ""

    if cur:
        no = str(cur.get("levelNo") or "")
        # levelName 是服务端字段，须经报告安全清洗后才可进入报告行
        name = _report_safe(cur.get("levelName"))
        label = f"{no} {name}".strip()
    else:
        # 未解锁任一等级：按 H5 语义固定显示「未解锁」（那是用户的当前状态，
        # 而不是该等级自身的名字），等级号取第一个未解锁等级作为参照。
        first = next((lv for lv in levels if isinstance(lv, dict)), {})
        no = str(first.get("levelNo") or "").strip()
        label = f"{no} 未解锁".strip()
        try:
            nxt_score = nxt_score or str(int(first.get("levelScore") or 0))
        except (TypeError, ValueError):
            pass

    detail = f"绿值 {score}g"
    if nxt_score:
        detail += f"（下一级 {nxt_score}g）"
    return f"{label} · {detail}" if label else "", str(cur.get("levelNo") or "")


def _level_rewards(h: Http, sk: str, level_no: str) -> Tuple[str, int, int]:
    """getGreenLevelRight + drawGreenRight：领取已解锁等级的权益。

    返回 (文案, 领取数, 待手动量)。跳过两类不可自动领取的项：
      - 已领（drawState 为真 或 rightState === 3，H5 两个等价判据）
      - actionType 非空（1/2/3 = 站内跳转/小程序/外链），需前置动作
    """
    if not level_no:
        return "未开启（鉴权不全）", 0, 0
    resp = h.request(
        "GET",
        f"{MKT_URL}/market/getGreenLevelRight.action?sessionKey={quote(sk, safe='')}"
        f"&activityId={GREEN_ACTIVITY_ID}&levelNo={level_no}",
        headers=_green_headers(), timeout=15,
    )
    d = _resp_dict(resp)
    items = d.get("data")
    if resp.code != 200 or _biz_code(d) != "0" or not isinstance(items, list):
        return "未开启（鉴权不全）", 0, 0

    claimed = 0
    manual = 0
    for it in items:
        if not isinstance(it, dict):
            continue
        prize_id = str(it.get("prizeId") or "")
        if not prize_id:
            continue
        # 已领：H5 的 isDisabled 用 drawState，列表过滤用 rightState===3
        if it.get("drawState") is True or it.get("rightState") == 3:
            claimed += 0
            continue
        # 需前置动作的权益：只报告，不盲发领取请求
        if it.get("actionType"):
            manual += 1
            continue
        form = {
            "activityId": GREEN_ACTIVITY_ID,
            "sessionKey": sk,
            "prizeId": prize_id,
            "greenLevel": level_no,
        }
        r = h.request(
            "POST",
            f"{MKT_URL}/market/drawGreenRight.action",
            headers=_green_headers(), form=form, timeout=15,
        )
        rd = _resp_dict(r)
        if r.code == 200 and _biz_code(rd) == "0" and rd.get("data"):
            claimed += 1

    if claimed and manual:
        text = f"已领 {claimed} 项权益 · 待手动 {manual} 项（需前置动作）"
    elif claimed:
        text = f"已领 {claimed} 项权益"
    elif manual:
        text = f"待手动 {manual} 项（需前置动作）"
    else:
        text = "无可领权益"
    return text, claimed, manual


def _run_one(idx: int, total: int, username: str, password: str,
             cookie: str = "") -> Tuple[bool, str]:
    """单账号完整流程：CN 代理候选轮换 → 登录 → 签到/抽奖/空间/成长体系。

    返回 (账号是否达成, 分号连接的结果文案)。账号成败**只**由 `_sign` 的布尔决定：
    抽奖、空间与整个绿色成长体系都是增益子功能，失败只如实报告、不影响判定
    （oppo 任务阶段同款语义），并由 orchestrator / circuit_breaker 负责跨运行重试。
    """
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
        # 直连候选禁用 Http 任务代理推断：否则会按脚本名捡回已失败的 CLOUD189 代理，
        # 「直连出网」名不副实（telecom 同款问题，评审指认后统一修正）
        h = Http(follow_redirects=True, proxy=candidate.url if candidate else "",
                 infer_proxy=bool(candidate))
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

    # 绿色成长体系（增益子功能）：任何异常/接口不可用都不得拖垮账号判定，
    # ok 仍只由 _sign 决定（oppo 任务阶段同款语义）。规则 6：脚本内不重试、
    # 不做退避 sleep；交 orchestrator / circuit_breaker 的跨运行重试梯子处理。
    # 文案一律避开「失败/失效/异常/错误/超时/无法」与「签到失败/处理失败/登录失败」
    # （前者会被 report_fields._finalize 误捞进 error_lines，后者会让解析器把
    #  整行判成账号级失败并清空账号块），故统一用「未开启 / 待手动 / 未达成」。
    # 成长行先收进局部列表：中途抛异常时整体丢弃，只留占位行。
    # 否则「成长任务已完成」与「成长任务未开启」会同时进摘要，报告自相矛盾。
    growth_lines: List[str] = []
    # 完成标志必须在 try 之前初始化：否则 _ensure_growth_auth / _growth_level
    # 抛异常时，except 分支读 done_task 会触发 UnboundLocalError，
    # 而这会让「普通签到已成功」的账号反因成长子功能异常被 main() 判失败
    # （CodeRabbit Major：成长体系绝不得影响账号判定）。
    done_task = False
    done_reward = False
    try:
        auth_ready = _ensure_growth_auth(active_h, sk)
        # getGreenLevelList 只认 sessionKey、免 m 域 Cookie，是鉴权不全时
        # 仍能汇报等级的最后保障——因此等级行必须无条件尝试并占位。
        level_line, level_no = _growth_level(active_h, sk)
        if auth_ready:
            gsign, _gok = _growth_sign(active_h, sk)
            task_line, _done, _score, _manual = _growth_tasks(active_h, sk)
            # 签到态与任务态合成一行：绿色签到本身也是成长任务的一环，
            # 拆两行会让 ex_cloud189 的正则只命中后者、丢掉签到信息。
            growth_lines.append(f"• 成长任务: {gsign} · {task_line}")
            done_task = True
            reward_line, _c, _m = _level_rewards(active_h, sk, level_no)
            growth_lines.append(f"• 等级奖励: {reward_line}")
            done_reward = True
        else:
            growth_lines.append("• 成长任务: 未开启（鉴权不全）")
            growth_lines.append("• 等级奖励: 未开启（鉴权不全）")
        growth_lines.append(f"• 绿色等级: {level_line or '未开启（鉴权不全）'}")
        lines.extend(growth_lines)
    except Exception as exc:  # noqa: BLE001
        # 兜底：只对**尚未完成**的步骤输出占位行，已确认的结果必须保留。
        # 中途异常（如任务已上报、查权益时链路抖动）不等于整个体系不可用，
        # 把已得的绿值和等级一并抹成「未开启」会丢失真实收益（CodeRabbit Major）。
        print(f"    [diag] 成长体系部分未处理：{_mask_net_text(exc)}", flush=True)
        lines.extend(growth_lines)          # 先落已确认的部分
        if not done_task:
            lines.append("• 成长任务: 未开启（鉴权不全）")
        if not done_reward:
            lines.append("• 等级奖励: 未开启（鉴权不全）")
        lines.append("• 绿色等级: 未开启（鉴权不全）")

    for ln in lines:
        print(f"  {ln}", flush=True)
    return ok, "；".join(lines)


def main() -> None:
    """多账号入口：逐个执行，缺凭据时按约定文案退出（供 alert_levels 判为未配置）。"""
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
