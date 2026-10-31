#!/usr/bin/env python3
# cron: 0 9 * * *
# new Env("中国电信 签到")
"""中国电信（营业厅 / 天翼生活 / 10000）App 抓包纯授权签到、免费抽奖与资产统计。

模式说明：
- 服务密码自动登录（推荐）：TELECOM_PASSWORD_* 配置后，sign 过期时经
  appgologin 网关（userLoginNormal，loginType=4）RSA+3DES 换取免密 Ticket
  并缓存 Redis，之后每日由 ticket 自动续换 sign，长期免维护。
  密码类硬错误（错输/锁定）触发当日立即熔断，防止重试梯子连续错输锁死密码。
- 纯 App 抓包整串鉴权模式（兜底）：无需账密，抓包整串 sign 有效期约 1 天。
- 会话凭据经 Upstash Redis 与本地 KV 缓存跨 run 持久化，平滑保活。

环境变量：
- TELECOM_HEADER_1...: 抓包整串（支持含 sign / phone / Authorization 的 Header 串、query 串或 JSON）
- TELECOM_PASSWORD_1...: 服务密码（手机号缺省回退 CLOUD189_USERNAME_*，或显式 TELECOM_PHONE_*）
"""
from __future__ import annotations

import base64
import json
import os
import random
import re
import string
import sys
import time
import urllib.parse
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 本地调试自动加载 .env
try:
    import dotenv
    dotenv.load_dotenv(override=False)
except ImportError:
    pass

from common import (
    BJT,
    Http,
    ProxyEndpoint,
    env_seq,
    format_dead_proxy_alert,
    get_all_proxy_endpoints,
    is_already_signed,
    load_kv_state,
    main_guard,
    mask_str,
    parse_proxies_text,
    save_kv_state,
)
from circuit_breaker import trip_circuit_breaker

# 加密库：金豆中心接口依赖 RSA-1024 与 AES-ECB / 3DES
try:
    from Crypto.Cipher import AES, DES3, PKCS1_v1_5
    from Crypto.PublicKey import RSA
    from Crypto.Util.Padding import pad, unpad

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

PREFIX = "TELECOM_"

# 自动兑换话费目标配置（默认目标：10元话费直充券，8000金豆达标）
# 环境变量可能被误配为非数字（Secret 填写错误）——解析失败时回退默认门槛，避免整个任务导入即崩
TELECOM_EXCHANGE_GOAL = (os.getenv("TELECOM_EXCHANGE_GOAL") or "").strip() or "10元话费直充券"
try:
    TELECOM_EXCHANGE_BEANS = int((os.getenv("TELECOM_EXCHANGE_BEANS") or "").strip() or "8000")
except ValueError:
    TELECOM_EXCHANGE_BEANS = 8000
if TELECOM_EXCHANGE_BEANS <= 0:
    TELECOM_EXCHANGE_BEANS = 8000

# ---------- 金豆商城（wapact.189.cn:9001）话费抢兑 ----------
# 2026-10-31 排障结论（本地实测 + 开源抢兑脚本交叉验证）：
# 旧 try_exchange_phone_bill 直调 wappark paradise/receiverRights 属错误链路——
# 该接口 payload 需权益 id + accId（缺 id 时服务端 NPE → HTTP 500，脚本却因
# 响应无 msg 字段把失败美化成「已提交」），且目标商品「10元话费直充券」实际
# 挂在金豆商城秒杀场，与乐园权益目录分属两套系统。真实链路：
#   ticket → /unified/user/login（AES-ECB, key=telecom_wap_2018）→ Bearer token
#   → /gateway/golden/api/queryInfo（商城侧金豆余额 amountTotal）
#   → /gateway/golden/goldGoods/getGoodsList（场次商品列表；场次外返回
#     code=999999「系统错误」，已实测与瑞数 Cookie/UA/HTTP 版本无关）
#   → /gateway/standExchange/detailNew/exchange {"activityId": <商品id>}
# biz.resultCode：0=成功 410=未开始 412=次数上限 413=已售罄；HTTP 429=限频。
# 抢兑场次（BJT）：上午场 10:00 开抢（20元/10元话费券），下午场 14:00（小额券），
# 先到先得。00:50 主链路时点必然错过场次，抢兑由专项任务 telecom-exchange
# （TELECOM_MODE=exchange）在场次窗口内等待并发突发提交。
JINDOU_AES_KEY = "telecom_wap_2018"
JINDOU_LOGIN_URL = "https://wapact.189.cn:9001/unified/user/login"
JINDOU_QUERY_URL = "https://wapact.189.cn:9001/gateway/golden/api/queryInfo"
JINDOU_GOODS_URL = (
    "https://wapact.189.cn:9001/gateway/golden/goldGoods/getGoodsList"
    "?floorType=0&userType=1&page=1&order=3&tabOrder="
)
JINDOU_EXCHANGE_URL = "https://wapact.189.cn:9001/gateway/standExchange/detailNew/exchange"
JINDOU_UA = (
    "Mozilla/5.0 (Linux; Android 13; 22081212C Build/TKQ1.220829.002) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.97 Mobile Safari/537.36"
)
JINDOU_REFERER = "https://wapact.189.cn:9001/JinDouMall/JinDouMall_independentDetails.html"
JINDOU_WINDOWS: Tuple[Tuple[int, int], ...] = ((10, 0), (14, 0))
# 开抢前 45 秒开始突发提交（占服务端队列），开抢后 120 秒仍拿不到列表视为今日列表不可用
JINDOU_LEAD_SECONDS = 45
JINDOU_TAIL_SECONDS = 120
# 任务内等待开场的上限：超过则立即探测退出，交给 rolling 冷却重新排程（全部
# 时刻按北京时间场次推算，下次运行被精确钉在场次前 30 分钟，见 _jindou_next_due）
JINDOU_MAX_WAIT_SECONDS = 31 * 60
# 单场突发兑换请求上限（开源参考实现单账号单商品一轮即 10 发，此处默认对齐并允许收敛）
try:
    JINDOU_BURST = max(1, min(20, int((os.getenv("TELECOM_EXCHANGE_BURST") or "").strip() or "10")))
except ValueError:
    JINDOU_BURST = 10

# 电信网关登录公钥与 3DES 密钥
LOGIN_RSA_PUB = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBkLT15ThVgz6/NOl6s8GNPofdWzWbCkWnkaAm7O2LjkM1H7dMvzkiqdxU02jamGRHLX/ZNMCXHnPcW/sDhiFCBN18qFvy8g6VYb9QtroI09e176s+ZCtiv7hbin2cCTj99iUpnEloZm19lwHyo69u5UMiPMpq0/XKBO8lYhN/gwIDAQAB\n"
    "-----END PUBLIC KEY-----"
)
KEY_3DES = b"1234567`90koiuyhgtfrdews"
IV_3DES = 8 * b"\0"

# 电信金豆活动中心公钥与业务对称密钥
DATA_RSA_PUB = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+ugG5A8cZ3FqUKDwM57GM4io6JGcStivT8UdGt67PEOihLZTw3P7371+N47PrmsCpnTRzbTgcupKtUv8ImZalYk65dU8rjC/ridwhw9ffW2LBwvkEnDkkKKRi2liWIItDftJVBiWOh17o6gfbPoNrWORcAdcbpk2L+udld5kZNwIDAQAB\n"
    "-----END PUBLIC KEY-----"
)
AES_SIGN_KEY = b"34d7cb0bcdf07523"

UA_MOBILE = (
    "Mozilla/5.0 (Linux; U; Android 12; zh-cn; Build/SP1A.210812.016) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Mobile Safari/537.36 "
    "CtClient;10.5.0;Android;12;20002"
)


# ---------- 代理候选与调度（复用境内 CN 出口） ----------


def _get_candidate_proxies() -> List[ProxyEndpoint]:
    """获取中国电信任务可用的代理出口列表（CN 家宽优先，sing-box 国际家宽兜底）。"""
    endpoints = get_all_proxy_endpoints(task_prefix="TELECOM")
    if not endpoints:
        raw = (
            os.getenv("TELECOM_PROXY")
            or os.getenv("CLOUD189_PROXY")
            or os.getenv("SMZDM_PROXY")
            or os.getenv("52POJIE_PROXY")
            or os.getenv("WUAI_PROXY")
            or ""
        )
        endpoints = parse_proxies_text(raw, default_name_prefix="电信CN代理")
    endpoints = endpoints[:3]

    # 兜底出口：CI 的 sing-box 统一出站（socks5://127.0.0.1:1080，「国际家宽」组）。
    # wappark 的 WAF 拒数据中心/海外 IP（直连 412/-1），但家宽属性出口可能放行；
    # 排在 CN 家宽代理之后、直连之前。本地无 sing-box 时该候选会快速失败被跳过。
    sb_url = (os.getenv("SINGBOX_SOCKS_URL") or "socks5://127.0.0.1:1080").strip()
    try:
        from proxy_manager import parse_proxy_line
        sb_ep = parse_proxy_line(f"{sb_url}#singbox-国际家宽兜底")
        if sb_ep and all(ep.url != sb_ep.url for ep in endpoints):
            endpoints.append(sb_ep)
    except Exception:
        pass
    return endpoints


# ---------- 业务接口加解密逻辑 ----------


_CREDENTIAL_ERR_PATTS = (
    "密码错误", "密码不正确", "弱密码", "忘记密码",
    "密码已被锁定", "账号已锁定", "用户不存在", "账号不存在",
)


def _is_credential_desc(desc: str) -> bool:
    """登录网关返回的密码类硬错误判定：重试只会加重锁定，须当日停手。"""
    return any(p in (desc or "") for p in _CREDENTIAL_ERR_PATTS)


# App 同款 getSingle 现签端点与请求模板（2026-09-19 HAR 逆向，appgologinsz 为抓包实测可用节点）
APP_GETSINGLE_URL = "https://appgologinsz.189.cn/map/clientXML"
_GETSINGLE_CLIENT_TYPE = "#13.3.0#channel29#OPPO PJJ110#"
_GETSINGLE_PROVINCE_CODE = "600202"  # 随账号归属省固定（抓包值）


def _build_getsingle_xml(token: str, uid: str, target_id: str, ts: str) -> str:
    """构造 App 同款 clientXML getSingle 请求体（UserLoginName 需带尾部分号，与抓包一致）。"""
    return (
        f'<Request><HeaderInfos><Code>getSingle</Code><Timestamp>{ts}</Timestamp>'
        f'<BroadAccount></BroadAccount><BroadToken></BroadToken>'
        f'<ClientType>{_GETSINGLE_CLIENT_TYPE}</ClientType>'
        f'<FixedLineAccount></FixedLineAccount><FixedLineToken></FixedLineToken>'
        f'<ProvinceCode>{_GETSINGLE_PROVINCE_CODE}</ProvinceCode>'
        f'<ShopId>20002</ShopId><Source>110003</Source><SourcePassword>Sid98s</SourcePassword>'
        f'<Token>{token}</Token>'
        f'<UserLoginName>{uid};</UserLoginName></HeaderInfos>'
        f'<Content><Attach>test</Attach><FieldData><TargetId>{target_id}</TargetId>'
        f'<Url>4a6862274835b451</Url></FieldData></Content></Request>'
    )


def _encrypt_aes(data: Union[str, Dict[str, Any], List[Any]], key: bytes = AES_SIGN_KEY) -> str:
    """AES-128-ECB 加密，PKCS7 填充，Hex 格式输出。"""
    if not HAS_CRYPTO:
        raise RuntimeError("缺少 pycryptodome 依赖，请执行 pip install pycryptodome")
    if isinstance(data, (dict, list)):
        payload = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    else:
        payload = str(data)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(payload.encode("utf-8"), 16))
    return encrypted.hex()


def _encrypt_rsa(data: Union[str, Dict[str, Any]]) -> str:
    """RSA PKCS#1 v1.5 分段加密（每段 32 字节），Hex 格式拼接输出。"""
    if not HAS_CRYPTO:
        raise RuntimeError("缺少 pycryptodome 依赖，请执行 pip install pycryptodome")
    if isinstance(data, (dict, list)):
        payload = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    else:
        payload = str(data)
    rsa_key = RSA.import_key(DATA_RSA_PUB)
    cipher = PKCS1_v1_5.new(rsa_key)
    res_list: List[str] = []
    for i in range(0, len(payload), 32):
        chunk = payload[i : i + 32].encode("utf-8")
        res_list.append(cipher.encrypt(chunk).hex())
    return "".join(res_list)


# ---------- 账号凭据模型与解析 ----------


class TelecomAccount:
    def __init__(
        self,
        index: int,
        phone: str = "",
        sign: str = "",
        authorization: str = "",
        cookie: str = "",
        user_agent: str = "",
        ticket: str = "",
        password: str = "",
        app_token: str = "",
        uid: str = "",
        target_id: str = "",
        extra_headers: Optional[Dict[str, str]] = None,
    ):
        self.index = index
        self.phone = phone.strip()
        self.sign = sign.strip()
        self.authorization = authorization.strip()
        self.cookie = cookie.strip()
        self.user_agent = user_agent.strip()
        self.ticket = ticket.strip()
        self.password = password.strip()
        # App 长效登录 Token 三件套（clientXML getSingle 现签 Ticket 用，见 mint_ticket_with_token）
        self.app_token = app_token.strip()
        self.uid = uid.strip()
        self.target_id = target_id.strip()
        self.extra_headers = extra_headers or {}

    @property
    def display_name(self) -> str:
        if self.phone:
            return mask_str(self.phone)
        if self.sign:
            return f"账号#{self.index} ({mask_str(self.sign, keep_start=4, keep_end=4)})"
        return f"账号#{self.index}"

    def has_credentials(self) -> bool:
        return bool(
            self.sign or self.authorization or self.ticket
            or (self.app_token and self.uid and self.target_id)
            or (self.phone and self.password)
        )


def _parse_account_config(raw: str, index: int, password: str = "") -> TelecomAccount:
    """从抓包整串中智能解析 phone, sign, authorization, cookie, user_agent, extra_headers。"""
    raw = (raw or "").strip()
    if not raw and not password:
        return TelecomAccount(index)

    phone = ""
    sign = ""
    auth = ""
    ticket = ""
    app_token = ""
    uid = ""
    target_id = ""
    cookies: List[str] = []
    user_agent = ""
    extra_headers: Dict[str, str] = {}

    # 1. 逐行提取 Header
    for line in raw.splitlines():
        l = line.strip()
        if not l or ":" not in l:
            continue
        k, v = l.split(":", 1)
        k_low = k.strip().lower()
        v_val = v.strip().strip("\"'")
        if k_low == "cookie":
            if v_val:
                cookies.append(v_val)
        elif k_low == "user-agent":
            user_agent = v_val
        elif k_low == "sign" and re.match(r"^[0-9a-zA-Z_-]{16,128}$", v_val):
            sign = v_val
        elif k_low in ("authorization", "auth"):
            auth = v_val
        elif k_low in ("vx3b5xuq", "x-requested-with"):
            extra_headers[k.strip()] = v_val
        elif k_low == "ticket":
            ticket = v_val
        elif k_low == "token" and v_val.startswith("V1."):
            app_token = v_val
        elif k_low in ("uid", "userid"):
            uid = v_val
        elif k_low in ("targetid", "target"):
            target_id = v_val

    # 2. 检查内嵌 JSON
    m_json = re.search(r"(\{[\s\S]*\})", raw)
    if m_json:
        try:
            d = json.loads(m_json.group(1))
            if isinstance(d, dict):
                if not phone:
                    p = str(d.get("phone") or d.get("mobile") or d.get("username") or "")
                    if re.match(r"^1\d{10}$", p):
                        phone = p
                if not sign:
                    s = str(d.get("sign") or d.get("sign_token") or "")
                    if s:
                        sign = s
                if not auth:
                    a = str(d.get("authorization") or d.get("token") or d.get("auth") or "")
                    if a:
                        auth = a
                if not ticket:
                    t = str(d.get("ticket") or "")
                    if t:
                        ticket = t
        except Exception:
            pass

    # 3. 经典格式: 手机号#sign 或 手机号#sign#auth（单行且无换行）
    if "#" in raw and not ("\n" in raw or "{" in raw):
        parts = [p.strip() for p in raw.split("#")]
        if len(parts) == 2:
            phone = parts[0]
            sign = parts[1]
        elif len(parts) >= 3:
            phone = parts[0]
            sign = parts[1]
            auth = parts[2]

    # 4. Key-Value 串或正则补充提取 sign 与 auth 与 ticket
    if not sign:
        m_sign = re.search(r"['\"]?sign['\"]?\s*[:=]\s*['\"]?([0-9a-zA-Z_-]{16,128})['\"]?", raw)
        if m_sign:
            sign = m_sign.group(1)
    if not auth:
        m_auth = re.search(
            r"['\"]?(?:authorization|token|auth)['\"]?\s*[:=]\s*['\"]?(Bearer\s+[^\s\"',;]+|[0-9a-zA-Z_-]{16,128})['\"]?",
            raw,
            re.I,
        )
        if m_auth:
            auth = m_auth.group(1)
    if not ticket:
        m_tk = re.search(r"['\"]?ticket['\"]?\s*[:=]\s*['\"]?([0-9a-zA-Z]{32,256})['\"]?", raw)
        if m_tk:
            ticket = m_tk.group(1)
    if not sign:
        m_sign = re.search(r"['\"]?sign['\"]?\s*[:=]\s*['\"]?([0-9a-zA-Z_-]{16,128})['\"]?", raw)
        if m_sign:
            sign = m_sign.group(1)
    if not auth:
        m_auth = re.search(
            r"['\"]?(?:authorization|token|auth)['\"]?\s*[:=]\s*['\"]?(Bearer\s+[^\s\"',;]+|[0-9a-zA-Z_-]{16,128})['\"]?",
            raw,
            re.I,
        )
        if m_auth:
            auth = m_auth.group(1)

    # 5. 提取明文手机号
    if not phone:
        m_phone = re.search(r"['\"]?(?:phone|mobile|userLoginName)['\"]?\s*[:=]\s*['\"]?(\d{11})['\"]?", raw)
        if m_phone:
            phone = m_phone.group(1)

    # 5.5 App 长效 Token 三件套（token/uid/targetId，App 同款 getSingle 换票凭据）。
    #     token 为 V1.0 前缀 base64（含 +/=），避免被下方 auth 的 [A-Za-z0-9_-] 正则误吞
    if not app_token:
        m_tok = re.search(r"['\"]?token['\"]?\s*[:=]\s*['\"]?(V1\.0[A-Za-z0-9+/=]{64,512})['\"]?", raw)
        if m_tok:
            app_token = m_tok.group(1)
    if not uid:
        m_uid = re.search(r"['\"]?uid['\"]?\s*[:=]\s*['\"]?(\d{6,20})['\"]?", raw, re.I)
        if m_uid:
            uid = m_uid.group(1)
    if not target_id:
        m_tgt = re.search(r"['\"]?target(?:_?id)?['\"]?\s*[:=]\s*['\"]?([0-9a-fA-F]{32,128})['\"]?", raw, re.I)
        if m_tgt:
            target_id = m_tgt.group(1)

    # 6. 从 cookies / distinct_id 逆向解析手机号（神策/统计 SDK distinct_id base64 编码的手机号）
    if not phone and (cookies or "distinct_id" in raw):
        unq = urllib.parse.unquote(raw)
        m_dist = re.search(r'\"distinct_id\"\s*:\s*\"([A-Za-z0-9+/=]{12,24})\"', unq)
        if m_dist:
            try:
                b = base64.b64decode(m_dist.group(1)).decode("utf-8")
                if re.match(r"^1\d{10}$", b):
                    phone = b
            except Exception:
                pass

    # 7. 从 CtClient User-Agent 逆向解析手机号（b64 前缀!#!b64 尾6位，两端去 padding 拼接）
    if not phone and user_agent:
        m_uaph = re.search(r"([A-Za-z0-9+/=]+)!#!([A-Za-z0-9+/=]+)", user_agent)
        if m_uaph:
            try:
                def _b64_fix(s: str) -> str:
                    s = s.strip()
                    pad = 4 - (len(s) % 4)
                    if pad != 4:
                        s += "=" * pad
                    return base64.b64decode(s).decode("utf-8")
                p1 = _b64_fix(m_uaph.group(1))
                p2 = _b64_fix(m_uaph.group(2))
                if re.match(r"^1\d{10}$", p2 + p1):
                    phone = p2 + p1
                elif re.match(r"^1\d{10}$", p1 + p2):
                    phone = p1 + p2
            except Exception:
                pass

    # 8. 规范化 User-Agent：若以裸 CtClient 开头，补充 Android WebView 前缀以规避 WAF 412
    if user_agent and not user_agent.startswith("Mozilla/5.0"):
        user_agent = f"Mozilla/5.0 (Linux; U; Android 12; zh-cn) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Mobile Safari/537.36 {user_agent}"

    # 9. 单值推断（仅提供 sign 或 Bearer 串）
    if not sign and not auth:
        if raw.startswith("Bearer "):
            auth = raw
        elif len(raw) >= 32 and re.match(r"^[0-9a-zA-Z]+$", raw):
            sign = raw

    cookie_str = "; ".join(cookies)
    return TelecomAccount(
        index=index,
        phone=phone,
        sign=sign,
        authorization=auth,
        cookie=cookie_str,
        user_agent=user_agent,
        ticket=ticket,
        password=password,
        app_token=app_token,
        uid=uid,
        target_id=target_id,
        extra_headers=extra_headers,
    )


def load_all_accounts() -> List[TelecomAccount]:
    """多账号序列加载：支持 App 抓包整串（TELECOM_HEADER_1...）与服务密码登录（TELECOM_PASSWORD_1...）。"""
    accounts: List[TelecomAccount] = []
    idx = 1
    while True:
        header_val = os.getenv(f"TELECOM_HEADER_{idx}") or os.getenv(f"telecom_header_{idx}") or ""
        pwd_val = os.getenv(f"TELECOM_PASSWORD_{idx}") or os.getenv(f"TELECOM_SERVICE_PASSWORD_{idx}") or ""
        phone_val = os.getenv(f"TELECOM_PHONE_{idx}") or os.getenv(f"TELECOM_USERNAME_{idx}") or os.getenv(f"CLOUD189_USERNAME_{idx}") or ""

        if not header_val and not pwd_val:
            if idx == 1:
                header_val = os.getenv("TELECOM_HEADER", "") or os.getenv("TELECOM_header", "")
                pwd_val = os.getenv("TELECOM_PASSWORD", "") or os.getenv("TELECOM_SERVICE_PASSWORD", "")
                phone_val = phone_val or os.getenv("CLOUD189_USERNAME", "")

        if not header_val and not pwd_val:
            break

        acc = _parse_account_config(header_val, idx, password=pwd_val)
        if not acc.phone and phone_val and re.match(r"^1\d{10}$", phone_val):
            acc.phone = phone_val
        if acc.has_credentials():
            accounts.append(acc)
        idx += 1

    return accounts


# ---------- 电信 API 会话客户端 ----------


class TelecomClient:
    def __init__(self, account: TelecomAccount, http: Http):
        self.acc = account
        self.http = http
        self.phone = account.phone
        self.password = account.password
        self.sign = account.sign
        self.authorization = account.authorization
        self.ticket = account.ticket
        self.cookie = account.cookie
        self.user_agent = account.user_agent
        self.app_token = account.app_token
        self.uid = account.uid
        self.target_id = account.target_id
        self.extra_headers = dict(account.extra_headers)
        self.state_file = f".telecom_state_{account.index}.json"
        self.redis_key = f"cat_checkin:state:telecom_{account.index}"
        # cookie 来源标记：restore_cached_session 从缓存/Redis 恢复时置 True，
        # 用于与用户 HEADER 抓包提供的 cookie 区分（见 prepare_auth 的清理逻辑）
        self._cookie_from_cache = False
        # 服务密码登录返回的密码类硬错误描述（非空 = 当日须停止重试登录）
        self.credential_error = ""
        # 现签 mint 遭遇网络类失败（连接超时/-1/WAF 412）标记：用于把「缺 sign」
        # 归因为出口网络问题以触发代理轮换，而非当成凭据缺失直接放弃
        self.mint_network_failure = False
        # ssoHomLogin 返回的乐园账户 accId（等级权益/兑换记录等接口的账户标识，
        # 2026-10-31 排障发现此前一直被丢弃——receiverRights 缺它直接 500）
        self.acc_id = ""

    def _req(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json_data: Any = None,
        data: Any = None,
        timeout: int = 15,
    ) -> Dict[str, Any]:
        h = {
            "User-Agent": self.user_agent or UA_MOBILE,
            "Origin": "https://wappark.189.cn",
            "Referer": "https://wappark.189.cn/resources/dist/signNew.html",
            "X-Requested-With": "com.ct.client",
            "Accept": "application/json, text/plain, */*",
        }
        if self.cookie:
            h["Cookie"] = self.cookie
        if self.extra_headers:
            h.update(self.extra_headers)
        if headers:
            h.update(headers)
        try:
            resp = self.http.request(
                method,
                url,
                headers=h,
                json_data=json_data,
                data=data,
                timeout=timeout,
            )
            data_dict = resp.json({}) if isinstance(resp.json({}), dict) else {}
            if resp.code != 200 and not data_dict:
                return {"code": resp.code, "msg": f"HTTP {resp.code}", "_http_error": True}
            return data_dict
        except Exception as err:
            if os.getenv("DEBUG"):
                print(f"    [DEBUG] 请求异常 {url}: {err}", flush=True)
            return {"code": -1, "msg": str(err), "_http_error": True}

    def restore_cached_session(self) -> bool:
        """从 Upstash Redis 或本地状态恢复会话缓存。"""
        state = load_kv_state(self.redis_key, self.state_file)
        if not state:
            return False

        if not self.phone and state.get("phone"):
            self.phone = str(state.get("phone"))
        if not self.password and state.get("password"):
            self.password = str(state.get("password"))
        if not self.sign and state.get("sign"):
            self.sign = str(state.get("sign"))
        if not self.authorization and state.get("authorization"):
            self.authorization = str(state.get("authorization"))
        if not self.ticket and state.get("ticket"):
            self.ticket = str(state.get("ticket"))
        if not self.cookie and state.get("cookie"):
            self.cookie = str(state.get("cookie"))
            self._cookie_from_cache = True
        if not self.user_agent and state.get("user_agent"):
            ua = str(state.get("user_agent")).strip()
            # 状态恢复的 UA 必须通过完整性校验：截断 Mozilla / 裸 App UA 会被
            # wappark WAF 一律 412（2026-09-19 CI 全天失败的第二根因，探针实测
            # UA 敏感：完整 Mozilla+App 后缀 200，其余全 412）。不合规则弃用，
            # 回退 UA_MOBILE 默认值
            if ua.startswith("Mozilla/5.0") and "AppleWebKit" in ua and "Safari" in ua:
                self.user_agent = ua
        if not self.app_token and state.get("app_token"):
            self.app_token = str(state.get("app_token"))
        if not self.uid and state.get("uid"):
            self.uid = str(state.get("uid"))
        if not self.target_id and state.get("target_id"):
            self.target_id = str(state.get("target_id"))
        # 注意：password 有意不持久化（2026-09-19 起）——服务密码路线被 3006 设备级
        # 风控阻断后仅存兜底意义，落盘/入 Redis 只增加泄露面与误触发登录的风险；
        # 服务密码仅经 TELECOM_PASSWORD_* 环境变量在内存中直读

        if self.sign or self.authorization or self.ticket or (self.phone and self.password) \
                or (self.app_token and self.uid):
            # 脱敏打印恢复状态的字段长度，便于定位「陈旧缓存抢跑」类问题（2026-09-19）
            print(f"    [keepalive] 成功加载账号缓存会话 (更新于: {state.get('updated_at', '未知')}) "
                  f"[sign={len(str(state.get('sign') or ''))} ticket={len(str(state.get('ticket') or ''))} "
                  f"cookie={len(str(state.get('cookie') or ''))} ua={len(str(state.get('user_agent') or ''))} "
                  f"auth={len(str(state.get('authorization') or ''))} token={'Y' if state.get('app_token') else 'N'}]",
                  flush=True)
            return True
        return False

    def save_session(self) -> None:
        """持久化当前可用会话凭据（不含密码：敏感值永不落盘，见 restore_cached_session 注释）。"""
        state = {
            "phone": self.phone,
            "sign": self.sign,
            "authorization": self.authorization,
            "ticket": self.ticket,
            "cookie": self.cookie,
            "user_agent": self.user_agent,
            "app_token": self.app_token,
            "uid": self.uid,
            "target_id": self.target_id,
            "updated_at": datetime.now(BJT).strftime("%Y-%m-%d %H:%M:%S"),
        }
        save_kv_state(self.redis_key, self.state_file, state)

    def login_with_password(self) -> bool:
        """使用手机号+服务密码向 appgologin 网关申请会话 Ticket 并换取 sign。"""
        if not (self.phone and self.password) or not HAS_CRYPTO:
            return False

        alphabet = "abcdef0123456789"
        uuid_parts = [
            "".join(random.sample(alphabet, 8)),
            "".join(random.sample(alphabet, 4)),
            "4" + "".join(random.sample(alphabet, 3)),
            "".join(random.sample(alphabet, 4)),
            "".join(random.sample(alphabet, 12)),
        ]
        timestamp = datetime.now(BJT).strftime("%Y%m%d%H%M%S")
        cipher_raw = f"iPhone 14 15.4.{uuid_parts[0]}{uuid_parts[1]}{self.phone}{timestamp}{self.password[:6]}0$$$0."
        try:
            rsa_k = RSA.import_key(LOGIN_RSA_PUB)
            c = PKCS1_v1_5.new(rsa_k)
            enc_cipher = base64.b64encode(c.encrypt(cipher_raw.encode())).decode()
        except Exception as e:
            print(f"    [login] 加密登录凭据异常: {e}", flush=True)
            return False

        def _enc_p(text: str) -> str:
            return "".join(chr(ord(ch) + 2) for ch in text)

        body = {
            "headerInfos": {
                "code": "userLoginNormal",
                "timestamp": timestamp,
                "broadAccount": "",
                "broadToken": "",
                "clientType": "#11.3.0#channel35#Xiaomi Redmi K30 Pro#",
                "shopId": "20002",
                "source": "110003",
                "sourcePassword": "Sid98s",
                "token": "",
                "userLoginName": _enc_p(self.phone),
            },
            "content": {
                "attach": "test",
                "fieldData": {
                    "loginType": "4",
                    "accountType": "",
                    "loginAuthCipherAsymmertric": enc_cipher,
                    "deviceUid": uuid_parts[0] + uuid_parts[1] + uuid_parts[2],
                    "phoneNum": _enc_p(self.phone),
                    "isChinatelecom": "0",
                    "systemVersion": "12",
                    "authentication": _enc_p(self.password),
                },
            },
        }

        resp = self.http.request(
            "POST",
            "https://appgologin.189.cn:9031/login/client/userLoginNormal",
            json_data=body,
            headers={"Content-Type": "application/json", "User-Agent": "CtClient;10.4.1;Android;13"},
            timeout=15,
        )
        data = resp.json({}) if isinstance(resp.json({}), dict) else {}
        rd = data.get("responseData") or {}
        l_res = (rd.get("data") or {}).get("loginSuccessResult") or {}
        if not l_res:
            desc = rd.get("resultDesc") or data.get("headerInfos", {}).get("reason") or "登录未成功"
            print(f"    [login] 服务密码登录网关响应: {desc}", flush=True)
            if _is_credential_desc(desc):
                self.credential_error = desc
                print("    [login] ⛔ 密码类硬错误：当日不再重试登录（防止服务密码连续错输被锁定）", flush=True)
            return False

        user_id = str(l_res.get("userId", ""))
        token = str(l_res.get("token", ""))
        if not (user_id and token):
            return False

        # 3DES 加密 TargetId 获取 XML Ticket
        des_c = DES3.new(KEY_3DES, DES3.MODE_CBC, IV_3DES)
        target_id_hex = des_c.encrypt(pad(user_id.encode(), DES3.block_size)).hex()
        xml_data = (
            f"<Request><HeaderInfos><Code>getSingle</Code><Timestamp>{timestamp}</Timestamp>"
            f"<BroadAccount></BroadAccount><BroadToken></BroadToken>"
            f"<ClientType>#9.6.1#channel50#iPhone 14 Pro Max#</ClientType><ShopId>20002</ShopId>"
            f"<Source>110003</Source><SourcePassword>Sid98s</SourcePassword><Token>{token}</Token>"
            f"<UserLoginName>{self.phone}</UserLoginName></HeaderInfos><Content><Attach>test</Attach>"
            f"<FieldData><TargetId>{target_id_hex}</TargetId><Url>4a6862274835b451</Url></FieldData></Content></Request>"
        )
        xml_resp = self.http.request(
            "POST",
            "https://appgologin.189.cn:9031/map/clientXML",
            data=xml_data,
            headers={"User-Agent": "CtClient;10.4.1;Android;13", "Content-Type": "application/xml"},
            timeout=15,
        )
        tk_match = re.findall(r"<Ticket>(.*?)</Ticket>", xml_resp.text)
        if not tk_match:
            print("    [login] 未能从网关 XML 获取 Ticket", flush=True)
            return False

        try:
            des_dec = DES3.new(KEY_3DES, DES3.MODE_CBC, IV_3DES)
            ticket_val = unpad(des_dec.decrypt(bytes.fromhex(tk_match[0])), DES3.block_size).decode()
            self.ticket = ticket_val
            print(f"    [login] 账号【{mask_str(self.phone)}】服务密码鉴权成功，已获取免密 Ticket", flush=True)
            return self.exchange_ticket()
        except Exception as e:
            print(f"    [login] Ticket 3DES 解密失败: {e}", flush=True)
            return False

    def exchange_ticket(self) -> bool:
        """若存在 ticket，通过 ssoHomLogin 自动换取最新可用 sign 并反解手机号。"""
        if not self.ticket:
            return False
        url = f"https://wappark.189.cn/jt-sign/ssoHomLogin?ticket={self.ticket}"
        res = self._req("GET", url)
        if res.get("resoultCode") == "0" and res.get("sign"):
            self.sign = res["sign"]
            self.acc.sign = res["sign"]
            # accId 与 sign 同源下发，乐园权益/兑换记录接口的账户标识（此前被丢弃）
            if res.get("accId"):
                self.acc_id = str(res["accId"])
            user_num = res.get("userNum", "")
            if user_num and HAS_CRYPTO:
                try:
                    c = AES.new(AES_SIGN_KEY, AES.MODE_ECB)
                    dec_phone = unpad(c.decrypt(bytes.fromhex(user_num)), 16).decode("utf-8")
                    if re.match(r"^1\d{10}$", dec_phone):
                        self.phone = dec_phone
                        self.acc.phone = dec_phone
                except Exception:
                    pass
            print(f"    [ticket] 成功利用 ticket 换取电信会话 sign: {mask_str(self.sign, 4, 4)}", flush=True)
            return True
        # 失败不得静默：打印响应要点（脱敏）定位 WAF/会话层问题（2026-09-19 CI 排障）
        print(f"    [ticket] 换取 sign 失败: http_code={res.get('code')} "
              f"resoultCode={res.get('resoultCode')} "
              f"msg={str(res.get('resoultMsg') or res.get('msg') or '')[:80]}", flush=True)
        return False

    def mint_ticket_with_token(self) -> bool:
        """App 同款免密换票：长效 Token 经 clientXML getSingle 现签 Ticket 并换取 sign。

        逆向结论（2026-09-19 HAR 抓包）：App 每次打开金豆 H5 均以自身登录 Token 调
        getSingle 现签一张 Ticket（3DES 加密下发），H5 经 ssoHomLogin 换 sign。
        该路径不需要账密、不触发 3006 设备验证，Token 寿命远长于 ticket/sign。
        """
        if not (self.app_token and self.uid and self.target_id and HAS_CRYPTO):
            return False
        ts = datetime.now(BJT).strftime("%Y%m%d%H%M%S")
        xml = _build_getsingle_xml(self.app_token, self.uid, self.target_id, ts)
        # 连接超时 10s（原 20s）：死节点（如 TELECOM_PROXY 首位的 HK09，每次
        # curl(28) TCP 连接超时）会吃满整个 timeout 才触发轮换，直接侵蚀 300s 任务预算；
        # 健康节点（HK03）实测现签仅 1~3s，10s 留足余量又不误伤慢节点（2026-10-06 CI 复盘）。
        resp = self.http.request(
            "POST",
            APP_GETSINGLE_URL,
            data=xml,
            headers={"Content-Type": "application/xml", "User-Agent": "CtClient;10.4.1;Android;13"},
            timeout=10,
        )
        text = resp.text or ""
        # 网络类失败（连接超时/-1/WAF 412/5xx）：与出口相关，应触发代理轮换而非放弃
        if resp.code == -1 or resp.code == 412 or 500 <= resp.code < 600:
            self.mint_network_failure = True
        result_code = re.search(r"<ResultCode>(.*?)</ResultCode>", text)
        if resp.code != 200 or (result_code and result_code.group(1) != "0000"):
            reason = re.search(r"<Reason>(.*?)</Reason>", text)
            print(f"    [token] getSingle 现签失败: code={resp.code} "
                  f"result={result_code.group(1) if result_code else '?'} "
                  f"reason={reason.group(1) if reason else text[:80]}", flush=True)
            return False
        tk_match = re.findall(r"<Ticket>(.*?)</Ticket>", text)
        if not tk_match:
            print("    [token] getSingle 响应中无 Ticket", flush=True)
            return False
        try:
            des_dec = DES3.new(KEY_3DES, DES3.MODE_CBC, IV_3DES)
            self.ticket = unpad(des_dec.decrypt(bytes.fromhex(tk_match[0])), DES3.block_size).decode()
        except Exception as e:
            print(f"    [token] Ticket 3DES 解密失败: {e}", flush=True)
            return False
        print(f"    [token] App 长效 Token 现签 Ticket 成功，正在换取 sign...", flush=True)
        return self.exchange_ticket()

    # ---------- 金豆商城（wapact.189.cn:9001）抢兑 ----------

    def _jindou_headers(self, token: str = "") -> Dict[str, str]:
        h = {"User-Agent": JINDOU_UA, "Referer": JINDOU_REFERER}
        if token:
            h["Authorization"] = f"Bearer {token}"
        return h

    def jindou_unified_login(self) -> str:
        """App 现签 ticket 经 wapact 统一登录换金豆商城 Bearer token（AES-ECB）。"""
        if not (self.ticket and HAS_CRYPTO):
            return ""
        payload = json.dumps({
            "ticket": self.ticket,
            "backUrl": "https%3A%2F%2Fwapact.189.cn%3A9001",
            "platformCode": "P201010301",
            "loginType": 2,
        })
        try:
            cipher = AES.new(JINDOU_AES_KEY.encode("utf-8"), AES.MODE_ECB)
            enc = base64.b64encode(
                cipher.encrypt(pad(payload.encode("utf-8"), AES.block_size))
            ).decode("ascii")
        except Exception:
            return ""
        res = self.http.request(
            "POST", JINDOU_LOGIN_URL, data=enc,
            headers={"Content-Type": "application/json;charset=UTF-8", **self._jindou_headers()},
            timeout=15,
        )
        try:
            data = res.json() or {}
        except Exception:
            data = {}
        if res.code == 200 and data.get("code") == 0:
            token = str((data.get("biz") or {}).get("token") or "")
            if token:
                return token
        print(f"    [商城] 统一登录失败: http={res.code} code={data.get('code')} "
              f"msg={str(data.get('message'))[:60]}", flush=True)
        return ""

    def jindou_query_balance(self, token: str) -> Optional[int]:
        """金豆商城侧金豆余额（biz.amountTotal），失败返回 None。"""
        res = self.http.request("GET", JINDOU_QUERY_URL, headers=self._jindou_headers(token), timeout=15)
        try:
            data = res.json() or {}
        except Exception:
            return None
        if res.code == 200 and data.get("code") == 0:
            try:
                return int(float((data.get("biz") or {}).get("amountTotal")))
            except (TypeError, ValueError):
                return None
        return None

    def jindou_fetch_goods(self, token: str) -> Tuple[Optional[List[Dict[str, Any]]], str]:
        """场次商品列表。返回 (列表 or None, 错误说明)；None=列表不可用（多为场次未开放，
        服务端返回 code=999999「系统错误」——已实测与瑞数 Cookie/UA/HTTP 版本无关）。"""
        res = self.http.request("GET", JINDOU_GOODS_URL, headers=self._jindou_headers(token), timeout=15)
        try:
            data = res.json() or {}
        except Exception:
            return None, f"HTTP {res.code}"
        if res.code == 200 and data.get("code") == 0:
            items = (data.get("biz") or {}).get("ExchangeGoodslist")
            if isinstance(items, list):
                return [it for it in items if isinstance(it, dict)], ""
            return [], ""
        return None, str(data.get("message") or f"code={data.get('code')}")

    def jindou_exchange_once(self, token: str, activity_id: str) -> Dict[str, str]:
        """提交一次兑换，返回归一化 {code, result_code, message}。"""
        res = self.http.request(
            "POST", JINDOU_EXCHANGE_URL,
            json_data={"activityId": activity_id},
            headers={"Content-Type": "application/json;charset=UTF-8", **self._jindou_headers(token)},
            timeout=15,
        )
        if res.code == 412:
            return {"code": "HTTP412", "result_code": "", "message": "WAF/风控拦截(HTTP 412)"}
        if res.code == 429:
            return {"code": "HTTP429", "result_code": "", "message": "请求频率受限(HTTP 429)"}
        try:
            data = res.json() or {}
        except Exception:
            return {"code": str(res.code), "result_code": "",
                    "message": f"非JSON响应: {(res.text or '')[:60]}"}
        biz = data.get("biz") or {}
        return {
            "code": str(data.get("code")),
            "result_code": str(biz.get("resultCode") or ""),
            "message": str(data.get("message") or ""),
        }

    def try_exchange_phone_bill(self, goal: str, target_beans: int) -> str:
        """金豆达标时尝试金豆商城抢兑目标话费券（如实回报，不再美化失败）。

        场次未开放/列表不可用时明确说明并指向专项抢兑任务，杜绝旧链路
        「响应为空也报已提交」的假成功。"""
        _, msg = run_jindou_exchange(self, goal, target_beans, wait_for_window=False, burst=1)
        return msg

    def prepare_auth(self) -> bool:
        """准备可用鉴权票据：Token 现签优先（App 同款），缓存会话仅作回退。"""
        self.restore_cached_session()

        # 若未指定手机号，优先尝试复用同账号序号的 CLOUD189 手机号配置
        if not self.phone:
            cloud189_user = (
                os.getenv(f"CLOUD189_USERNAME_{self.acc.index}")
                or os.getenv("CLOUD189_USERNAME")
                or os.getenv("CLOUD189_username")
                or ""
            ).strip()
            if re.match(r"^1\d{10}$", cloud189_user):
                self.phone = cloud189_user
                self.acc.phone = cloud189_user

        # 2026-09-19 CI 全天失败根因（两段式）：恢复的陈旧缓存会话先于现签打接口，
        # ① 旧 sign 抢跑使 mint 被跳过，死会话请求被 WAF 412 短路；
        # ② 缓存 cookie 与出口 IP 绑定（WAF 通行状态），随 mint 内部 ssoHomLogin
        #    重放照样 412，现签成功也无法落地（本地无缓存 cookie 故全绿）。
        # 故：来自缓存的 cookie 一律先行丢弃（cookieless 请求已验证畅通），且持有
        # 长效 Token 时永远先现签（App 同款），仅现签失败时回退缓存 sign/ticket 老路。
        if self._cookie_from_cache:
            self.cookie = ""
            self._cookie_from_cache = False
        minted = False
        if self.app_token and self.uid and HAS_CRYPTO:
            minted = self.mint_ticket_with_token()
        if not minted and not self.sign and self.ticket:
            self.exchange_ticket()

        # 若 sign 仍然缺失但配置了服务密码，执行服务密码登录换票
        if not self.sign and (self.phone and self.password):
            self.login_with_password()
        if not (self.sign or self.authorization or self.ticket
                or (self.app_token and self.uid and self.target_id)
                or (self.phone and self.password)):
            return False

        # 若仍未指定手机号，尝试从金豆个人中心反查
        if self.sign and not self.phone and HAS_CRYPTO:
            try:
                info_res = self._req(
                    "POST",
                    "https://wappark.189.cn/jt-sign/paradise/getParadiseInfo",
                    json_data={"para": _encrypt_rsa({})},
                    headers={"sign": self.sign},
                )
                m_ph = info_res.get("data", {}).get("phone") or info_res.get("data", {}).get("mobile")
                if m_ph:
                    self.phone = str(m_ph)
                    self.acc.phone = str(m_ph)
            except Exception:
                pass

        return True


# ---------- 签到与资产业务逻辑 ----------


def execute_telecom_task(client: TelecomClient) -> Dict[str, Any]:
    """执行单个电信账号的完整签到、抽奖与任务流程。"""
    res: Dict[str, Any] = {
        "status": "未开始",
        "gain_bean": 0,
        "streak_days": 0,
        "lottery_res": "",
        "task_res": "",
        "food_res": "",
        "total_bean": "",
        "goal_res": "",
        "imusic_res": "",
        "error": "",
    }

    if not client.prepare_auth():
        res["status"] = "失败"
        res["error"] = "缺少 App 抓包凭据（请在 TELECOM_HEADER_1 配置抓包整串）"
        return res

    if client.credential_error:
        res["status"] = "失败"
        res["error"] = (f"服务密码凭证错误（{client.credential_error}）"
                        f"——已停止当日重试以防密码锁定，请核对密码后次日自动复跑")
        return res

    # 1. 执行每日签到
    if client.sign and HAS_CRYPTO:
        payload_data: Dict[str, Any] = {"date": int(time.time() * 1000), "sysType": "20002"}
        if client.phone:
            payload_data["phone"] = client.phone
        sign_payload = {"encode": _encrypt_aes(payload_data)}
        sign_res = client._req(
            "POST",
            "https://wappark.189.cn/jt-sign/webSign/sign",
            json_data=sign_payload,
            headers={"sign": client.sign},
        )
        msg = sign_res.get("msg") or sign_res.get("resoultMsg") or ""
        code = str(sign_res.get("code") or "")

        if is_already_signed(msg, extra_phrases=("已签", "已经签")):
            res["status"] = "今日已签"
        elif code in ("0", "200") or "成功" in msg:
            res["status"] = "成功"
            m_bean = re.search(r"(\d+)\s*金豆", msg) or re.search(r"\+(\d+)", msg)
            if m_bean:
                res["gain_bean"] += int(m_bean.group(1))
            else:
                res["gain_bean"] += 10
        elif code in ("401", "403") or "未授权" in msg or "未登录" in msg or "失效" in msg or "过期" in msg:
            if client.ticket and client.exchange_ticket():
                print("    [ticket] 检测到旧 sign 失效，已通过 ticket 自动换取新会话，正在重试打卡...", flush=True)
                return execute_telecom_task(client)
            if (client.app_token and client.uid) and client.mint_ticket_with_token():
                print("    [token] 检测到旧 sign 失效，已用 App 长效 Token 现签换得新会话，正在重试打卡...", flush=True)
                return execute_telecom_task(client)
            if (client.phone and client.password) and client.login_with_password():
                print("    [login] 检测到旧 sign 失效，已通过服务密码自动登录换取新会话，正在重试打卡...", flush=True)
                return execute_telecom_task(client)
            if client.credential_error:
                res["status"] = "失败"
                res["error"] = (f"服务密码凭证错误（{client.credential_error}）"
                                f"——已停止当日重试以防密码锁定")
                return res
            res["status"] = "失败"
            res["error"] = f"App 会话已失效（{msg or '401 未授权访问'}），请更新 TELECOM_HEADER_1 或配置 TELECOM_PASSWORD_1"
            return res
        elif sign_res.get("_http_error") or code == "-1":
            res["status"] = "失败"
            res["error"] = f"网络请求异常（{msg or 'HTTP ' + code}）"
            return res
        else:
            res["status"] = "失败"
            res["error"] = f"签到接口异常（{msg or 'code=' + code}）"
            return res
    elif not client.sign:
        res["status"] = "失败"
        if client.mint_network_failure:
            # 现签因出口连接失败/被 WAF 拦截而未取得 sign：网络类错误，交给
            # _run_account 轮换下一代理候选（凭据本身没有问题）
            res["error"] = "网络请求异常（现签未取得 sign：出口连接失败或被 WAF 拦截）"
        else:
            res["error"] = "缺少 sign 凭据，无法完成签到"
        return res
    elif not HAS_CRYPTO:
        res["status"] = "失败"
        res["error"] = "缺少 pycryptodome 加密依赖"
        return res

    # 仅在签到成功或今日已签时，继续执行后续奖励领取与资产查询
    if res["status"] in ("成功", "今日已签"):
        # 2. 查询连签与累签进度，自动领取奖励
        if client.sign and HAS_CRYPTO:
            rsa_para: Dict[str, Any] = {"phone": client.phone} if client.phone else {}
            st_res = client._req(
                "POST",
                "https://wappark.189.cn/jt-sign/api/home/userStatusInfo",
                json_data={"para": _encrypt_rsa(rsa_para)},
                headers={"sign": client.sign},
            )
            sign_day = str(st_res.get("data", {}).get("signDay") or st_res.get("signDay") or 0)
            if sign_day.isdigit() and int(sign_day) > 0:
                res["streak_days"] = int(sign_day)
                if sign_day == "7":
                    ex_payload = {"phone": client.phone, "type": "7"} if client.phone else {"type": "7"}
                    ex_res = client._req(
                        "POST",
                        "https://wappark.189.cn/jt-sign/webSign/exchangePrize",
                        json_data={"para": _encrypt_rsa(ex_payload)},
                        headers={"sign": client.sign},
                    )
                    ex_msg = ex_res.get("msg") or ex_res.get("resoultMsg") or ""
                    print(f"    [奖励] 领取7天连签奖励: {ex_msg}", flush=True)

            cont_res = client._req(
                "POST",
                "https://wappark.189.cn/jt-sign/webSign/continueSignDays",
                json_data={"para": _encrypt_rsa(rsa_para)},
                headers={"sign": client.sign},
            )
            cont_days = str(cont_res.get("data", {}).get("continueSignDays") or cont_res.get("continueSignDays") or 0)
            if cont_days in ("15", "28"):
                ex_payload = {"phone": client.phone, "type": cont_days} if client.phone else {"type": cont_days}
                ex_res = client._req(
                    "POST",
                    "https://wappark.189.cn/jt-sign/webSign/exchangePrize",
                    json_data={"para": _encrypt_rsa(ex_payload)},
                    headers={"sign": client.sign},
                )
                ex_msg = ex_res.get("msg") or ex_res.get("resoultMsg") or ""
                print(f"    [奖励] 领取累签{cont_days}天奖励: {ex_msg}", flush=True)

        # 3. 免费金豆大转盘抽奖
        if client.authorization:
            auth_hdr = client.authorization if client.authorization.startswith("Bearer ") else f"Bearer {client.authorization}"
            tab_res = client._req(
                "GET",
                f"https://wapact.189.cn:9001/gateway/golden/api/queryTurnTable?userType=1&_={int(time.time()*1000)}",
                headers={"Authorization": auth_hdr},
            )
            if tab_res.get("code") == 0 and tab_res.get("biz", {}).get("wzTurntable", {}).get("code"):
                act_id = tab_res["biz"]["wzTurntable"]["code"]
                chk_res = client._req(
                    "GET",
                    f"https://wapact.189.cn:9001/gateway/standQuery/detail/check?activityId={act_id}",
                    headers={"Authorization": auth_hdr},
                )
                result_info = chk_res.get("biz", {}).get("resultInfo") or {}
                user_max = result_info.get("userMaximum", 0)
                user_cnt = result_info.get("userCount", 0)
                rem = max(0, user_max - user_cnt)
                lottery_prizes = []
                if rem > 0:
                    print(f"    [抽奖] 剩余可用免费抽奖机会: {rem} 次", flush=True)
                    for _ in range(min(rem, 3)):
                        time.sleep(1)
                        draw_res = client._req(
                            "POST",
                            "https://wapact.189.cn:9001/gateway/golden/api/lottery",
                            json_data={"activityId": act_id},
                            headers={"Authorization": auth_hdr},
                        )
                        p_name = (
                            draw_res.get("biz", {}).get("prizeName")
                            or draw_res.get("msg")
                            or draw_res.get("resoultMsg")
                            or ""
                        )
                        if p_name:
                            lottery_prizes.append(p_name)
                    res["lottery_res"] = "、".join(lottery_prizes) if lottery_prizes else "抽奖完成"
                else:
                    res["lottery_res"] = "今日已抽"
                    print("    [抽奖] 今日免费抽奖次数已用尽", flush=True)
            else:
                msg = tab_res.get("msg") or tab_res.get("resoultMsg") or "暂无活动"
                res["lottery_res"] = f"今日已抽({msg})" if "已" in msg else msg
                print(f"    [抽奖] 转盘响应: {msg}", flush=True)
        else:
            res["lottery_res"] = "无抽奖凭据"

        # 4. 金豆日常浏览与聚合任务
        if client.sign and HAS_CRYPTO:
            hp_payload = {"shopId": "20001", "type": "hg_qd_zrwzjd"}
            if client.phone:
                hp_payload["phone"] = client.phone
            hp_res = client._req(
                "POST",
                "https://wappark.189.cn/jt-sign/webSign/homepage",
                json_data={"para": _encrypt_rsa(hp_payload)},
                headers={"sign": client.sign},
            )
            tasks_done = 0
            ad_items = hp_res.get("data", {}).get("biz", {}).get("adItems") or []
            hp_code = str(hp_res.get("code") if hp_res.get("code") is not None else hp_res.get("resoultCode", ""))
            for t in ad_items:
                state = str(t.get("taskState"))
                if state in ("0", "1"):
                    task_id = t.get("taskId")
                    title = t.get("title", "未命名任务")
                    if task_id:
                        poly_payload = {"jobId": task_id}
                        if client.phone:
                            poly_payload["phone"] = client.phone
                        poly_res = client._req(
                            "POST",
                            "https://wappark.189.cn/jt-sign/webSign/polymerize",
                            json_data={"para": _encrypt_rsa(poly_payload)},
                            headers={"sign": client.sign},
                        )
                        r_code = str(poly_res.get("resoultCode") if poly_res.get("resoultCode") is not None else poly_res.get("code", ""))
                        r_msg = poly_res.get("resoultMsg") or poly_res.get("msg") or ""
                        if "请勿频繁点击" in r_msg:
                            time.sleep(1.5)
                            poly_res = client._req(
                                "POST",
                                "https://wappark.189.cn/jt-sign/webSign/polymerize",
                                json_data={"para": _encrypt_rsa(poly_payload)},
                                headers={"sign": client.sign},
                            )
                            r_code = str(poly_res.get("resoultCode") if poly_res.get("resoultCode") is not None else poly_res.get("code", ""))
                            r_msg = poly_res.get("resoultMsg") or poly_res.get("msg") or ""
                        if r_code in ("0", "200") or "成功" in r_msg:
                            tasks_done += 1
                            print(f"    [任务] 🎉 完成任务: {title}", flush=True)
                        time.sleep(1.2)
            if tasks_done > 0:
                res["task_res"] = f"完成{tasks_done}项"
            elif hp_code in ("0", "200") or "成功" in (hp_res.get("msg") or hp_res.get("resoultMsg") or ""):
                res["task_res"] = "今日已完成" if ad_items else "暂无待领任务"
            else:
                res["task_res"] = "今日暂无待领"
            print(f"    [任务] 任务列表扫描: 共 {len(ad_items)} 项，本次完成 {tasks_done} 项", flush=True)

        # 5. 益豆乐园喂食任务（最多 10 次）
        if client.sign and HAS_CRYPTO:
            feed_cnt = 0
            food_payload = {"phone": client.phone} if client.phone else {}
            for _ in range(10):
                feed_res = client._req(
                    "POST",
                    "https://wappark.189.cn/jt-sign/paradise/food",
                    json_data={"para": _encrypt_rsa(food_payload)},
                    headers={"sign": client.sign},
                )
                msg = feed_res.get("resoultMsg") or feed_res.get("msg") or ""
                code = str(feed_res.get("code") or "")
                if "成功" in msg or code in ("0", "200"):
                    feed_cnt += 1
                    if "最大" in msg or "上限" in msg:
                        break
                    time.sleep(0.8)
                elif "最大" in msg or "上限" in msg or "不足" in msg:
                    if feed_cnt == 0:
                        res["food_res"] = "今日已喂满"
                    break
                else:
                    if feed_cnt == 0 and msg:
                        res["food_res"] = f"跳过({msg[:15]})"
                    break
            if feed_cnt > 0:
                res["food_res"] = f"喂食{feed_cnt}次"
            elif not res["food_res"]:
                res["food_res"] = "今日已喂满"
            print(f"    [乐园] 益豆乐园喂食: {res['food_res']}", flush=True)

        # 6. 查询总资产（金豆余额）
        if client.sign and HAS_CRYPTO:
            info_payload = {"phone": client.phone} if client.phone else {}
            coin_res = client._req(
                "POST",
                "https://wappark.189.cn/jt-sign/api/home/userCoinInfo",
                json_data={"para": _encrypt_rsa(info_payload)},
                headers={"sign": client.sign},
            )
            total_bean = (
                coin_res.get("totalCoin")
                or coin_res.get("data", {}).get("totalCoin")
                or coin_res.get("coin")
            )
            if total_bean is None:
                info_res = client._req(
                    "POST",
                    "https://wappark.189.cn/jt-sign/paradise/getParadiseInfo",
                    json_data={"para": _encrypt_rsa(info_payload)},
                    headers={"sign": client.sign},
                )
                total_bean = (
                    info_res.get("data", {}).get("coin")
                    or info_res.get("data", {}).get("goldBean")
                    or info_res.get("data", {}).get("userInfo", {}).get("totalCoin")
                    or info_res.get("userInfo", {}).get("totalCoin")
                )
            if total_bean is not None:
                res["total_bean"] = str(total_bean)
                print(f"    [资产] 金豆总额: {res['total_bean']}", flush=True)
            else:
                res["total_bean"] = "查询异常"

        # 7. 目标进度计算与达标自动兑换
        if str(res["total_bean"]).isdigit():
            curr_bean = int(res["total_bean"])
            if curr_bean >= TELECOM_EXCHANGE_BEANS:
                print(f"    [目标] 🎉 金豆已达标 ({curr_bean} >= {TELECOM_EXCHANGE_BEANS})！正在执行自动兑换【{TELECOM_EXCHANGE_GOAL}】...", flush=True)
                ex_res = client.try_exchange_phone_bill(TELECOM_EXCHANGE_GOAL, TELECOM_EXCHANGE_BEANS)
                res["goal_res"] = ex_res
            else:
                diff = TELECOM_EXCHANGE_BEANS - curr_bean
                pct = round((curr_bean / TELECOM_EXCHANGE_BEANS) * 100, 1)
                res["goal_res"] = f"距离【{TELECOM_EXCHANGE_GOAL}】({TELECOM_EXCHANGE_BEANS}金豆) 还差 {diff} 金豆 (进度 {pct}%)"
                print(f"    [目标] {res['goal_res']}", flush=True)

        # 8. 天翼爱音乐「AI视频创作赢话费」（ai.imusic.cn ai119）：getSingle 现签
        # ticket 同源直接登录，月度免费生成次数用满，每次提交 +20 积分兑奖券开奖。
        # 独立子活动：任何异常只记录到 imusic_res，绝不影响主签到结果与退出码。
        if os.getenv("TELECOM_IMUSIC_DISABLE", "").strip() not in ("1", "true", "True"):
            if client.ticket and HAS_CRYPTO:
                try:
                    from imusic import run_imusic_luck

                    im = run_imusic_luck(client.http, client.ticket, client.phone)
                    parts_im = []
                    if im.get("videos"):
                        parts_im.append(f"提交{im['videos']}次生成")
                    if im.get("gain"):
                        parts_im.append(f"点数+{im['gain']}")
                    if im.get("redeemed"):
                        parts_im.append(f"已兑{im['redeemed']}")
                    if im.get("draws"):
                        parts_im.append(f"抽奖{im['draws']}次")
                    if im.get("score"):
                        parts_im.append(f"总点数{im['score']}")
                    if im.get("issue"):
                        parts_im.append(str(im["issue"]))
                    detail = "，".join(parts_im) or str(im.get("msg") or "")
                    res["imusic_res"] = f"{im.get('status')}({detail})" if detail else str(im.get("status"))
                    print(f"    [imusic] 赢花费活动: {res['imusic_res']}", flush=True)
                except Exception as im_exc:
                    res["imusic_res"] = f"跳过(异常: {type(im_exc).__name__})"
                    print(f"    [imusic] 赢花费活动异常: {im_exc}", flush=True)
            else:
                res["imusic_res"] = "跳过(无现签ticket)"
                print("    [imusic] 无现签 ticket，跳过赢花费活动", flush=True)

        # 签到成功后持久化有效会话
        client.save_session()

    return res


# ---------- 金豆商城抢兑主流程 ----------


def _jindou_next_window(now: Optional[datetime] = None) -> datetime:
    """下一个抢兑场次开抢时刻（BJT）。"""
    now = now or datetime.now(BJT)
    for h, m in JINDOU_WINDOWS:
        w = now.replace(hour=h, minute=m, second=0, microsecond=0)
        if w > now:
            return w
    return (now + timedelta(days=1)).replace(
        hour=JINDOU_WINDOWS[0][0], minute=JINDOU_WINDOWS[0][1], second=0, microsecond=0)


def _jindou_next_due(terminal: bool, now: Optional[datetime] = None) -> datetime:
    """滚动冷却（sched.type=rolling）的下次到期时刻（BJT）。

    全部时刻按北京时间场次（10:00/14:00 BJT）推算，把下次运行精确落在
    「场次前 30 分钟」，由任务内等待对齐 09:59:15 突发，不依赖心跳的半点量化：
    - terminal=True（今日终局：成功/售罄/限兑/无券/未达标）→ 明日 09:30；
    - terminal=False（暂时性失败）→ 下一个场次前 30 分钟。"""
    now = now or datetime.now(BJT)
    if terminal:
        base = (now + timedelta(days=1)).replace(
            hour=JINDOU_WINDOWS[0][0], minute=JINDOU_WINDOWS[0][1], second=0, microsecond=0)
        return base - timedelta(minutes=30)
    return _jindou_next_window(now) - timedelta(minutes=30)


def _jindou_schedule_next_run(terminal: bool) -> None:
    """把下次到期时刻写进滚动冷却状态（due = last_credit_ts + period_h*24h）。

    写入后 orchestrator 的 rolling 冷却检查会屏蔽此前的一切触发（含重试梯
    next_retry_at——plan_due_tasks 中 rolling 检查先于退避检查），从而把
    telecom-exchange 的实际运行时刻钉死在场次窗口边缘。"""
    next_due = _jindou_next_due(terminal)
    last_credit_ts = (next_due - timedelta(hours=24)).timestamp()
    prefix = os.getenv("CAT_CHECKIN_REDIS_PREFIX", "cat_checkin:").rstrip(":")
    try:
        save_kv_state(
            f"{prefix}:state:notify:telecom-exchange",
            ".notify_state_telecom-exchange.json",
            {"last_credit_ts": last_credit_ts},
        )
        print(f"    [商城] 下次运行已排定: {next_due.strftime('%Y-%m-%d %H:%M')} BJT（滚动冷却）",
              flush=True)
    except Exception as exc:
        print(f"    [商城] 排程写入失败（退回重试梯兜底）: {exc}", flush=True)


def _match_goal_goods(goal: str, goods: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """在场次商品里匹配目标话费券：标题需含目标金额（如 10元）与「话费」。

    金额用「非数字前缀 + 金额 + 元」匹配，避免 10 误中 110 元类标题。"""
    m = re.search(r"(\d+(?:\.\d+)?)\s*元", goal or "")
    if not m:
        return None
    amount = re.escape(m.group(1))
    for it in goods:
        title = str(it.get("title") or "")
        if "话费" in title and re.search(rf"(?<![0-9.]){amount}\s*元", title):
            return it
    return None


def run_jindou_exchange(
    client: TelecomClient,
    goal: str,
    target_beans: int,
    wait_for_window: bool = False,
    burst: Optional[int] = None,
) -> Tuple[bool, str]:
    """金豆商城话费券抢兑。返回 (今日是否终局, 可读结果)。

    ok=True：今日无需再试（兑换成功 / 售罄 / 限兑 / 未达标 / 今日无此券）；
    ok=False：暂时性失败（网络 / 场次未就绪 / 突发未中），由 rolling 自排程拉回场次窗口。

    突发时机：wait_for_window=True 且距下一场次 ≤35 分钟时，任务内等待至
    开抢前 JINDOU_LEAD_SECONDS 秒再连发（对齐开源抢兑脚本的预发排队策略）；
    否则立即探测执行（场次已开时列表可直接服务，错峰探测亦不空耗）。"""
    burst = burst or JINDOU_BURST
    now = datetime.now(BJT)
    window = _jindou_next_window(now)
    lead = timedelta(seconds=JINDOU_LEAD_SECONDS)
    gap = window - now
    if wait_for_window and timedelta(0) < gap <= timedelta(minutes=35) and gap > lead:
        wait_s = (gap - lead).total_seconds()
        if wait_s <= JINDOU_MAX_WAIT_SECONDS:
            print(f"    [商城] 距开抢 {int(gap.total_seconds())}s，任务内等待 "
                  f"{int(wait_s)}s 后突发提交...", flush=True)
            time.sleep(wait_s)

    token = client.jindou_unified_login()
    if not token:
        return False, "金豆商城统一登录失败（ticket 失效或网络异常）"
    balance = client.jindou_query_balance(token)
    if balance is None:
        return False, "金豆商城余额查询失败"
    if balance < target_beans:
        return True, f"金豆 {balance} 未达目标 {target_beans}，无需抢兑"

    goods, goods_err = client.jindou_fetch_goods(token)
    if goods is None:
        return False, (f"场次商品列表不可用({goods_err[:30]})——多为场次未开放，"
                       "由 telecom-exchange 任务在场次窗口(10:00/14:00 BJT)重试")
    item = _match_goal_goods(goal, goods)
    if not item:
        titles = "、".join(
            str(it.get("title") or "?") for it in goods[:6] if isinstance(it, dict)) or "无话费券"
        return True, f"今日场次无「{goal}」上架（在场: {titles}）"
    try:
        cost = int(float(str(item.get("amount") or "0")))
    except (TypeError, ValueError):
        cost = 0
    if cost and balance < cost:
        return True, f"「{item.get('title')}」需 {cost} 金豆，余额 {balance} 不足"

    activity_id = str(item.get("id") or "")
    title = str(item.get("title") or goal)
    print(f"    [商城] 目标商品: {title} ({cost}金豆) activityId={activity_id[:12]}…", flush=True)
    result_code = ""
    for attempt in range(1, burst + 1):
        r = client.jindou_exchange_once(token, activity_id)
        result_code = r["result_code"]
        if r["code"] == "0" and result_code == "0":
            print(f"    [商城] 🎉 第{attempt}发兑换成功: {title}", flush=True)
            return True, f"🎉 成功兑换【{title}】(耗 {cost} 金豆)，按活动规则到账"
        if result_code == "412":
            return True, f"兑换【{title}】已达次数上限（限兑规则），今日终止"
        if result_code == "413":
            return True, f"【{title}】已售罄（先到先得），今日终止"
        print(f"    [商城] 第{attempt}/{burst}发未中: result={result_code or r['code']} "
              f"{r['message'][:40]}", flush=True)
        time.sleep(random.uniform(2.0, 4.0))
    return False, f"「{title}」连发 {burst} 次未成功（末次: {result_code or 'HTTP错误'}）"


def run_exchange_mode() -> int:
    """TELECOM_MODE=exchange 专项任务：金豆商城话费抢兑（含场次等待与突发提交）。

    退出码语义：0=今日已终局（成功/售罄/限兑/无券/未达标），1=暂时性失败。
    结束时自写 rolling 冷却状态，把下次运行精确排到下一个场次窗口边缘
    （北京时间），全部时刻推算见 _jindou_next_due。"""
    print("【中国电信 金豆商城话费抢兑】")
    accounts = load_all_accounts()
    if not accounts:
        print("未配置电信凭据（TELECOM_HEADER_* 缺失且无本地/Redis 状态缓存）")
        return 1

    all_terminal = True
    for acc in accounts:
        print(f"\n👤 用户: 【{acc.display_name}】")
        terminal = False
        # 与 _run_account 同款出口候选：CN 家宽 → sing-box 兜底 → 直连（wapact 网关
        # 对数据中心 IP 未实测拦截，直连保底必须入队，本地无代理时唯一可用出口）
        proxy_queue: List[Optional[ProxyEndpoint]] = list(_get_candidate_proxies())
        if None not in proxy_queue:
            proxy_queue.append(None)
        for candidate in proxy_queue[:3]:
            p_url = candidate.url if candidate else ""
            label = candidate.display_name if candidate else "直连出网"
            print(f"  🌐 正在通过 [{label}] 执行抢兑...", flush=True)
            http = Http(task_name="TELECOM", proxy=p_url, follow_redirects=True, impersonate="chrome124")
            client = TelecomClient(acc, http)
            if not client.prepare_auth():
                # 现签失败多为出口网络问题（死节点吃满超时），换下一候选而非放弃
                print("    [商城] 该出口无法取得有效票据，尝试下一候选", flush=True)
                continue
            terminal, msg = run_jindou_exchange(
                client, TELECOM_EXCHANGE_GOAL, TELECOM_EXCHANGE_BEANS, wait_for_window=True)
            print(f"• 抢兑: 【{msg}】", flush=True)
            if terminal:
                break
            # 网络类暂时失败换出口重试；业务类失败（突发未中等）直接跳出等 rolling 重排
            if not ("登录失败" in msg or "余额查询失败" in msg or "列表不可用" in msg):
                break
        if not terminal:
            all_terminal = False

    # 自排程：把下次运行钉在下一个场次窗口边缘（全部账号终局→明日 09:30；
    # 存在暂时性失败→下一场次前 30 分钟）。滚动冷却优先于重试梯，杜绝心跳
    # 半点量化把突发时刻推过 10:00:00 开抢点（2026-10-31 复盘修正）。
    _jindou_schedule_next_run(all_terminal)
    return 0 if all_terminal else 1


# ---------- 账号执行与候选代理轮换 ----------


def _run_account(acc: TelecomAccount) -> Tuple[bool, Dict[str, Any]]:
    """带候选代理轮换执行单个电信账号。"""
    candidates = _get_candidate_proxies()
    proxy_queue: List[Optional[ProxyEndpoint]] = list(candidates)
    if None not in proxy_queue:
        proxy_queue.append(None)

    last_outcome: Dict[str, Any] = {}
    for candidate in proxy_queue:
        p_name = candidate.display_name if candidate else "直连出网"
        p_url = candidate.url if candidate else ""
        if candidate:
            print(f"  🌐 正在通过 CN 出口 [{p_name}] 建立连接...", flush=True)
        else:
            print(f"  🌐 正在通过 [直连出网] 建立连接...", flush=True)

        # Chrome TLS 指纹模拟：wappark 的 WAF 对数据中心/被标记 IP 上的 urllib 裸指纹
        # 返回 412（2026-09-19 CI 实测），与 smzdm 同款解法；本地家宽直连不受影响
        http = Http(task_name="TELECOM", proxy=p_url, follow_redirects=True, impersonate="chrome124")
        client = TelecomClient(acc, http)
        outcome = execute_telecom_task(client)
        last_outcome = outcome

        err = outcome.get("error", "")
        # 服务密码类硬错误：立即熔断当日重试（密码连错约 5 次会被锁定 24h，
        # 次数/退避驱动的重试梯子对此无感知，必须在此显式熔断；跨日自动归零复跑）
        if "服务密码凭证错误" in err:
            trip_circuit_breaker(
                "telecom",
                reason=f"服务密码凭证错误，停止当日重试以防密码锁定（{client.credential_error}）",
                output=err,
            )
            return False, outcome
        # 若凭据失效（401未授权等）或完全没有凭据，无需轮换代理，直接返回失败；
        # 「现签未取得 sign」的网络类失败已归因为网络请求异常，走下方轮换分支
        if "会话已失效" in err or "缺少 App 抓包凭据" in err or "pycryptodome" in err:
            return False, outcome

        # 若执行成功或今日已签，直接返回
        if outcome.get("status") in ("成功", "今日已签"):
            return True, outcome

        # 若是网络层异常或 WAF 412 拦截，继续尝试下一代理候选
        if "网络请求异常" in err or "WAF" in err or "HTTP 412" in err or "-1" in err:
            if candidate:
                print(f"  {format_dead_proxy_alert(candidate, err)}", flush=True)
            else:
                print(f"  ⚠️ 直连请求异常: {err}", flush=True)
            continue

        return False, outcome

    return False, last_outcome


# ---------- 主流程 ----------


def main() -> None:
    # 专项模式：金豆商城话费抢兑（telecom-exchange 任务），与 00:50 主签到链路分离
    if (os.getenv("TELECOM_MODE") or "").strip().lower() == "exchange":
        sys.exit(run_exchange_mode())

    print("【中国电信 签到】")
    accounts = load_all_accounts()
    if not accounts:
        print("未配置中国电信签到凭证，请在环境变量配置 TELECOM_HEADER_1（App 抓包整串）")
        print("说明：本任务采用纯 App 抓包整串鉴权模式，提取含 sign/phone 的 Header 串（约 30 天有效），免除账密风控。")
        print("详细说明参见 .env.example 中的 中国电信 配置段落。")
        sys.exit(0)

    success_cnt = 0
    total_cnt = len(accounts)

    for acc in accounts:
        print(f"\n👤 用户: 【{acc.display_name}】")
        ok, outcome = _run_account(acc)

        if not ok or outcome.get("error"):
            print(f"❌ 签到失败：{outcome.get('error', '未知异常')}")
            continue

        status_text = outcome["status"]
        parts = [f"【{status_text}】"]
        if outcome["gain_bean"]:
            parts.append(f"(+{outcome['gain_bean']} 金豆)")
        if outcome["streak_days"]:
            parts.append(f"连签天数: 【{outcome['streak_days']}】天")
        print(f"• 签到: {' '.join(parts)}")

        if outcome["lottery_res"]:
            print(f"• 抽奖: 【{outcome['lottery_res']}】")
        if outcome["task_res"]:
            print(f"• 任务: 【{outcome['task_res']}】")
        if outcome["food_res"]:
            print(f"• 乐园: 【{outcome['food_res']}】")
        if outcome["total_bean"]:
            print(f"• 资产: 金豆 【{outcome['total_bean']}】")
        if outcome.get("goal_res"):
            print(f"• 目标: 【{outcome['goal_res']}】")
        if outcome.get("imusic_res"):
            print(f"• 赢花费: 【{outcome['imusic_res']}】")

        if outcome["status"] in ("成功", "今日已签"):
            success_cnt += 1

    print(f"\n总结：成功 {success_cnt}/{total_cnt}")
    if success_cnt == 0 and total_cnt > 0:
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
