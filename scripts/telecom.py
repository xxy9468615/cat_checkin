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
from datetime import datetime
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
    """获取中国电信任务可用的 CN 代理出口列表。"""
    endpoints = get_all_proxy_endpoints(task_prefix="TELECOM")
    if endpoints:
        return endpoints[:3]
    raw = (
        os.getenv("TELECOM_PROXY")
        or os.getenv("CLOUD189_PROXY")
        or os.getenv("SMZDM_PROXY")
        or os.getenv("52POJIE_PROXY")
        or os.getenv("WUAI_PROXY")
        or ""
    )
    return parse_proxies_text(raw, default_name_prefix="电信CN代理")[:3]


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

    # 7. 从 CtClient User-Agent 逆向解析手机号 (如 NTUxMTA5!#!MTc3NjI -> 17762 + 551109)
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
        # 服务密码登录返回的密码类硬错误描述（非空 = 当日须停止重试登录）
        self.credential_error = ""

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
        if not self.user_agent and state.get("user_agent"):
            self.user_agent = str(state.get("user_agent"))
        if not self.app_token and state.get("app_token"):
            self.app_token = str(state.get("app_token"))
        if not self.uid and state.get("uid"):
            self.uid = str(state.get("uid"))
        if not self.target_id and state.get("target_id"):
            self.target_id = str(state.get("target_id"))

        if self.sign or self.authorization or self.ticket or (self.phone and self.password) \
                or (self.app_token and self.uid):
            print(f"    [keepalive] 成功加载账号缓存会话 (更新于: {state.get('updated_at', '未知')})", flush=True)
            return True
        return False

    def save_session(self) -> None:
        """持久化当前可用会话凭据。"""
        state = {
            "phone": self.phone,
            "password": self.password,
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
        resp = self.http.request(
            "POST",
            APP_GETSINGLE_URL,
            data=xml,
            headers={"Content-Type": "application/xml", "User-Agent": "CtClient;10.4.1;Android;13"},
            timeout=20,
        )
        text = resp.text or ""
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

    def try_exchange_phone_bill(self, goal: str, target_beans: int) -> str:
        """金豆达标时尝试调用金豆商城/权益接口自动兑换话费。"""
        payload = {
            "phone": self.phone,
            "showType": "9003",
            "showEffect": "8",
            "czValue": "0",
        }
        res = self._req(
            "POST",
            "https://wappark.189.cn/jt-sign/paradise/receiverRights",
            json_data={"para": _encrypt_rsa(payload)},
            headers={"sign": self.sign},
        )
        msg = res.get("resoultMsg") or res.get("msg") or ""
        code = str(res.get("resoultCode") if res.get("resoultCode") is not None else res.get("code", ""))
        if code in ("0", "200") or "成功" in msg:
            return f"🎉 成功自动兑换【{goal}】: {msg}"
        return f"🎯 已达标！自动兑换响应: {msg or '已提交'}（请在电信 App 金豆商城核查到账）"

    def prepare_auth(self) -> bool:
        """准备可用鉴权票据：优先从环境变量加载，次选本地/Redis缓存。"""
        self.restore_cached_session()
        # 若持有 ticket 且 sign 缺失，尝试用 ticket 换票
        if not self.sign and self.ticket:
            self.exchange_ticket()

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

        # 若 sign 仍然缺失且无可用 ticket：优先用 App 长效 Token 现签（免密、免设备验证）
        if not self.sign and (self.app_token and self.uid):
            self.mint_ticket_with_token()

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

        # 签到成功后持久化有效会话
        client.save_session()

    return res


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
        # 若凭据失效（401未授权等）或缺少凭据，无需轮换代理，直接返回失败
        if "会话已失效" in err or "缺少" in err or "pycryptodome" in err:
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

        if outcome["status"] in ("成功", "今日已签"):
            success_cnt += 1

    print(f"\n总结：成功 {success_cnt}/{total_cnt}")
    if success_cnt == 0 and total_cnt > 0:
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
