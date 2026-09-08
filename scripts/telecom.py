#!/usr/bin/env python3
# cron: 0 9 * * *
# new Env("中国电信 签到")
"""中国电信（营业厅 / 天翼生活 / 10000）App 抓包纯授权签到、免费抽奖与资产统计。

模式说明：
- 纯 App 抓包整串鉴权模式：无需账密，彻底规避风控锁定与验证码。
- 提取移动端 App 或电信活动 H5 页（wappark.189.cn / wapact.189.cn）的抓包整串凭证。
- 单次抓包提取凭证有效期通常为 30 天左右，支持多账号序列按月轮转。
- 会话凭据经 Upstash Redis 与本地 KV 缓存跨 run 持久化，平滑保活。

环境变量：
- TELECOM_HEADER_1...: 抓包整串（支持含 sign / phone / Authorization 的 Header 串、query 串或 JSON）
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

from common import (
    BJT,
    Http,
    ProxyEndpoint,
    env_seq,
    get_all_proxy_endpoints,
    is_already_signed,
    load_kv_state,
    main_guard,
    mask_str,
    parse_proxies_text,
    save_kv_state,
)

# 加密库：金豆中心接口依赖 RSA-1024 与 AES-ECB
try:
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.PublicKey import RSA
    from Crypto.Util.Padding import pad

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

PREFIX = "TELECOM_"

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
        extra_headers: Optional[Dict[str, str]] = None,
    ):
        self.index = index
        self.phone = phone.strip()
        self.sign = sign.strip()
        self.authorization = authorization.strip()
        self.cookie = cookie.strip()
        self.user_agent = user_agent.strip()
        self.extra_headers = extra_headers or {}

    @property
    def display_name(self) -> str:
        if self.phone:
            return mask_str(self.phone)
        if self.sign:
            return f"账号#{self.index} ({mask_str(self.sign, keep_start=4, keep_end=4)})"
        return f"账号#{self.index}"

    def has_credentials(self) -> bool:
        return bool(self.sign or self.authorization)


def _parse_account_config(raw: str, index: int) -> TelecomAccount:
    """从抓包整串中智能解析 phone, sign, authorization, cookie, user_agent, extra_headers。"""
    raw = (raw or "").strip()
    if not raw:
        return TelecomAccount(index)

    phone = ""
    sign = ""
    auth = ""
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
        elif k_low == "x-requested-with":
            extra_headers[k.strip()] = v_val

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

    # 4. Key-Value 串或正则补充提取 sign 与 auth
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
        m_uaph = re.search(r"CtClient;[^;\r\n]+;([A-Za-z0-9+/=]+)!#!([A-Za-z0-9+/=]+)", user_agent)
        if m_uaph:
            try:
                p1 = base64.b64decode(m_uaph.group(1)).decode("utf-8")
                p2 = base64.b64decode(m_uaph.group(2)).decode("utf-8")
                if re.match(r"^1\d{10}$", p2 + p1):
                    phone = p2 + p1
                elif re.match(r"^1\d{10}$", p1 + p2):
                    phone = p1 + p2
            except Exception:
                pass

    # 8. 单值推断（仅提供 sign 或 Bearer 串）
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
        extra_headers=extra_headers,
    )


def load_all_accounts() -> List[TelecomAccount]:
    """多账号序列加载：统一按 App 抓包整串（TELECOM_HEADER_1, TELECOM_HEADER_2...）设定。"""
    accounts: List[TelecomAccount] = []
    # 逐序号直接获取环境变量，保留整串内部的换行与结构，不被通用 env_seq 误按行切分
    idx = 1
    raw_list: List[str] = []
    while True:
        val = os.getenv(f"TELECOM_HEADER_{idx}") or os.getenv(f"telecom_header_{idx}")
        if val not in (None, ""):
            raw_list.append(val)
            idx += 1
        else:
            break

    if not raw_list:
        single = os.getenv("TELECOM_HEADER", "").strip() or os.getenv("TELECOM_header", "").strip()
        if single:
            raw_list = [single]

    for idx, item in enumerate(raw_list, 1):
        acc = _parse_account_config(item, idx)
        if acc.has_credentials():
            accounts.append(acc)

    return accounts


# ---------- 电信 API 会话客户端 ----------


class TelecomClient:
    def __init__(self, account: TelecomAccount, http: Http):
        self.acc = account
        self.http = http
        self.phone = account.phone
        self.sign = account.sign
        self.authorization = account.authorization
        self.cookie = account.cookie
        self.user_agent = account.user_agent
        self.extra_headers = dict(account.extra_headers)
        self.state_file = f".telecom_state_{account.index}.json"
        self.redis_key = f"cat_checkin:state:telecom_{account.index}"

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
            return resp.json({}) if isinstance(resp.json({}), dict) else {}
        except Exception as err:
            if os.getenv("DEBUG"):
                print(f"    [DEBUG] 请求异常 {url}: {err}", flush=True)
            return {}

    def restore_cached_session(self) -> bool:
        """从 Upstash Redis 或本地状态恢复会话缓存。"""
        state = load_kv_state(self.redis_key, self.state_file)
        if not state:
            return False

        if not self.phone and state.get("phone"):
            self.phone = str(state.get("phone"))
        if not self.sign and state.get("sign"):
            self.sign = str(state.get("sign"))
        if not self.authorization and state.get("authorization"):
            self.authorization = str(state.get("authorization"))
        if not self.cookie and state.get("cookie"):
            self.cookie = str(state.get("cookie"))
        if not self.user_agent and state.get("user_agent"):
            self.user_agent = str(state.get("user_agent"))

        if self.sign or self.authorization:
            print(f"    [keepalive] 成功加载账号缓存会话 (更新于: {state.get('updated_at', '未知')})", flush=True)
            return True
        return False

    def save_session(self) -> None:
        """持久化当前可用会话凭据。"""
        state = {
            "phone": self.phone,
            "sign": self.sign,
            "authorization": self.authorization,
            "cookie": self.cookie,
            "user_agent": self.user_agent,
            "updated_at": datetime.now(BJT).strftime("%Y-%m-%d %H:%M:%S"),
        }
        save_kv_state(self.redis_key, self.state_file, state)

    def prepare_auth(self) -> bool:
        """准备可用鉴权票据：优先本地/Redis缓存 -> 验证 sign 探活。"""
        self.restore_cached_session()
        if not (self.sign or self.authorization):
            return False

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

        self.save_session()
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
        "error": "",
    }

    if not client.prepare_auth():
        res["status"] = "失败"
        res["error"] = "缺少 App 抓包凭据（请在 TELECOM_HEADER_1 配置抓包整串）"
        return res

    # 1. 执行每日签到
    if client.sign and HAS_CRYPTO:
        payload_data: Dict[str, Any] = {"date": int(time.time() * 1000)}
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
        code = sign_res.get("code")

        if is_already_signed(msg, extra_phrases=("已签", "已经签")):
            res["status"] = "今日已签"
        elif code in (0, 200, "0", "200") or "成功" in msg:
            res["status"] = "成功"
            m_bean = re.search(r"(\d+)\s*金豆", msg) or re.search(r"\+(\d+)", msg)
            if m_bean:
                res["gain_bean"] += int(m_bean.group(1))
            else:
                res["gain_bean"] += 10
        elif "未登录" in msg or "失效" in msg or "过期" in msg:
            res["status"] = "失败"
            res["error"] = f"App 会话已失效（{msg}），请更新 TELECOM_HEADER_1"
            return res
        else:
            res["status"] = f"已响应({msg[:20]})" if msg else "完成"

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
        res["lottery_res"] = "今日已抽"

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
        for t in ad_items:
            if t.get("taskState") in ("0", "1", 0, 1) and str(t.get("contentOne")) == "18":
                task_id = t.get("taskId")
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
                    if poly_res.get("code") in (0, 200, "0", "200") or "成功" in (poly_res.get("msg") or ""):
                        tasks_done += 1
                        time.sleep(1)
        if tasks_done > 0:
            res["task_res"] = f"完成{tasks_done}项"
        else:
            res["task_res"] = "今日已完成" if ad_items else "暂无待领任务"
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
            if "成功" in msg or feed_res.get("code") in (0, 200, "0", "200"):
                feed_cnt += 1
                if "最大" in msg or "上限" in msg:
                    break
                time.sleep(0.8)
            elif "最大" in msg or "上限" in msg or "不足" in msg:
                break
            else:
                break
        if feed_cnt > 0:
            res["food_res"] = f"喂食{feed_cnt}次"
        else:
            res["food_res"] = "今日已喂满"
        print(f"    [乐园] 益豆乐园喂食: {res['food_res']}", flush=True)

    # 6. 查询总资产（金豆余额）
    if client.sign and HAS_CRYPTO:
        info_payload = {"phone": client.phone} if client.phone else {}
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
        if total_bean is None:
            coin_res = client._req(
                "POST",
                "https://wappark.189.cn/jt-sign/api/home/userCoinInfo",
                json_data={"para": _encrypt_rsa(info_payload)},
                headers={"sign": client.sign},
            )
            total_bean = (
                coin_res.get("data", {}).get("totalCoin")
                or coin_res.get("data", {}).get("coin")
                or coin_res.get("totalCoin")
                or coin_res.get("coin")
            )
        if total_bean is not None:
            res["total_bean"] = str(total_bean)
            print(f"    [资产] 金豆总额: {res['total_bean']}", flush=True)
        else:
            res["total_bean"] = "同步中"

    # 最终状态收敛
    if res["status"] == "未开始":
        res["status"] = "成功" if (res["gain_bean"] or res["lottery_res"] or res["task_res"]) else "已完成"

    return res


# ---------- 主流程 ----------


def main() -> None:
    print("【中国电信 签到】")
    accounts = load_all_accounts()
    if not accounts:
        print("未配置中国电信签到凭证，请在环境变量配置 TELECOM_HEADER_1（App 抓包整串）")
        print("说明：本任务采用纯 App 抓包整串鉴权模式，提取含 sign/phone 的 Header 串（约 30 天有效），免除账密风控。")
        print("详细说明参见 .env.example 中的 中国电信 配置段落。")
        sys.exit(0)

    # 准备代理候选（按需容灾切换）
    proxies = _get_candidate_proxies()
    proxy_str = proxies[0].url if proxies else None
    if proxy_str:
        print(f"[proxy] 已加载境内 CN 代理出口: {proxies[0].name}")

    http = Http(task_name="TELECOM", proxy=proxy_str, follow_redirects=True)

    success_cnt = 0
    total_cnt = len(accounts)

    for acc in accounts:
        print(f"\n👤 用户: 【{acc.display_name}】")
        client = TelecomClient(acc, http)
        outcome = execute_telecom_task(client)

        if outcome["error"]:
            print(f"❌ 签到失败：{outcome['error']}")
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

        if "失败" not in outcome["status"]:
            success_cnt += 1

    print(f"\n总结：成功 {success_cnt}/{total_cnt}")
    if success_cnt == 0 and total_cnt > 0:
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
