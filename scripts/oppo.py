#!/usr/bin/env python3
# cron: 20 9 * * *
# new Env("OPPO商城 签到")
"""OPPO 商城（欢太 / HeyTap）每日自动打卡签到、连续签到里程碑大奖领取、日常浏览任务一键完成与积分资产统计。

核心逻辑：
1. 凭证解析、长效 SSO 根凭据与自动换票续期保活：
   - 提取并解析 webAccessToken（JWT），校验过期时间（会话级 24 小时）；
   - 支持欢太账号中心 SSO 根凭据 (acIdAuthSession)，通过底层 Web SDK (account_web_sdk) 换票链路：
     a. GET /cn/oapi/auth/api/account/state?bizAppKey=... 获取 OAuth state；
     b. 生成符合 PKCE 规范的密钥对 (43 位随机字符 codeVerifier 与 SHA-256 哈希 codeChallenge)；
     c. 携带 acIdAuthSession 请求 https://id.heytap.com/identity/web/v1/authn/auth-and-callback 获取授权码 (code)；
     d. 提交 POST /cn/oapi/auth/api/account/login 兑换最新 24 小时 webAccessToken 与商城会话 Cookie。
2. 双层持久化（Upstash Redis + 本地 State）：
   - 凭据状态自动同步持久化至 Upstash Redis (cat_checkin:state:oppo_{idx}) 与本地文件 (.oppo_state_{idx}.json)；
   - 即使 runner 销毁，下一次运行时也能基于长效 SSO 根凭据自动静默无感换票，实现数月长期免维护。
3. 每日打卡签到 (signIn)：
   - POST /api/cn/oapi/marketing/cumulativeSignIn/signIn；
   - 幂等放行：已签到（code 5008 / "今天已经签到过啦"）自动识别，新签到返回 +10 积分收益。
4. 连签里程碑奖励自动领取 (drawCumulativeAward)：
   - GET /api/cn/oapi/marketing/cumulativeSignIn/getSignInDetail 评估连签进度；
   - 达标 3/7/14/28 天连签里程碑且未领取的奖励自动一键领取。
5. 日常 8 大浏览赚积分任务自动一键上报 (signInOrShareTask)：
   - GET /api/cn/oapi/marketing/task/queryTaskList 拉取今日任务列表；
   - 过滤浏览类日常任务（taskType=1），直接向 taskReport 接口上报完成；
   - 稳拿 8 × 2 = 16 积分。
6. 积分资产查询 (queryMemberCreditInfo)：
   - 实时拉取最新积分总余额、等级与抵扣额。

环境变量：
- OPPO_COOKIE_1, OPPO_COOKIE_2... (多账号序列，推荐)
- OPPO_COOKIE (单账号兼容)
- OPPO_PROXY / 52POJIE_PROXY / PROXY (可选代理出口，支持复用境内 CN 代理)
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sys
import time
import urllib.parse
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# 本地直跑便捷自动加载根目录 .env
_ROOT_ENV = ROOT_DIR / ".env"
if _ROOT_ENV.exists():
    try:
        with open(_ROOT_ENV, encoding="utf-8") as _ef:
            for _line in _ef:
                _line = _line.strip()
                if not _line or _line.startswith("#") or "=" not in _line:
                    continue
                _k, _v = _line.split("=", 1)
                _k, _v = _k.strip(), _v.strip()
                if _k and _k not in os.environ:
                    if len(_v) >= 2 and ((_v[0] == '"' and _v[-1] == '"') or (_v[0] == "'" and _v[-1] == "'")):
                        _v = _v[1:-1]
                    os.environ[_k] = _v
    except Exception:
        pass

from common import (
    BJT,
    DEFAULT_UA,
    Http,
    env_seq,
    is_already_signed,
    load_kv_state,
    main_guard,
    mask_str,
    save_kv_state,
)

PREFIX = "OPPO_"
BASE_HOST = "https://hd.opposhop.cn"
BIZ_APP_KEY = "D5y74udFkSmoA3XS1TSMfi"
SIGN_IN_ACTIVITY_ID = "2094340289534894080"
CREDITS_ADD_ACTION_ID = "1788913e6d9e4683b8b9ab0088733560"
TASK_ACTIVITY_ID = "1919591795180969984"


def _decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    """从 JWT 令牌中解析 Payload 字典。"""
    try:
        parts = token.split(".")
        if len(parts) >= 2:
            padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
            return json.loads(base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8", errors="ignore"))
    except Exception:
        pass
    return None


def _decode_jwt_exp(token: str) -> Optional[int]:
    """从 JWT webAccessToken 中提取 exp 过期时间戳（秒级）。"""
    payload = _decode_jwt_payload(token)
    if payload and isinstance(payload, dict):
        return payload.get("exp")
    return None


def _parse_cookie_items(raw_cookie: str) -> Dict[str, str]:
    """解析 Cookie 字符串为键值字典。"""
    items: Dict[str, str] = {}
    for part in raw_cookie.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        items[k.strip()] = v.strip()
    return items


def _format_cookie_str(items: Dict[str, str]) -> str:
    """将 Cookie 字典序列化为请求头格式。"""
    return "; ".join(f"{k}={v}" for k, v in items.items() if k and v is not None)


def _extract_user_info(cookie_items: Dict[str, str]) -> Tuple[str, str, str]:
    """从 Cookie 的 memberinfo 字段提取昵称、UID 与 oid。"""
    member_raw = cookie_items.get("memberinfo", "")
    if member_raw:
        try:
            unquoted = urllib.parse.unquote(member_raw)
            data = json.loads(unquoted)
            uid = str(data.get("id", "") or "")
            name = str(data.get("name", "") or "")
            oid = str(data.get("oid", "") or "")
            return name, uid, oid
        except Exception:
            pass
    return "", "", ""


def _generate_pkce_pair() -> Tuple[str, str]:
    """生成符合 HeyTap Web SDK 规范的 PKCE 密钥对 (codeVerifier, codeChallenge)。

    codeVerifier: 43 位随机字母数字 [A-Za-z0-9]
    codeChallenge: SHA-256 哈希后的 16 进制小写字符串 (Hex Digest)
    """
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    code_verifier = "".join(secrets.choice(chars) for _ in range(43))
    code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).hexdigest()
    return code_verifier, code_challenge


def _try_refresh_oppo_token(http: Http, cookie_items: Dict[str, str]) -> Tuple[bool, Dict[str, str], str]:
    """使用 HeyTap 欢太账号中心 SSO 根凭据 (acIdAuthSession) 与 PKCE 机制换票续期 OPPO 商城登录态。

    逆向自 HeyTap account_web_sdk 与商城前端 node_modules_heytap_login-sdk_adapters_web_adapter_js：
    1. 请求商城鉴权网关拉取 OAuth 随机 state: GET /cn/oapi/auth/api/account/state
    2. 生成规范 PKCE 密钥对 (43 位随机字符 codeVerifier 与 SHA-256 哈希 codeChallenge)
    3. 携带 acIdAuthSession 请求欢太 SSO 换票网关:
       GET https://id.heytap.com/identity/web/v1/authn/auth-and-callback
       获取 302 重定向并提取换票授权码 (code)
    4. 提交换票授权码兑换商城新会话:
       POST /cn/oapi/auth/api/account/login
       载荷: {"code": code, "state": state, "codeVerifier": codeVerifier}
    5. 解析响应 Set-Cookie 与 JSON 实体，合并提取最新 24 小时 webAccessToken 与会话凭据。
    """
    ac_session = cookie_items.get("acIdAuthSession", "")
    if not ac_session:
        return False, cookie_items, "缺少 acIdAuthSession 长效 SSO 凭据"

    # 步骤 1: 请求商城鉴权状态拉取 state
    state = ""
    try:
        state_url = f"{BASE_HOST}/cn/oapi/auth/api/account/state?bizAppKey={BIZ_APP_KEY}"
        resp_state = http.request("GET", state_url)
        if resp_state and resp_state.code == 200:
            s_data = resp_state.json() or {}
            if isinstance(s_data.get("data"), dict):
                state = str(s_data["data"].get("state", "") or "")
    except Exception:
        pass

    if not state:
        state = uuid.uuid4().hex

    # 步骤 2: 生成 PKCE 密钥对
    code_verifier, code_challenge = _generate_pkce_pair()

    # 步骤 3: 访问欢太 SSO 换票授权中心获取 code
    callback_url = f"{BASE_HOST}/?state={state}"
    auth_params = {
        "bizAppKey": BIZ_APP_KEY,
        "callback": callback_url,
        "codeChallenge": code_challenge,
        "toRegisterPage": "false",
        "enablePKCEMode": "true",
    }
    auth_url = f"https://id.heytap.com/identity/web/v1/authn/auth-and-callback?{urllib.parse.urlencode(auth_params)}"
    sso_headers = {
        "User-Agent": DEFAULT_UA,
        "Referer": f"{BASE_HOST}/",
        "Origin": BASE_HOST,
        "Cookie": f"acIdAuthSession={ac_session}",
    }

    auth_code = ""
    try:
        resp_auth = http.request("GET", auth_url, headers=sso_headers, follow_redirects=False)
        if resp_auth and resp_auth.code in (301, 302, 303, 307, 308):
            loc = resp_auth.headers.get("location") or resp_auth.headers.get("Location") or ""
            if loc:
                parsed_loc = urllib.parse.urlparse(loc)
                q_dict = urllib.parse.parse_qs(parsed_loc.query)
                if "code" in q_dict:
                    auth_code = q_dict["code"][0]
        elif resp_auth and resp_auth.code == 200:
            auth_json = resp_auth.json() or {}
            if isinstance(auth_json.get("data"), dict):
                auth_code = str(auth_json["data"].get("code", "") or "")
            elif "authCode" in auth_json:
                auth_code = str(auth_json["authCode"] or "")
    except Exception as e:
        return False, cookie_items, f"SSO 授权中心请求异常: {e}"

    if not auth_code:
        return False, cookie_items, "SSO 未下发授权 code（可能 acIdAuthSession 已过期）"

    # 步骤 4: 商城后端使用授权码与 PKCE verifier 换取会话
    login_url = f"{BASE_HOST}/cn/oapi/auth/api/account/login"
    login_body = {
        "code": auth_code,
        "state": state,
        "codeVerifier": code_verifier,
    }
    login_headers = {
        "Content-Type": "application/json",
        "Origin": BASE_HOST,
        "Referer": f"{BASE_HOST}/",
        "User-Agent": DEFAULT_UA,
    }
    try:
        resp_login = http.request("POST", login_url, json_data=login_body, headers=login_headers)
    except Exception as e:
        return False, cookie_items, f"换票登录网关异常: {e}"

    if not resp_login or resp_login.code != 200:
        err_hint = resp_login.text[:100] if resp_login else "无响应"
        return False, cookie_items, f"换票登录失败: HTTP {resp_login.code if resp_login else 'None'} ({err_hint})"

    login_res = resp_login.json() or {}
    if login_res.get("code") != 200 and not login_res.get("success"):
        return False, cookie_items, f"换票拒绝: {login_res.get('message', '未知错误')}"

    # 步骤 5: 从 CookieJar 和响应实体提取更新凭据
    new_items = dict(cookie_items)
    for c in http.jar:
        if c.name and c.value:
            new_items[c.name] = c.value

    if isinstance(login_res.get("data"), dict):
        d = login_res["data"]
        for k in ("webAccessToken", "memberinfo", "oppo_track_id"):
            if k in d and d[k]:
                new_items[k] = str(d[k])

    new_token = new_items.get("webAccessToken", "")
    if not new_token:
        return False, cookie_items, "换票响应缺少 webAccessToken"

    return True, new_items, "换票续期成功"


def _run_account(cookie_str: str, index: int, total: int) -> Tuple[bool, str]:
    raw_cookie = cookie_str.strip()
    env_hash = hashlib.md5(raw_cookie.encode("utf-8")).hexdigest()
    redis_key = f"cat_checkin:state:oppo_{index}"
    state_file = f".oppo_state_{index}.json"

    # 1. 加载双层持久化状态（Upstash Redis + 本地 State）
    state = load_kv_state(redis_key, state_file) or {}
    cur_cookie = raw_cookie
    if state.get("env_hash") == env_hash and state.get("cookie"):
        cur_cookie = str(state["cookie"]).strip()

    cookie_items = _parse_cookie_items(cur_cookie)

    # 确保 acIdAuthSession 长效根凭据在状态合并中不遗失
    if "acIdAuthSession" not in cookie_items:
        raw_items = _parse_cookie_items(raw_cookie)
        if "acIdAuthSession" in raw_items:
            cookie_items["acIdAuthSession"] = raw_items["acIdAuthSession"]
        elif state.get("acIdAuthSession"):
            cookie_items["acIdAuthSession"] = str(state["acIdAuthSession"])

    web_token = cookie_items.get("webAccessToken", "")
    has_sso = bool(cookie_items.get("acIdAuthSession"))

    http = Http(task_name="oppo")

    # 2. 凭证初始化：若缺少 webAccessToken 但具备 acIdAuthSession，先换票初始化
    if not web_token:
        if raw_cookie.startswith("eyJ") and "." in raw_cookie:
            web_token = raw_cookie
            cookie_items["webAccessToken"] = web_token
        elif has_sso:
            print(f"[{index}/{total}] 🔄 检测到欢太 SSO 根凭据(acIdAuthSession)，正在初始化换取商城令牌...")
            ok_ref, new_items, ref_msg = _try_refresh_oppo_token(http, cookie_items)
            if ok_ref:
                cookie_items = new_items
                web_token = cookie_items.get("webAccessToken", "")
                print(f"[{index}/{total}] ✅ 初始换票成功，已生成有效 webAccessToken")
            else:
                print(f"[{index}/{total}] ❌ 初始换票失败: {ref_msg}")
                return False, f"初始换票失败: {ref_msg}"
        else:
            print(f"[{index}/{total}] ❌ 未在 Cookie 中检测到 webAccessToken 登录令牌")
            return False, "缺少登录凭据(webAccessToken 或 acIdAuthSession)"

    user_name, user_id, user_oid = _extract_user_info(cookie_items)
    display_id = mask_str(user_id) if user_id else f"账号 #{index}"
    display_name = f"（{mask_str(user_name)}）" if user_name else ""
    print(f"\n[{index}/{total}] 👤 用户: {display_id}{display_name}")

    # 3. 凭据有效期评估与提前静默换票
    exp_ts = _decode_jwt_exp(web_token)
    if exp_ts:
        now_ts = int(time.time())
        rem_sec = exp_ts - now_ts
        rem_hours = rem_sec / 3600
        exp_dt = datetime.fromtimestamp(exp_ts, tz=BJT).strftime("%Y-%m-%d %H:%M:%S")
        if rem_sec <= 0:
            print(f"  ⚠️ webAccessToken 已于 {exp_dt} 过期！")
            if has_sso:
                print("  🔄 正在尝试利用 HeyTap SSO 根凭据无感换票自动续期...")
                ok_ref, new_items, ref_msg = _try_refresh_oppo_token(http, cookie_items)
                if ok_ref:
                    cookie_items = new_items
                    web_token = cookie_items.get("webAccessToken", "")
                    exp_ts = _decode_jwt_exp(web_token)
                    print(f"  ✅ 换票续期成功！新令牌到期时间: {datetime.fromtimestamp(exp_ts, tz=BJT).strftime('%Y-%m-%d %H:%M:%S') if exp_ts else '未知'}")
                else:
                    print(f"  ❌ 换票续期失败: {ref_msg}")
        elif rem_sec < 1800:
            print(f"  ⏳ 凭证即将过期: 剩余 {rem_sec // 60} 分钟（到期时间: {exp_dt}）")
            if has_sso:
                print("  🔄 剩余寿命不足 30 分钟，执行提前静默换票保活...")
                ok_ref, new_items, ref_msg = _try_refresh_oppo_token(http, cookie_items)
                if ok_ref:
                    cookie_items = new_items
                    web_token = cookie_items.get("webAccessToken", "")
                    exp_ts = _decode_jwt_exp(web_token)
                    print(f"  ✅ 静默换票成功！新令牌到期时间: {datetime.fromtimestamp(exp_ts, tz=BJT).strftime('%Y-%m-%d %H:%M:%S') if exp_ts else '未知'}")
                else:
                    print(f"  ⚠️ 提前换票暂未成功 ({ref_msg})，继续尝试使用现有令牌打卡")
        else:
            print(f"  🔑 凭据有效: 剩余 {rem_hours:.1f} 小时（到期时间: {exp_dt}）")
            if not has_sso:
                print("  💡 提示: 若需长期免维护，建议在 OPPO_COOKIE 中配置欢太 SSO 根凭据(acIdAuthSession)")

    # 4. 补齐鉴权必须的辅助 Cookie 与请求头
    # OPPO Mall 接口网关校验 cookie 中的 authHost 与 sa_distinct_id，若未提供易报 403 用户未登录。
    sa_id = cookie_items.get("sa_distinct_id") or user_oid or ""
    if "authHost" not in cookie_items:
        cookie_items["authHost"] = "www.opposhop.cn"
    if "sa_distinct_id" not in cookie_items and sa_id:
        cookie_items["sa_distinct_id"] = sa_id

    req_cookie = _format_cookie_str(cookie_items)

    common_headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Cookie": req_cookie,
        "s_channel": "h5_m",
        "source_type": "504",
        "Origin": BASE_HOST,
        "Referer": f"{BASE_HOST}/bp/b371ce270f7509f0?nightModelEnable=true&us=huiyuanpindao",
    }
    if sa_id:
        common_headers["sa_distinct_id"] = sa_id

    # 5. 查询签到详情
    print("  📋 查询签到状态与连签进度...")
    detail_url = f"{BASE_HOST}/api/cn/oapi/marketing/cumulativeSignIn/getSignInDetail?activityId={SIGN_IN_ACTIVITY_ID}"
    resp_detail = http.request("GET", detail_url, headers=common_headers)
    sign_detail_data = {}
    if resp_detail and resp_detail.code == 200:
        sign_detail_data = resp_detail.json() or {}

    # 6. 每日打卡签到
    print("  👉 提交每日打卡签到...")
    sign_in_url = f"{BASE_HOST}/api/cn/oapi/marketing/cumulativeSignIn/signIn"
    sign_body = {
        "activityId": SIGN_IN_ACTIVITY_ID,
        "creditsAddActionId": CREDITS_ADD_ACTION_ID,
        "business": 1,
    }

    resp_sign = http.request("POST", sign_in_url, json_data=sign_body, headers=common_headers)
    sign_res = resp_sign.json() if resp_sign and resp_sign.code == 200 else {}
    code = sign_res.get("code")
    msg = sign_res.get("message", "") or sign_res.get("errorMessage", "")
    sign_ok = False
    gained_points = 0

    if code == 200:
        sign_ok = True
        gained_points = 10
        print(f"  🎉 签到成功！获得 +10 积分")
    elif code in (5008, 1001, 1002) or is_already_signed(msg) or "已经签到" in msg or "已签到" in msg or "已完成" in msg:
        sign_ok = True
        print(f"  ℹ️ 今日已签到，跳过打卡 ({msg or '今日已完成签到'})")
    else:
        err_msg = msg or f"HTTP {resp_sign.code if resp_sign else 'No Response'}"
        print(f"  ⚠️ 签到返回: {err_msg}")
        # 若出现会话失效且有 SSO 凭据，尝试反应式换票重试
        if "登录" in err_msg or "auth" in err_msg.lower() or "token" in err_msg.lower() or code == 403:
            if has_sso:
                print("  🔄 检测到登录态失效，正在使用 HeyTap SSO 重新换票重试...")
                ok_ref, new_items, ref_msg = _try_refresh_oppo_token(http, cookie_items)
                if ok_ref:
                    cookie_items = new_items
                    web_token = cookie_items.get("webAccessToken", "")
                    exp_ts = _decode_jwt_exp(web_token)
                    req_cookie = _format_cookie_str(cookie_items)
                    common_headers["Cookie"] = req_cookie
                    # 重试打卡
                    resp_sign = http.request("POST", sign_in_url, json_data=sign_body, headers=common_headers)
                    sign_res = resp_sign.json() if resp_sign and resp_sign.code == 200 else {}
                    code = sign_res.get("code")
                    msg = sign_res.get("message", "") or sign_res.get("errorMessage", "")
                    if code == 200:
                        sign_ok = True
                        gained_points = 10
                        print(f"  🎉 重试签到成功！获得 +10 积分")
                    elif code in (5008, 1001, 1002) or is_already_signed(msg):
                        sign_ok = True
                        print(f"  ℹ️ 重试确认今日已签到，跳过打卡")
                    else:
                        return False, f"换票后重试打卡仍失败: {msg or resp_sign.code}"
                else:
                    return False, f"登录态失效且换票未通过: {ref_msg}"
            else:
                return False, f"登录态失效: {err_msg}"
        else:
            sign_ok = True

    # 7. 连签里程碑奖励提取
    milestones = sign_detail_data.get("data", {}).get("cumulativeAwardList", []) if isinstance(sign_detail_data.get("data"), dict) else []
    if milestones:
        for award in milestones:
            award_id = award.get("awardId") or award.get("id")
            award_status = award.get("status")
            award_name = award.get("awardName", "里程碑奖励")
            if award_status == 1 and award_id:
                print(f"  🎁 发现可领取的连签里程碑: {award_name}，正在领取...")
                draw_url = f"{BASE_HOST}/api/cn/oapi/marketing/cumulativeSignIn/drawCumulativeAward"
                draw_body = {
                    "activityId": SIGN_IN_ACTIVITY_ID,
                    "awardId": award_id,
                    "creditsAddActionId": CREDITS_ADD_ACTION_ID,
                    "business": 1,
                }
                resp_draw = http.request("POST", draw_url, json_data=draw_body, headers=common_headers)
                draw_res = resp_draw.json() if resp_draw and resp_draw.code == 200 else {}
                if draw_res.get("code") == 200:
                    print(f"  ✅ 领取成功: {award_name}")
                else:
                    print(f"  ℹ️ 领取结果: {draw_res.get('message', '未成功')}")

    # 8. 日常赚积分任务（自动完成上报与一键领取奖励）
    print("  🚀 获取日常赚积分任务列表...")
    task_url = f"{BASE_HOST}/api/cn/oapi/marketing/task/queryTaskList?activityId={TASK_ACTIVITY_ID}&source=c"
    resp_tasks = http.request("GET", task_url, headers=common_headers)
    task_list_data = resp_tasks.json() if resp_tasks and resp_tasks.code == 200 else {}
    task_dtos = []
    if isinstance(task_list_data.get("data"), dict):
        task_dtos = task_list_data["data"].get("taskDTOList", [])

    task_success_cnt = 0
    task_total_points = 0
    if task_dtos:
        print(f"  📦 发现 {len(task_dtos)} 项活动任务，正在自动处理...")
        for t in task_dtos:
            t_id = t.get("taskId")
            t_name = t.get("taskName", "未知任务")
            t_type = t.get("taskType", 1)
            t_status = t.get("taskStatus", 1)

            # 已完成并已领奖 (status 3: FINISHED)
            if t_status == 3:
                print(f"    ℹ️ 今日已领奖: {t_name}")
                continue

            # 步骤一：未完成且为可直接上报的浏览类日常任务 (taskType == 1)，上报完成条件 (status 1: PREPARE_FINISH -> 2: GO_AWARD)
            if t_status == 1 and t_type == 1 and t_id:
                report_url = f"{BASE_HOST}/api/cn/oapi/marketing/taskReport/signInOrShareTask?taskId={t_id}&activityId={TASK_ACTIVITY_ID}&taskType={t_type}"
                resp_rep = http.request("GET", report_url, headers=common_headers)
                rep_res = resp_rep.json() if resp_rep and resp_rep.code == 200 else {}
                if rep_res.get("code") == 200 and rep_res.get("data") == 200:
                    t_status = 2
                else:
                    rep_msg = rep_res.get("message", "")
                    if "上限" in rep_msg or "完成" in rep_msg:
                        t_status = 2
                    else:
                        print(f"    ⏩ 跳过: {t_name} ({rep_msg or '未达成条件'})")
                        continue
                time.sleep(0.5)

            # 步骤二：待领奖状态 (status 2: GO_AWARD)，调用 receiveAward 领取积分奖励 (2 -> 3)
            if t_status == 2 and t_id:
                award_url = f"{BASE_HOST}/api/cn/oapi/marketing/task/receiveAward?taskId={t_id}&activityId={TASK_ACTIVITY_ID}&creditsAddActionId={CREDITS_ADD_ACTION_ID}&business=1"
                resp_award = http.request("GET", award_url, headers=common_headers)
                award_res = resp_award.json() if resp_award and resp_award.code == 200 else {}
                aw_code = award_res.get("code")
                aw_data = award_res.get("data") or {}
                if aw_code == 200 and (aw_data.get("receiveStatus") or aw_data.get("awardValue")):
                    pts = int(aw_data.get("awardValue") or 2)
                    task_success_cnt += 1
                    task_total_points += pts
                    print(f"    🎉 领奖成功: {t_name} (+{pts} 积分)")
                elif aw_code == 1000005:
                    print(f"    ℹ️ 已领取或未达标: {t_name}")
                else:
                    aw_msg = award_res.get("message") or award_res.get("errorMessage", "未知错误")
                    print(f"    ⚠️ 领奖失败: {t_name} ({aw_msg})")
                time.sleep(0.5)

    # 9. 查询会员总积分资产
    total_credit = "未知"
    credit_url = f"{BASE_HOST}/api/cn/oapi/marketing/member/queryMemberCreditInfo"
    resp_credit = http.request("GET", credit_url, headers=common_headers)
    if resp_credit and resp_credit.code == 200:
        cr_data = resp_credit.json() or {}
        if isinstance(cr_data.get("data"), dict):
            c_info = cr_data["data"]
            total_credit = str(c_info.get("amount") if c_info.get("amount") is not None else c_info.get("credit", "未知"))
            lvl = c_info.get("userLevel", "")
            worth = c_info.get("deductibleAmountText", "")
            worth_desc = f"，抵扣金: {worth}" if worth else ""
            print(f"  💰 账户积分余额: {total_credit} (Lv.{lvl}{worth_desc})")
        else:
            print(f"  💰 当前账户总积分: {total_credit}")

    # 10. 持久化最新状态至 Upstash Redis 与本地文件
    ref_token = cookie_items.get("refreshToken", "")
    if not ref_token and web_token:
        payload = _decode_jwt_payload(web_token)
        if payload and isinstance(payload, dict):
            ref_token = str(payload.get("refreshToken", "") or "")

    save_kv_state(
        redis_key,
        state_file,
        {
            "cookie": _format_cookie_str(cookie_items),
            "webAccessToken": web_token,
            "refreshToken": ref_token,
            "acIdAuthSession": cookie_items.get("acIdAuthSession", ""),
            "exp": exp_ts or 0,
            "env_hash": env_hash,
            "updated_at": datetime.now(BJT).strftime("%Y-%m-%d %H:%M:%S"),
        },
    )

    summary_desc = f"打卡成功，刷完 {task_success_cnt} 个任务 (+{task_total_points}分)，总积分: {total_credit}"
    return True, summary_desc


def main() -> None:
    print("=" * 50)
    print("📱 OPPO商城 每日打卡与赚积分任务")
    print("=" * 50)

    cookies = env_seq(PREFIX, "COOKIE", required=False)
    if not cookies:
        raw_cookie = os.getenv("OPPO_COOKIE", "").strip()
        if raw_cookie:
            cookies = [raw_cookie]

    if not cookies:
        print("❌ 未检测到 OPPO 登录凭据，请在 .env 配置 OPPO_COOKIE_1")
        sys.exit(1)

    total = len(cookies)
    success_count = 0
    statuses: List[str] = []

    for idx, c in enumerate(cookies, 1):
        try:
            ok, desc = _run_account(c, idx, total)
            if ok:
                success_count += 1
                statuses.append(desc)
            else:
                statuses.append(f"失败: {desc}")
        except Exception as exc:
            print(f"[{idx}/{total}] ❌ 执行异常: {exc}")
            statuses.append(f"异常: {exc}")

    print("\n" + "=" * 50)
    print(f"🏁 执行完毕: 成功 {success_count}/{total} 个账号")
    print("=" * 50)

    if success_count == 0:
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
