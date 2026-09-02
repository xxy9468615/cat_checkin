#!/usr/bin/env python3
# cron: 10 9 * * *
# new Env("什么值得买 签到")
"""什么值得买（smzdm.com）每日自动签到、积分金币提取与 Cookie 滚动保活。

功能：
1. 采用移动端 App 原生签名协议签到（POST https://user-api.smzdm.com/checkin），免受 Web 端极验验证码（110202）拦截
2. 自动根据 Cookie 中的 sess 凭证计算移动端签名（MD5 sign）与安全校验码（DES-ECB sk）
3. 聚合签到基础奖励与全额奖励（POST /checkin/all_reward），非阻断拉取 VIP 权益资产（POST /vip）
4. 提取连续签到天数、本次获得积分、经验值、总积分、金币、等级
5. Upstash Redis + 本地 State 双层跨 CI 持久化（cat_checkin:state:smzdm_{idx}）与 Cookie 滚动保活
6. sess 45 天长效 Cookie 寿命推算与剩余有效天数预警（<7 天告警）
7. 多账号独立隔离运行与用户名/UID 智能脱敏，支持出口代理容灾与直连兜底

环境变量：
- SMZDM_COOKIE_1, SMZDM_COOKIE_2... (多账号序列，推荐)
- SMZDM_COOKIE / SMZDM_cookie (单账号兼容)
- SMZDM_PROXY / SMZDM_BACKUP_PROXIES / PROXY (可选代理出口)
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from common import (
    BJT,
    Http,
    env_seq,
    is_already_signed,
    load_kv_state,
    main_guard,
    mask_str,
    save_kv_state,
)

PREFIX = "SMZDM_"
WEB_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# 什么值得买 App 协议参数 (Android V11.1.90)
APP_VERSION = "11.1.90"
APP_VERSION_REV = "1190"
SIGN_KEY = "apr1$AwP!wRRT$gJ/q.X24poeBInlUJC"
SK_KEY = b"geZm53XAspb02exN"


def _generate_sk(uid: str, did: str) -> str:
    """计算 App 端安全性密钥 sk（DES-ECB + PKCS7 填充，Base64 编码）。"""
    try:
        from Crypto.Cipher import DES
        from Crypto.Util.Padding import pad

        cipher = DES.new(SK_KEY[:8], DES.MODE_ECB)
        plaintext = (str(uid) + str(did)).encode("utf-8")
        return base64.b64encode(cipher.encrypt(pad(plaintext, 8))).decode("utf-8")
    except Exception:
        return "1"


def _generate_device_id(uid: str) -> str:
    """生成与账号绑定的固定 15 位伪 IMEI 设备号，保证会话一致性。"""
    h = hashlib.md5(f"smzdm_dev_{uid}".encode("utf-8")).hexdigest()
    num_part = "".join(str(int(c, 16) % 10) for c in h[:12])
    return f"086{num_part}"


def _compute_sign(fields: Dict[str, Any], sign_key: str = SIGN_KEY) -> str:
    """计算 App 端表单签名 sign（字母序升序排列、排除空值后加盐取 MD5 大写）。"""
    pairs: List[str] = []
    for k in sorted(fields.keys()):
        v = str(fields[k]).replace(" ", "")
        if v:
            pairs.append(f"{k}={v}")
    payload = "&".join(pairs) + f"&key={sign_key}"
    return hashlib.md5(payload.encode("utf-8")).hexdigest().upper()


def _extract_jsonp(text: str) -> Dict[str, Any]:
    """安全解析 JSON 或剥离 JSONP 回调函数包裹。"""
    text = text.strip()
    if not text:
        return {}
    if text.startswith("{") and text.endswith("}"):
        try:
            return json.loads(text)
        except Exception:
            pass
    m = re.search(r"^[a-zA-Z0-9_$]+\s*\(([\s\S]*)\)\s*;?$", text)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    m_brace = re.search(r"(\{[\s\S]*\})", text)
    if m_brace:
        try:
            return json.loads(m_brace.group(1))
        except Exception:
            pass
    return {}


def _parse_cookie_dict(cookie_str: str) -> Dict[str, str]:
    """将 cookie 字符串解析为键值对字典。"""
    res: Dict[str, str] = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        res[k.strip()] = v.strip()
    return res


def _merge_cookie_str(base_cookie: str, set_cookies: List[str]) -> str:
    """合并现有 Cookie 字符串与 HTTP 响应下发的 Set-Cookie 列表。"""
    c_dict = _parse_cookie_dict(base_cookie)
    for sc in set_cookies:
        if not sc:
            continue
        first_item = sc.split(";")[0].strip()
        if "=" in first_item:
            k, v = first_item.split("=", 1)
            c_dict[k.strip()] = v.strip()
    return "; ".join(f"{k}={v}" for k, v in c_dict.items())


def _calc_cookie_expiry(cookie_str: str, state: Dict[str, Any]) -> Optional[int]:
    """推算 sess Cookie 的剩余有效天数（默认 45 天会话周期）。"""
    saved_ts = state.get("saved_ts")
    if saved_ts and isinstance(saved_ts, (int, float)):
        expire_ts = int(saved_ts) + 45 * 86400
        return max(0, int((expire_ts - time.time()) / 86400))
    return 45


def _get_candidate_proxies() -> List[str]:
    """解析候选代理列表（支持换行或逗号分隔，支持带注释）。"""
    raw = os.getenv("SMZDM_PROXY") or os.getenv("SMZDM_BACKUP_PROXIES") or os.getenv("PROXY") or ""
    res: List[str] = []
    for line in raw.replace(",", "\n").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            res.append(line)
    return res


def _post_app(
    h: Http,
    endpoint: str,
    sess: str,
    cookie_str: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Tuple[int, Dict[str, Any], str, List[str]]:
    """向什么值得买 App 端 API 发送签名 POST 请求。"""
    ts = f"{int(time.time())}000"
    fields: Dict[str, Any] = {
        "basic_v": "0",
        "f": "android",
        "time": ts,
        "v": APP_VERSION,
        "weixin": "1",
        "token": sess,
    }
    if extra:
        fields.update(extra)
    fields["sign"] = _compute_sign(fields)

    headers = {
        "User-Agent": f"smzdm_android_V{APP_VERSION} rv:{APP_VERSION_REV} (Redmi;Android10;zh)smzdmapp",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "*/*",
        "Cookie": cookie_str,
        "request_key": str(random.randint(10**15, 10**16)),
    }
    r = h.request("POST", f"https://user-api.smzdm.com{endpoint}", form=fields, headers=headers, timeout=20)
    data: Dict[str, Any] = {}
    try:
        data = r.json()
    except Exception:
        pass

    sc = r.headers.get("Set-Cookie")
    set_cookies = [sc] if isinstance(sc, str) else (sc or [])
    return r.code, data, r.text, set_cookies


def _fetch_user_current_web(h: Http, cookie: str) -> Dict[str, Any]:
    """Web 端兜底获取当前用户信息。"""
    ts = int(time.time() * 1000)
    url = f"https://zhiyou.smzdm.com/user/info/jsonp_get_current?_={ts}"
    headers = {
        "User-Agent": WEB_UA,
        "Referer": "https://zhiyou.smzdm.com/user/",
        "Accept": "*/*",
        "Cookie": cookie,
    }
    try:
        r = h.request("GET", url, headers=headers, timeout=15)
        if r.code == 200:
            return _extract_jsonp(r.text)
    except Exception:
        pass
    return {}


def _run_account(raw_cookie: str, idx: int, total: int) -> Tuple[bool, str]:
    """单账号什么值得买 App 协议签到流程。"""
    raw_cookie = raw_cookie.strip()
    if not raw_cookie:
        raise RuntimeError("Cookie 为空")

    c_dict = _parse_cookie_dict(raw_cookie)
    sess = c_dict.get("sess") or ""
    if not sess:
        raise RuntimeError("Cookie 缺少关键鉴权字段 sess，请重新从浏览器获取完整 Cookie")

    init_uid = c_dict.get("smzdm_id") or ""
    if not init_uid and "user" in c_dict:
        m_u = re.search(r"(\d+)", c_dict["user"])
        if m_u:
            init_uid = m_u.group(1)

    env_hash = hashlib.md5(raw_cookie.encode("utf-8")).hexdigest()
    redis_key = f"cat_checkin:state:smzdm_{idx}"
    state_file = f".smzdm_state_{idx}.json"

    state = load_kv_state(redis_key, state_file) or {}
    cur_cookie = raw_cookie

    # 若环境变量未变更且状态中有滚动保存的有效 cookie，则使用滚动 cookie
    if state.get("env_hash") == env_hash and state.get("cookie"):
        cur_cookie = str(state["cookie"]).strip()
        # 保持 sess 最新
        c_dict_rolled = _parse_cookie_dict(cur_cookie)
        if c_dict_rolled.get("sess"):
            sess = c_dict_rolled["sess"]

    candidate_proxies = _get_candidate_proxies()
    if not candidate_proxies:
        candidate_proxies = [""]

    h: Optional[Http] = None
    res_data: Dict[str, Any] = {}
    raw_resp_text = ""
    collected_set_cookies: List[str] = []
    used_proxy = ""

    device_id = _generate_device_id(init_uid)
    sk = _generate_sk(init_uid, device_id)
    checkin_payload = {
        "captcha": "",
        "sk": sk,
        "touchstone_event": "",
    }

    # 1. 尝试通过候选出口（代理/直连）发起 App 端原生签到
    for p in candidate_proxies:
        try:
            cur_h = Http(follow_redirects=True, proxy=p)
            code, parsed, raw_text, sc_list = _post_app(
                cur_h, "/checkin", sess, cur_cookie, extra=checkin_payload
            )
            if code == 200 and parsed:
                h = cur_h
                res_data = parsed
                raw_resp_text = raw_text
                collected_set_cookies.extend(sc_list)
                used_proxy = p
                break
            elif len(candidate_proxies) > 1:
                p_label = p if len(p) < 30 else (p[:27] + "...")
                print(f"⚠️ 代理 {p_label} 响应异常 (HTTP {code})，正在尝试备用出口...")
        except Exception as e:
            if len(candidate_proxies) > 1:
                p_label = p if len(p) < 30 else (p[:27] + "...")
                print(f"⚠️ 代理 {p_label} 连接失败 ({e})，正在尝试备用出口...")

    # 若所有代理均未接通且未尝试过直连，尝试直连兜底
    if not h and candidate_proxies != [""]:
        print("⚠️ 所有代理均未接通，正在尝试直连兜底...")
        try:
            cur_h = Http(follow_redirects=True, proxy="")
            code, parsed, raw_text, sc_list = _post_app(
                cur_h, "/checkin", sess, cur_cookie, extra=checkin_payload
            )
            if code == 200 and parsed:
                h = cur_h
                res_data = parsed
                raw_resp_text = raw_text
                collected_set_cookies.extend(sc_list)
        except Exception as e:
            raise RuntimeError(f"直连请求失败: {e}")

    if not h or not res_data:
        err_hint = raw_resp_text[:120] if raw_resp_text else "无法连接至 user-api.smzdm.com"
        raise RuntimeError(f"网络请求异常：{err_hint}")

    # 2. 非阻断拉取全额签到奖励与 VIP 用户资产详情
    vip_data: Dict[str, Any] = {}
    try:
        _post_app(h, "/checkin/all_reward", sess, cur_cookie)
    except Exception:
        pass

    try:
        _, parsed_vip, _, sc_vip = _post_app(h, "/vip", sess, cur_cookie)
        if parsed_vip:
            vip_data = parsed_vip
            collected_set_cookies.extend(sc_vip)
    except Exception:
        pass

    # 3. 提取用户信息（昵称、UID、等级）
    base_info = vip_data.get("data", {}).get("base", {}) if isinstance(vip_data.get("data"), dict) else {}
    vip_info = vip_data.get("data", {}).get("vip", {}) if isinstance(vip_data.get("data"), dict) else {}

    nickname = str(base_info.get("display_name") or "")
    smzdm_id = str(base_info.get("user_smzdm_id") or init_uid or "")

    # 若 VIP 端未获取到昵称，尝试 Web 端非阻断兜底
    if not nickname:
        user_info_web = _fetch_user_current_web(h, cur_cookie)
        u_data = user_info_web.get("data", {}) if isinstance(user_info_web, dict) else {}
        nickname = str(u_data.get("nickname") or u_data.get("smzdm_id") or init_uid or "")
        if not smzdm_id:
            smzdm_id = str(u_data.get("smzdm_id") or "")

    masked_name = mask_str(nickname, 1, 1) if nickname else f"账号 #{idx}"
    masked_id = mask_str(smzdm_id, 2, 2) if smzdm_id else "未知"

    remaining_days = _calc_cookie_expiry(cur_cookie, state)
    expiry_tag = ""
    if remaining_days is not None:
        if remaining_days < 7:
            expiry_tag = f" | ⚠️ Cookie 剩余 {remaining_days} 天（请尽快更新）"
        else:
            expiry_tag = f" | 🔑 Cookie 剩余 {remaining_days} 天"

    proxy_tag = f" | 🌐 代理出口: {used_proxy}" if used_proxy else ""
    print(f"[{idx}/{total}] 👤 用户: 【{masked_name}】 (UID: {masked_id}){expiry_tag}{proxy_tag}")

    error_code = res_data.get("error_code")
    error_msg = str(res_data.get("error_msg") or "")
    data = res_data.get("data", {}) if isinstance(res_data.get("data"), dict) else {}

    # 4. 判定签到成败与幂等
    is_success = str(error_code) == "0"
    if is_success:
        add_point = int(data.get("cpadd") or data.get("add_point") or 0)
        checkin_num = int(data.get("daily_num") or data.get("checkin_num") or 0)
        point = int(data.get("cpoints") or data.get("point") or 0)
        exp = int(data.get("cexperience") or vip_info.get("exp_current") or data.get("exp") or 0)
        gold = int(data.get("cgold") or data.get("gold") or 0)
        rank = str(vip_info.get("exp_level") or data.get("rank") or "0")
        slogan = str(data.get("slogan") or "")

        clean_slogan = re.sub(r"<[^>]+>", "", slogan).strip()

        is_already = (
            (add_point == 0 and ("已" in error_msg or not error_msg))
            or is_already_signed(error_msg, ("已签到", "今日已签", "已经签到", "请勿重复"))
            or ("已领" in clean_slogan)
            or ("已签" in clean_slogan)
        )
        status_label = "今日已签" if is_already else "成功"
        gain_part = (
            f"+{add_point} 积分"
            if add_point > 0
            else (clean_slogan if clean_slogan else ("今日已签" if is_already else "今日已领"))
        )

        print(f"• 签到: 【{status_label}】 连签天数: 【{checkin_num}】天 ({gain_part}) | 经验: 【{exp:,}】")
        print(f"• 资产: 积分 【{point:,}】 · 金币 【{gold:,}】 · 等级 【V{rank}】")

        # 5. 滚动保存状态（若有新 Set-Cookie 或更新保存时间）
        try:
            merged_cookie = _merge_cookie_str(cur_cookie, collected_set_cookies) if collected_set_cookies else cur_cookie
            save_kv_state(
                redis_key,
                state_file,
                {
                    "cookie": merged_cookie,
                    "env_hash": env_hash,
                    "nickname": nickname,
                    "smzdm_id": smzdm_id,
                    "saved_ts": int(state.get("saved_ts") or time.time()),
                    "updated_at": datetime.now(BJT).strftime("%Y-%m-%d %H:%M:%S"),
                },
            )
        except Exception:
            pass

        return True, "成功"

    # error_code != 0 时的幂等判定
    if is_already_signed(error_msg, ("已签到", "今日已签", "已经签到", "请勿重复")):
        print(f"• 签到: 【今日已签】 ({error_msg})")
        return True, "今日已签"

    # 真实失败
    err_detail = error_msg if error_msg else raw_resp_text[:120]
    raise RuntimeError(f"签到失败 [{error_code}]: {err_detail}")


def main() -> None:
    print("【什么值得买 签到】")
    raw_cookies = env_seq(PREFIX, "cookie", required=True)
    total = len(raw_cookies)
    success_count = 0
    failures: List[Tuple[int, str]] = []

    for idx, c in enumerate(raw_cookies, 1):
        try:
            ok, _ = _run_account(c, idx, total)
            if ok:
                success_count += 1
        except Exception as e:
            print(f"[{idx}/{total}] ❌ 签到失败: {e}")
            failures.append((idx, str(e)))

    print(f"\n✅ 全部 {total} 个账号处理完成 (成功 {success_count}/{total})")
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
