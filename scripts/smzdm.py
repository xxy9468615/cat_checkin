#!/usr/bin/env python3
# cron: 10 9 * * *
# new Env("什么值得买 签到")
"""什么值得买（smzdm.com）每日自动签到、积分金币提取与 Cookie 滚动保活。

功能：
1. 每日自动签到（GET https://zhiyou.smzdm.com/user/checkin/jsonp_checkin）
2. 提取连续签到天数、本次获得积分、经验值、总积分、金币、等级
3. 支持 JSONP / JSON 响应自动剥离与鲁棒解析
4. Upstash Redis + 本地 State 双层跨 CI 持久化（cat_checkin:state:smzdm_{idx}）与 Cookie 滚动保活
5. sess 45 天长效 Cookie 寿命推算与剩余有效天数预警（<7 天告警）
6. 多账号独立隔离运行与用户名/UID 智能脱敏

环境变量：
- SMZDM_COOKIE_1, SMZDM_COOKIE_2... (多账号序列，推荐)
- SMZDM_COOKIE / SMZDM_cookie (单账号兼容)
"""
from __future__ import annotations

import hashlib
import json
import os
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
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


def _extract_jsonp(text: str) -> Dict[str, Any]:
    """安全解析 JSON 或剥离 JSONP 回调函数包裹（如 jQuery1124...({...})）。"""
    text = text.strip()
    if not text:
        return {}
    if text.startswith("{") and text.endswith("}"):
        try:
            return json.loads(text)
        except Exception:
            pass
    # 尝试正则提取括号内的 JSON 结构
    m = re.search(r"^[a-zA-Z0-9_$]+\s*\(([\s\S]*)\)\s*;?$", text)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    # 兜底搜索首个大括号区域
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
    # 优先从 state["saved_ts"] 计算
    saved_ts = state.get("saved_ts")
    if saved_ts and isinstance(saved_ts, (int, float)):
        # SMZDM sess 默认 45 天 (3888000s)
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


def _fetch_user_current(h: Http, cookie: str) -> Dict[str, Any]:
    """非阻断获取什么值得买当前登录用户信息。"""
    ts = int(time.time() * 1000)
    url = f"https://zhiyou.smzdm.com/user/info/jsonp_get_current?_={ts}"
    headers = {
        "User-Agent": UA,
        "Referer": "https://zhiyou.smzdm.com/user/",
        "Accept": "*/*",
        "Cookie": cookie,
    }
    r = h.request("GET", url, headers=headers, timeout=15)
    if r.code == 200:
        return _extract_jsonp(r.text)
    return {}


def _run_account(raw_cookie: str, idx: int, total: int) -> Tuple[bool, str]:
    """单账号什么值得买签到流程。"""
    raw_cookie = raw_cookie.strip()
    if not raw_cookie:
        raise RuntimeError("Cookie 为空")

    c_dict = _parse_cookie_dict(raw_cookie)
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

    candidate_proxies = _get_candidate_proxies()
    if not candidate_proxies:
        candidate_proxies = [""]

    h: Optional[Http] = None
    r_checkin = None
    res_data: Dict[str, Any] = {}
    used_proxy = ""

    headers = {
        "User-Agent": UA,
        "Referer": "https://zhiyou.smzdm.com/user/",
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Cookie": cur_cookie,
    }

    # 1. 尝试通过候选出口（代理/直连）发起签到
    for p in candidate_proxies:
        cur_h = Http(follow_redirects=True, proxy=p)
        ts = int(time.time() * 1000)
        checkin_url = f"https://zhiyou.smzdm.com/user/checkin/jsonp_checkin?_={ts}"
        r = cur_h.request("GET", checkin_url, headers=headers, timeout=20)
        if r.code == 200:
            parsed = _extract_jsonp(r.text)
            if parsed:
                h = cur_h
                r_checkin = r
                res_data = parsed
                used_proxy = p
                break
        elif len(candidate_proxies) > 1:
            p_label = p if len(p) < 30 else (p[:27] + "...")
            print(f"⚠️ 代理 {p_label} 连接异常 (HTTP {r.code})，正在尝试备用出口...")

    if not r_checkin:
        # 若所有代理出口均失败，尝试直连兜底
        if candidate_proxies != [""]:
            print("⚠️ 所有代理均未接通，正在尝试直连兜底...")
            cur_h = Http(follow_redirects=True, proxy="")
            ts = int(time.time() * 1000)
            r = cur_h.request("GET", f"https://zhiyou.smzdm.com/user/checkin/jsonp_checkin?_={ts}", headers=headers, timeout=20)
            r_checkin = r
            res_data = _extract_jsonp(r.text)
            h = cur_h
        else:
            raise RuntimeError("网络请求异常：无法获取签到响应")

    if r_checkin.code != 200:
        raise RuntimeError(f"网络请求异常 HTTP [{r_checkin.code}]: {r_checkin.text[:100]}")

    # 2. 尝试获取用户信息（非阻断）
    user_info_resp = _fetch_user_current(h, cur_cookie) if h else {}
    user_data = user_info_resp.get("data", {}) if isinstance(user_info_resp, dict) else {}
    nickname = str(user_data.get("nickname") or user_data.get("smzdm_id") or init_uid or "")
    smzdm_id = str(user_data.get("smzdm_id") or init_uid or "")

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

    # 判定成败与幂等
    if error_code == 0:
        add_point = data.get("add_point", 0)
        checkin_num = data.get("checkin_num", 0)
        point = data.get("point", 0)
        exp = data.get("exp", 0)
        gold = data.get("gold", 0)
        rank = data.get("rank", 0)
        slogan = str(data.get("slogan") or "")

        # 整理 slogan 去除 HTML 标签
        clean_slogan = re.sub(r"<[^>]+>", "", slogan).strip()

        is_already = (add_point == 0) or ("已领" in clean_slogan) or ("已签" in clean_slogan)
        status_label = "今日已签" if is_already else "成功"
        gain_part = f"+{add_point} 积分" if add_point > 0 else (clean_slogan if clean_slogan else "今日已领")

        print(f"• 签到: 【{status_label}】 连签天数: 【{checkin_num}】天 ({gain_part}) | 经验: 【{exp:,}】")
        print(f"• 资产: 积分 【{point:,}】 · 金币 【{gold:,}】 · 等级 【V{rank}】")

        # 3. 滚动保存状态（若有新 Set-Cookie 或首次记录）
        try:
            # 捕获 Set-Cookie
            resp_set_cookies = r_checkin.headers.get("Set-Cookie")
            sc_list = [resp_set_cookies] if isinstance(resp_set_cookies, str) else (resp_set_cookies or [])
            merged_cookie = _merge_cookie_str(cur_cookie, sc_list) if sc_list else cur_cookie

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
    err_detail = error_msg if error_msg else r_checkin.text[:120]
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
