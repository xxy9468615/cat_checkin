#!/usr/bin/env python3
# cron: 0 10 * * *
# new Env("DJI 大疆社区签到")
import hashlib
import json
import re
import sys
import time
from datetime import datetime
from http.cookiejar import CookieJar
from typing import Dict, List, Optional, Tuple

from common import (
    BJT,
    DEFAULT_UA,
    Http,
    env_seq,
    find,
    findall,
    load_kv_state,
    main_guard,
    mask_str,
    save_kv_state,
)

PREFIX = "DJI_"
BASE_URL = "https://bbs.dji.com"
ACCOUNT_URL = "https://account.dji.com"


def nowms() -> int:
    return int(time.time() * 1000)


def _parse_cookie_dict(cookie_str: str) -> Dict[str, str]:
    """解析 Cookie 字符串为字典。"""
    c_dict = {}
    for item in cookie_str.split(";"):
        item = item.strip()
        if not item or "=" not in item:
            continue
        k, v = item.split("=", 1)
        c_dict[k.strip()] = v.strip()
    return c_dict


def _format_cookie_str(c_dict: Dict[str, str]) -> str:
    """格式化 Cookie 字典为字符串。"""
    return "; ".join(f"{k}={v}" for k, v in c_dict.items())


def _merge_cookies(raw_cookie: str, jar: CookieJar) -> str:
    """合并原始 Cookie 字符串与 CookieJar 中新获得的 Set-Cookie。"""
    c_dict = _parse_cookie_dict(raw_cookie)
    for c in jar:
        if c.value:
            c_dict[c.name] = c.value
    return _format_cookie_str(c_dict)


def _has_sso_passport(cookie_str: str) -> bool:
    """检查是否包含 .dji.com 域下的 1 年期 SSO 长效通行证凭据。"""
    return "_meta_key" in cookie_str or "auth_token_code" in cookie_str


def _try_sso_exchange(h: Http, base_cookie: str) -> Tuple[bool, str, str]:
    """使用 .dji.com 域下的 SSO 通行证凭据向 account.dji.com 发起换票，换取 bbs 论坛新会话。"""
    headers = {
        "User-Agent": DEFAULT_UA,
        "Referer": f"{BASE_URL}/",
        "Cookie": base_cookie,
    }
    sso_url = (
        f"{ACCOUNT_URL}/login?appId=bbs_pro&backUrl=https%3A%2F%2Fbbs.dji.com%2F"
        f"&locale=zh_CN&mode=redirect&autologin=y&t={nowms()}"
    )
    # 1. 访问 account SSO 重定向入口
    r_sso = h.request("GET", sso_url, headers=headers, timeout=30)
    merged_cookie = _merge_cookies(base_cookie, h.jar)

    # 2. 校验换票后是否成功登录论坛
    headers["Cookie"] = merged_cookie
    r_check = h.request(
        "GET",
        f"{BASE_URL}/api/v2/users/login-info?device=desktop&t={nowms()}",
        headers=headers,
        timeout=30,
    )
    if r_check.code == 200:
        login_text = r_check.text
        uid = find(r'"id":\s*(\d+)', login_text)
        if uid:
            return True, merged_cookie, login_text
    return False, base_cookie, ""


def _run_one(raw_cookie: str, idx: int, total: int) -> Tuple[bool, str]:
    raw_cookie = raw_cookie.strip()
    if not raw_cookie:
        raise RuntimeError("Cookie 为空")

    has_sso = _has_sso_passport(raw_cookie)
    env_hash = hashlib.md5(raw_cookie.encode("utf-8")).hexdigest()
    redis_key = f"cat_checkin:state:dji_{idx}"
    state_file = f".dji_state_{idx}.json"

    # 1. 状态恢复：检查 Upstash Redis 与 本地 State
    state = load_kv_state(redis_key, state_file) or {}
    cur_cookie = raw_cookie

    if state.get("env_hash") == env_hash and state.get("cookie"):
        cur_cookie = str(state["cookie"]).strip()

    h = Http(follow_redirects=True)
    headers = {"Cookie": cur_cookie, "Referer": f"{BASE_URL}/"}

    # 2. 获取用户信息与会话探测
    r_login = h.request("GET", f"{BASE_URL}/api/v2/users/login-info?device=desktop&t={nowms()}", headers=headers, timeout=30)
    login_text = r_login.text if r_login.code == 200 else ""
    uid = find(r'"id":\s*(\d+)', login_text)
    uuid = find(r'"uuid":\s*"([^"]+)"', login_text, "")
    username = find(r'"name":\s*"([^"]+)"', login_text, "?")
    start = find(r'"credits":\s*(\d+)', login_text, "?")

    # 3. 会话过期或异常处理：若未获取到 uid，尝试利用 SSO 凭据自动换票保活
    if not uid or not uuid:
        if has_sso:
            print("🔄 论坛会话未就绪或已过期，检测到 DJI SSO 长效通行证，正在执行自动换票保活...")
            ok, new_cookie, new_login = _try_sso_exchange(h, cur_cookie)
            if not ok and cur_cookie != raw_cookie:
                # 滚动凭证换票失败时，回退到环境变量原始凭据重试
                ok, new_cookie, new_login = _try_sso_exchange(h, raw_cookie)

            if ok:
                print("✅ DJI SSO 换票成功，已自动续期论坛会话凭证")
                cur_cookie = new_cookie
                headers["Cookie"] = cur_cookie
                login_text = new_login
                uid = find(r'"id":\s*(\d+)', login_text)
                uuid = find(r'"uuid":\s*"([^"]+)"', login_text, "")
                username = find(r'"name":\s*"([^"]+)"', login_text, "?")
                start = find(r'"credits":\s*(\d+)', login_text, "?")
            else:
                if r_login.code != 200:
                    raise RuntimeError(f"获取用户信息网络异常 (HTTP {r_login.code}) 且 SSO 换票未通过: {r_login.text[:100]}")
                raise RuntimeError("Cookie 已失效，且 SSO 换票未通过，请重新登录 bbs.dji.com 更新 DJI_cookie")
        else:
            if r_login.code != 200:
                raise RuntimeError(f"获取用户信息网络异常 (HTTP {r_login.code}): {r_login.text[:100]}")
            raise RuntimeError("Cookie 失效（login-info 未返回 uid/uuid，且未提供 _meta_key 长效凭据），请更新 DJI_cookie")

    # 4. 执行每日签到
    st = h.request("GET", f"{BASE_URL}/api/v2/home/paulsigns/user?device=desktop&t={nowms()}", headers=headers, timeout=30).text
    signed = find(r'"signed":\s*(true|false)', st, "false")
    days = find(r'"days":\s*(\d+)', st, "?")
    sign_points = "0"

    if signed != "true":
        sr = h.request("POST", f"{BASE_URL}/api/v2/home/paulsigns/sign?device=desktop", headers=headers, json_data={}, timeout=30).text
        sign_points = find(r'"increased":\s*(\d+)', sr, "0")
        # 签到 POST 的响应不校验会假成功：复查签到状态，仍未签上则显式失败
        st2 = h.request("GET", f"{BASE_URL}/api/v2/home/paulsigns/user?device=desktop&t={nowms()}", headers=headers, timeout=30).text
        if find(r'"signed":\s*(true|false)', st2, "false") != "true":
            raise RuntimeError(f"签到失败：{sr[:120]}")
        signed = "true"

    # 5. 浏览空间(赚积分, 非核心签到): 海外 runner 访问国内论坛偶发慢/超时，用较短超时 + 总时长上限保护
    own_ok = False
    other_ok = 0
    browse_deadline = time.monotonic() + 60
    try:
        if uid and uuid and time.monotonic() <= browse_deadline:
            own_ok = (h.request("GET", f"{BASE_URL}/pro/user-center?uid={uid}&uuid={uuid}&do=thread", headers=headers, timeout=20).code == 200)
        if time.monotonic() <= browse_deadline:
            threads = h.request("GET", f"{BASE_URL}/api/v2/forum/thread/list?device=desktop&channel_slug=home-square-all&limit=10&offset=10&sort_type=latest_posts", headers=headers, timeout=20).text
            uids = findall(r'"author":\{"id":(\d+),"uuid":"[^"]+"', threads)
            uuids = findall(r'"author":\{"id":\d+,"uuid":"([^"]+)"', threads)
            for auid, auuid in list(zip(uids, uuids))[:10]:
                if time.monotonic() > browse_deadline:
                    break
                try:
                    if h.request("GET", f"{BASE_URL}/pro/user-center?uid={auid}&uuid={auuid}", headers=headers, timeout=20).code == 200:
                        other_ok += 1
                except Exception:
                    pass
    except Exception:
        pass

    final = h.request("GET", f"{BASE_URL}/api/v2/users/login-info?device=desktop&t={nowms()}", headers=headers, timeout=30).text
    final_credits = find(r'"credits":\s*(\d+)', final, "?")

    # 6. 持久化最新 Cookie 与会话状态至 Redis / Local State
    try:
        save_kv_state(
            redis_key,
            state_file,
            {
                "cookie": cur_cookie,
                "env_hash": env_hash,
                "uid": uid,
                "uuid": uuid,
                "username": username,
                "has_sso": has_sso,
                "updated_at": datetime.now(BJT).strftime("%Y-%m-%d %H:%M:%S"),
            },
        )
    except Exception:
        pass

    masked_user = mask_str(username)
    masked_uid = mask_str(uid)
    prefix_label = f"[{idx}/{total}] " if total > 1 else ""
    sso_tag = " | 🔑 DJI SSO 1年长效凭据 (已启用自动换票保活)" if has_sso else " | ⚠️ 纯论坛 Cookie (14天寿命，建议补充 _meta_key)"

    lines = [
        f"{prefix_label}【个人信息】用户：【{masked_user}】 UID：【{masked_uid}】{sso_tag}",
        f"任务情况：【{'已签到' if signed=='true' else '本次执行'}】 连签天数：【{days}】",
        f"签到：【{'已签到' if signed=='true' else '成功'}】 +{sign_points} | 个人空间：【{'成功' if own_ok else '失败'}】 | 他人空间：【成功{other_ok}次】",
        f"积分变化：【{start} -> {final_credits}】",
    ]
    return True, "\n".join(lines)


def main():
    print("【DJI 大疆社区签到】")
    cookies = env_seq(PREFIX, "cookie")
    total = len(cookies)
    results: List[Tuple[bool, str]] = []

    for idx, c in enumerate(cookies, 1):
        c = c.strip()
        if not c:
            continue
        try:
            ok, msg = _run_one(c, idx, total)
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

    if ok_count != total:
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
