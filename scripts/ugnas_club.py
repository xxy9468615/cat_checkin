#!/usr/bin/env python3
# cron: 20 9 * * *
# new Env("绿联私有云 签到")
import re
import sys
import time
from typing import List, Tuple

from common import Http, env_seq, load_kv_state, main_guard, must_match, save_kv_state
import cookie_validity as cv

PREFIX = "UGNAS_"
# Discuz 系论坛登录凭据 cookie（站点哈希前缀 + _auth）
AUTH_COOKIE_RE = re.compile(r"^[A-Za-z0-9]+_auth$", re.IGNORECASE)


def _run_one(cookie: str, idx: int, total: int) -> Tuple[bool, str]:
    h = Http()
    r = h.request("GET", "https://club.ugnas.com/forum.php", headers={"Cookie": cookie})
    # cookie 失效时页面无积分信息：必须显式失败，否则报告假成功
    credit_str = must_match(r'积分:\s*\d+', r.text, "积分（未提取到，可能 cookie 失效）")

    # 凭据有效期跟踪（共享引擎）：粘贴 Cookie 无到期字段时如实报「已使用 N 天」，
    # 服务端续发 *_auth（勾选自动登录/记住密码）时自动转为精确倒计时
    redis_key = f"cat_checkin:state:ugnas_club_{idx}"
    state_file = f".ugnas_club_state_{idx}.json"
    learned = cv.learn_from_jar(h.jar, credential_match=AUTH_COOKIE_RE.match)
    tracked = cv.update_state(load_kv_state(redis_key, state_file) or {}, cookie, learned)
    validity_tag = cv.tag_for(cookie, tracked, learned, credential_match=AUTH_COOKIE_RE.match)
    try:
        save_kv_state(redis_key, state_file, {**tracked, "updated_at": int(time.time())})
    except Exception:
        pass

    prefix_label = f"[{idx}/{total}] " if total > 1 else ""
    return True, f"{prefix_label}{credit_str}{validity_tag}"


def main():
    print("【绿联私有云 签到】")
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
