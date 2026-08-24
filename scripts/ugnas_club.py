#!/usr/bin/env python3
# cron: 20 9 * * *
# new Env("绿联私有云 签到")
import sys
from typing import List, Tuple

from common import Http, env_seq, must_match, main_guard

PREFIX = "UGNAS_"


def _run_one(cookie: str, idx: int, total: int) -> Tuple[bool, str]:
    r = Http().request("GET", "https://club.ugnas.com/forum.php", headers={"Cookie": cookie})
    # cookie 失效时页面无积分信息：必须显式失败，否则报告假成功
    credit_str = must_match(r'积分:\s*\d+', r.text, "积分（未提取到，可能 cookie 失效）")
    prefix_label = f"[{idx}/{total}] " if total > 1 else ""
    return True, f"{prefix_label}{credit_str}"


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
