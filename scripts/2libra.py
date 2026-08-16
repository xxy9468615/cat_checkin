#!/usr/bin/env python3
# cron: 45 9 * * *
# new Env("2Libra 签到")
from __future__ import annotations

import os
import re
import sys

from common import Http, env, find, bj_time_from_iso_z, main_guard

PREFIX = "2LIBRA_"


def _load_cookies() -> list[dict]:
    """返回 [{"cookie": ..., "auth": ...}, ...]。

    多账号（推荐）：QL_2LIBRA_COOKIES，& 或换行或 && 分隔，每条带可选的 Authorization：
        格式为 cookie[|authorization]，如：
          cookie1
          cookie2|token2
    兼容单账号：
        QL_2LIBRA_cookie（可选配对 QL_2LIBRA_Authorization）
    """
    raw = os.getenv(f"{PREFIX}COOKIES", "").strip()
    accounts = []
    if raw:
        for chunk in re.split(r"\n|&&", raw):
            chunk = chunk.strip()
            if not chunk:
                continue
            parts = chunk.split("|", 1)
            accounts.append({"cookie": parts[0].strip(), "auth": parts[1].strip() if len(parts) > 1 else ""})

    # 兼容单账号环境变量
    cookie = env(PREFIX, "cookie", required=False)
    if cookie and not any(a["cookie"] == cookie for a in accounts):
        auth = env(PREFIX, "Authorization", default="", required=False)
        accounts.append({"cookie": cookie, "auth": auth})

    return accounts


def _run_one(cookie: str, auth: str) -> str:
    headers = {"Cookie": cookie, "Referer": "https://2libra.com/", "Origin": "https://2libra.com"}
    if auth:
        headers["Authorization"] = auth
    h = Http()
    sign = h.request("POST", "https://2libra.com/api/sign", headers=headers)
    coins = find(r'(?<="coins":)\d+(?=[,}])', sign.text)
    info = h.request("GET", "https://2libra.com/api/users/info?fields=info%2Cexp%2Ccoins", headers=headers).text
    stats = h.request("GET", "https://2libra.com/api/sign/stats", headers=headers).text
    username = find(r'(?<="username":").*?(?=")', info, "?")
    num = find(r'(?<="user_number":").*?(?=")', info, "?")
    cur = find(r'(?<="currentExp":)\d+(?=[,}])', info, "?")
    nxt = find(r'(?<="expToNext":)\d+(?=[,}])', info, "?")
    bal = find(r'(?<="coins":)\d+(?=[,}])', info, "?")
    lvl = find(r'(?<="exp":\{"level":)\d+(?=[,}])', info, "?")
    streak = find(r'(?<="streak":)\d+(?=[,}])', stats, "?")
    isotime = find(r'(?<=")\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z(?=")', stats)
    d, t = bj_time_from_iso_z(isotime) if isotime else ("", "")
    msg = find(r'(?<="m":").*?(?=")', sign.text)
    if coins:
        first = f"签到成功，签到时间为：{d} {t}，本次签到获得 {coins} 金币"
    elif msg:
        first = msg
    else:
        # coins 与错误消息都取不到（多为 cookie 失效返回错误页），不能当成功上报
        raise RuntimeError(f"签到结果未知（响应非预期）：{sign.text[:120]}")
    line = f"{username}（第 {num} 号会员）\n"
    line += first
    line += f"\n当前金币总数为 {bal} 个，已累计签到 {streak} 天\n当前用户等级为 {lvl} 级，经验值为 {cur} 点，距离升级还差 {nxt} 点"
    return line


def main():
    accounts = _load_cookies()
    if not accounts:
        raise RuntimeError(f"未配置 {PREFIX}COOKIES 或 {PREFIX}cookie")

    print("【2Libra 签到】")
    print(f"共 {len(accounts)} 个账号")
    results = []
    for idx, acc in enumerate(accounts, 1):
        try:
            line = _run_one(acc["cookie"], acc.get("auth", ""))
            print(f"[{idx}/{len(accounts)}] {line}")
            results.append((True, line))
        except Exception as e:
            line = f"[{idx}/{len(accounts)}] 签到失败：{e}"
            print(line)
            results.append((False, line))

    ok = sum(1 for ok_flag, _ in results if ok_flag)
    print(f"\n========== 签到总结 ==========\n成功 {ok}/{len(accounts)}")
    if ok != len(accounts):
        sys.exit(1)


main_guard(main)
