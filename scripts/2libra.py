#!/usr/bin/env python3
# cron: 45 9 * * *
# new Env("2Libra 签到")
from __future__ import annotations

import os
import re
import sys

from common import Http, env, env_seq, find, is_already_signed, bj_time_from_iso_z, main_guard, mask_str

PREFIX = "2LIBRA_"


def _load_cookies() -> list[dict]:
    """返回 [{"cookie": ..., "auth": ...}, ...]。

    序号序列（推荐）：2LIBRA_COOKIE_1, 2LIBRA_COOKIE_2...（可选配对 2LIBRA_AUTHORIZATION_1...）
    多账号旧格式：2LIBRA_COOKIES，换行或 && 分隔，每条带可选的 Authorization：
        格式为 cookie[|authorization]，如：
          cookie1
          cookie2|token2
    兼容单账号：
        2LIBRA_cookie（可选配对 2LIBRA_Authorization）
    """
    accounts: list[dict] = []

    # 1. 优先扫描序号配对的 COOKIE_1 / AUTHORIZATION_1 序列
    cookies = env_seq(PREFIX, "cookie", required=False)
    auths = env_seq(PREFIX, "authorization", required=False)
    for i in range(len(cookies)):
        c = cookies[i].strip()
        if not c:
            continue
        a = auths[i].strip() if i < len(auths) else ""
        if "|" in c:
            c_part, a_part = c.split("|", 1)
            accounts.append({"cookie": c_part.strip(), "auth": a_part.strip() or a})
        else:
            accounts.append({"cookie": c, "auth": a})

    # 2. 扫描 COOKIES 序列或兼容旧 COOKIES 变量（换行 / && 切分）
    raw_cookies = env_seq(PREFIX, "cookies", required=False)
    for chunk in raw_cookies:
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split("|", 1)
        item = {"cookie": parts[0].strip(), "auth": parts[1].strip() if len(parts) > 1 else ""}
        if not any(a["cookie"] == item["cookie"] for a in accounts):
            accounts.append(item)

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
    if sign.code == 200 and coins:
        first = f"签到成功，签到时间为：{d} {t}，本次签到获得 {coins} 金币"
    elif msg and is_already_signed(msg, ("已签", "重复")):
        # 幂等放行：仅当 msg 明确是「已签到」类语义；其余错误消息（未登录/风控等）必须红卡
        first = msg
    elif msg:
        raise RuntimeError(f"签到失败（HTTP {sign.code}）：{msg}")
    else:
        # coins 与错误消息都取不到（多为 cookie 失效返回错误页），不能当成功上报
        raise RuntimeError(f"签到结果未知（HTTP {sign.code}，响应非预期）：{sign.text[:120]}")
    line = f"{mask_str(username)}（第 {num} 号会员）\n"
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


if __name__ == "__main__":
    main_guard(main)
