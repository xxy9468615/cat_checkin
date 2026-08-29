#!/usr/bin/env python3
# cron: 45 9 * * *
# new Env("2Libra 签到")
"""2Libra (2libra.com) 每日签到 + Cookie 自带保活。

保活机制（2026-08-29 协议逆向：POST /api/auth/refresh）：
- access_token 为 60 天期 JWT（浏览器 Cookie 表里的过期时间只是文件保存期限，与登录态无关）；
  refresh_token 为一次性消费票据：每次成功换新通过 Set-Cookie 下发全新
  access_token + refresh_token，旧 refresh_token 立即作废。
- 脚本每次运行优先使用滚动 state（.2libra_state_{idx}.json + Upstash Redis
  cat_checkin:state:2libra_{idx}）中最新换新的完整 Cookie；当 access_token
  距到期不足 REFRESH_AHEAD_DAYS 天时自动调用 /api/auth/refresh 换新，
  并第一时间持久化响应中的新票据（一次性票据，丢失即断链、需重新登录）。
- env_hash（md5）更新感知：用户更新 Secrets 后自动优先使用最新环境变量 Cookie。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime

from common import (
    BJT,
    Http,
    env,
    env_seq,
    find,
    is_already_signed,
    bj_time_from_iso_z,
    load_kv_state,
    main_guard,
    mask_str,
    save_kv_state,
)

PREFIX = "2LIBRA_"
REFRESH_AHEAD_DAYS = 14  # access_token 剩余有效期低于该天数时自动换新


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


def _merge_cookies(base: str, jar) -> str:
    """合并已有 Cookie 串与 urllib CookieJar 中的最新 Set-Cookie（同名覆盖）。"""
    cookie_dict: dict[str, str] = {}
    if base:
        for part in base.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k.strip():
                    cookie_dict[k.strip()] = v.strip()
    for c in jar or ():
        if getattr(c, "name", None) and getattr(c, "value", None):
            cookie_dict[c.name] = c.value
    return "; ".join(f"{k}={v}" for k, v in cookie_dict.items())


def _cookie_get(cookie_str: str, name: str) -> str:
    m = re.search(rf"(?:^|;\s*){re.escape(name)}=([^;]+)", cookie_str or "")
    return m.group(1).strip() if m else ""


def _jwt_exp(token: str):
    """解析 JWT payload 的 exp（epoch 秒）；非 JWT 或解析失败返回 None。"""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return int(json.loads(base64.urlsafe_b64decode(payload)).get("exp") or 0) or None
    except Exception:
        return None


def _save_state(redis_key: str, state_file: str, cookie: str, env_hash: str) -> None:
    save_kv_state(
        redis_key,
        state_file,
        {
            "cookie": cookie,
            "env_hash": env_hash,
            "updated_at": datetime.now(BJT).strftime("%Y-%m-%d %H:%M:%S"),
        },
    )


def _keepalive_refresh(base: str, redis_key: str, state_file: str, env_hash: str, label: str) -> str:
    """保活：access_token 快到期时用 refresh_token 换新并立即持久化新票据。

    /api/auth/refresh 为一次性消费：成功即通过 Set-Cookie 下发全新
    access_token + refresh_token，旧 refresh_token 立即作废——换新成功后必须
    最先持久化再继续；失败则沿用当前 access_token（JWT 无状态，到期前仍可用）。
    """
    at = _cookie_get(base, "access_token")
    exp = _jwt_exp(at)
    if exp:
        days = (exp - time.time()) / 86400
        if days >= REFRESH_AHEAD_DAYS:
            return base
        print(f"{label} [keepalive] access_token 仅剩 {days:.1f} 天到期，尝试 refresh_token 换新...")
    elif not _cookie_get(base, "refresh_token"):
        return base  # 无 access_token/refresh_token 可保活
    h = Http()
    r = h.request(
        "POST",
        "https://2libra.com/api/auth/refresh",
        headers={"Cookie": base, "Referer": "https://2libra.com/", "Origin": "https://2libra.com"},
        json_data={},
    )
    if r.code not in (200, 201):
        print(f"{label} [keepalive] ⚠️ token 换新失败（HTTP {r.code}）——当前 access_token 到期前仍可签到，请尽快重新登录更新 Cookie")
        return base
    merged = _merge_cookies(base, h.jar)
    # 一次性票据：先持久化再继续签到，持久化失败必须显著告警（链路可能已断）
    try:
        _save_state(redis_key, state_file, merged, env_hash)
    except Exception as exc:
        print(f"{label} [keepalive] 🚨 换新结果持久化失败（{exc}）——本次运行会用新 token，下次运行可能需重新登录")
        return merged
    new_exp = _jwt_exp(_cookie_get(merged, "access_token"))
    exp_desc = datetime.fromtimestamp(new_exp, BJT).strftime("%Y-%m-%d %H:%M:%S") if new_exp else "?"
    print(f"{label} [keepalive] ✅ token 已换新并持久化，新 access_token 到期 {exp_desc} BJT")
    return merged


def _run_one(raw_cookie: str, auth: str, idx: int = 1, total: int = 1) -> str:
    state_file = f".2libra_state_{idx}.json"
    redis_key = f"cat_checkin:state:2libra_{idx}"
    saved = load_kv_state(redis_key, state_file) or {}
    saved_cookie = str(saved.get("cookie") or "").strip()
    saved_env_hash = str(saved.get("env_hash") or "").strip()
    env_hash = hashlib.md5(raw_cookie.encode("utf-8")).hexdigest() if raw_cookie else ""

    # 滚动 state 优先（含保活换新的最新票据）；用户更新 Secrets（env_hash 变化）时新 env 优先
    if raw_cookie and saved_cookie and env_hash and env_hash != saved_env_hash:
        print(f"[{idx}/{total}] 🆕 检测到环境变量 Cookie 已更新，优先使用最新配置")
        base = raw_cookie
    else:
        base = saved_cookie or raw_cookie

    base = _keepalive_refresh(base, redis_key, state_file, env_hash, f"[{idx}/{total}]")

    headers = {"Cookie": base, "Referer": "https://2libra.com/", "Origin": "https://2libra.com"}
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

    # 签到成功：合并本次链路 Set-Cookie 持久化，供下次运行保活与复用
    merged = _merge_cookies(base, h.jar)
    try:
        _save_state(redis_key, state_file, merged, env_hash)
    except Exception as exc:
        print(f"  ⚠️ 状态持久化失败: {exc}")
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
            line = _run_one(acc["cookie"], acc.get("auth", ""), idx, len(accounts))
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
