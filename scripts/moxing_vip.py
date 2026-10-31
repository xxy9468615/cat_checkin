#!/usr/bin/env python3
# cron: 5 10 * * *
# new Env("moxing.vip 签到")
import hashlib
import json
import re
import sys
from typing import List, Tuple

from common import Http, env, env_seq, find, findall, strip_tags, main_guard, mask_str

PREFIX = "MOXING_"
NAV_URL = "https://moxing.vip/"  # 站点导航页：论坛本体迁移时此处列出最新可用域名


def _extract_login_fields(text: str) -> tuple[str, str]:
    """从 Discuz 登录页提取 formhash 和 loginhash。"""
    formhash = (
        find(r'name=["\']formhash["\']\s+value=["\']([a-zA-Z0-9_]+)["\']', text)
        or find(r'value=["\']([a-zA-Z0-9_]+)["\']\s+name=["\']formhash["\']', text)
        or find(r'formhash[^\w\n]+value[^\w\n]+([a-zA-Z0-9_]+)', text)
        or find(r'formhash=([a-zA-Z0-9_]+)', text)
    )
    loginhash = (
        find(r'loginhash=([a-zA-Z0-9_]+)', text)
        or find(r'loginhash["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_]+)', text)
    )
    return formhash, loginhash


def _resolve_domain(h: Http, headers: dict, default: str) -> str:
    """解析存活的论坛域名：member.php 登录页能解析出 formhash+loginhash 才算存活。

    moxing.vip 已改版为纯导航页（2026-08），论坛本体迁移到多点域名（moxing.chat 等）。
    默认域名失效时从导航页抓候选列表自动切换，站点再迁移无需改代码。
    """
    def alive(d: str) -> bool:
        r = h.request("GET", d + "/member.php?mod=logging&action=login", headers=headers)
        if r.code != 200:
            return False
        fh, lh = _extract_login_fields(r.text)
        return bool(fh and lh)

    if alive(default):
        return default
    nav = h.request("GET", NAV_URL, headers=headers)
    for c in findall(r'href="(https?://[\w.-]+)"', nav.text):
        c = c.rstrip('/')
        if c != default and alive(c):
            print(f"ℹ️ 默认域名不可用，切换到: {c}")
            return c
    raise RuntimeError("未找到可用论坛域名（站点可能再次迁移）")


def _load_accounts() -> List[Tuple[str, str]]:
    accounts: List[Tuple[str, str]] = []
    users = env_seq(PREFIX, "username", required=False)
    pwds = env_seq(PREFIX, "password", required=False)
    for u, p in zip(users, pwds):
        u, p = u.strip(), p.strip()
        if u and p and (u, p) not in accounts:
            accounts.append((u, p))

    raw_accs = env_seq(PREFIX, "accounts", required=False) or env_seq(PREFIX, "account", required=False)
    for chunk in raw_accs:
        chunk = chunk.strip()
        if not chunk:
            continue
        if ":" in chunk:
            u, _, p = chunk.partition(":")
        elif "---" in chunk:
            u, _, p = chunk.partition("---")
        elif "," in chunk:
            u, _, p = chunk.partition(",")
        else:
            continue
        u, p = u.strip(), p.strip()
        if u and p and (u, p) not in accounts:
            accounts.append((u, p))

    return accounts


def _run_one(username: str, password: str, domain: str, ua: str, idx: int, total: int) -> Tuple[bool, str]:
    h = Http()
    headers = {"User-Agent": ua}
    domain = _resolve_domain(h, headers, domain)
    headers["Referer"] = domain + "/"

    login = h.request("GET", domain + "/member.php?mod=logging&action=login", headers=headers).text
    formhash, loginhash = _extract_login_fields(login)
    if not (formhash and loginhash):
        raise RuntimeError("登录页解析失败（formhash/loginhash 缺失），可能站点改版或被风控")

    h.request(
        "POST",
        domain + f"/member.php?mod=logging&action=login&loginsubmit=yes&loginhash={loginhash}&inajax=1",
        headers=headers,
        form={"formhash": formhash, "username": username, "password": hashlib.md5(password.encode()).hexdigest()},
    )
    page = h.request("GET", domain + "/plugin.php?id=k_misign%3Asign", headers=headers).text
    q = find(r'(plugin.php.+qiandao.+\w+)', page)
    sign_msg = ""
    if not q:
        if any(m in page for m in ("您今日已签到", "今日已签到", "已经签到", "already")):
            sign_msg = "今日已签到（幂等放行）"
        else:
            raise RuntimeError("签到页无签到入口且无已签到标记（插件变动或被风控），无法确认签到状态")
    else:
        sign_r = h.request("GET", domain + "/" + q, headers=headers)
        raw_msg = strip_tags(find(r'<!\[CDATA\[(.+?)\]\]>', sign_r.text, "")).strip()
        if raw_msg:
            if "失败" in raw_msg:
                raise RuntimeError(f"签到失败：{raw_msg}")
            sign_msg = f"签到响应：{raw_msg}"
        else:
            sign_msg = "签到成功"

    prof = h.request("GET", domain + "/home.php?mod=space", headers=headers).text
    if "个人资料" not in prof:
        raise RuntimeError("登录失败：个人资料页未检测到用户信息（账号密码错误或被风控）")

    credit = h.request("GET", domain + "/home.php?mod=spacecp&ac=credit&showcredit=1&inajax=1", headers=headers).text
    msg = ""
    auth = h.request("GET", domain + "/auth.php", headers=headers)
    sso = auth.headers.get("Location") if auth.headers else ""
    if sso:
        domain2 = find(r'https:\/\/[^/]+', sso) or domain
        h.request("GET", sso, headers=headers)
        xsrf = find(r'TOKEN=(\w+)', str(h.jar))
        cap = h.request("GET", domain2 + "/api/forum/captcha/generate", headers=headers).text
        k = find(r'y":"(\w+)"', cap)
        i = find(r'e":"(\w+)"', cap)
        if k and i:
            rr = h.request(
                "POST",
                domain2 + "/api/forum/check-in/sign",
                headers={**headers, "x-xsrf-token": xsrf},
                json_data={"captcha": i, "captcha_key": k},
            )
            try:
                _data = rr.json()
                if isinstance(_data, dict) and "message" in _data:
                    msg = str(_data["message"])
            except Exception:
                msg = find(r'message":"([^"]+)"', rr.text, rr.text[:80])

    t = find(r'(在线时间</em>\d+ 小时)', prof)
    u = find(r'<title>(.+)的个人资料', prof, username)
    g = find(r'用户组.+</a>', prof)
    j = find(r'积分.+</a>', prof)
    cr = find(r'威望.+', credit)
    masked_u = mask_str(strip_tags(u))

    prefix_label = f"[{idx}/{total}] " if total > 1 else ""
    summary = f"{prefix_label}用户名：{masked_u} {strip_tags(g)} {strip_tags(t)} {strip_tags(j)} {strip_tags(cr)} {sign_msg} {msg}".strip()
    return True, summary


def main():
    print("【moxing.vip 签到】")
    accounts = _load_accounts()
    if not accounts:
        raise RuntimeError(f"缺少凭据：请配置 {PREFIX}username 与 {PREFIX}password（或 {PREFIX}USERNAME_1/{PREFIX}PASSWORD_1）")

    domain = env(PREFIX, "Domain", "https://moxing.chat", False).rstrip('/')
    ua = env(PREFIX, "UA", "Mozilla/5.0 (Android 14; Mobile; rv:130.0) Gecko/130.0 Firefox/130.0", False)

    total = len(accounts)
    results: List[Tuple[bool, str]] = []

    for idx, (u, p) in enumerate(accounts, 1):
        try:
            ok, msg = _run_one(u, p, domain, ua, idx, total)
            print(msg)
            results.append((ok, msg))
        except Exception as e:
            prefix_label = f"[{idx}/{total}] " if total > 1 else ""
            err_msg = f"{prefix_label}用户名：{mask_str(u)} 签到失败：{e}"
            print(err_msg)
            results.append((False, err_msg))

    ok_count = sum(1 for ok, _ in results if ok)
    if total > 1:
        print(f"\n========== 签到总结 ==========\n成功 {ok_count}/{total}")

    if ok_count != total:
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
