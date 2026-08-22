#!/usr/bin/env python3
# cron: 40 9 * * *
# new Env("边界 AI 签到")
from common import Http, env, find, main_guard, mask_str
import os
import re
import sys

PREFIX = "BIANJIE_AI_"

LOGIN_URL = "https://ai1foo.com/api/v1/user/login"
# v2/user/signin/do 已下线（返回"活动已结束"），现用 v1
SIGNIN_URL = "https://api.ai1foo.com/api/v1/user/signin"
POINTS_URL = "https://api.ai1foo.com/api/v1/user/points"


def _load_accounts():
    """返回 [(username, password), ...]。

    多账号（推荐）：QL_BIANJIE_AI_ACCOUNTS，每行一个账号，
        分隔符支持 "user:pass" / "user---pass" / "user,pass"，
        账号之间用换行或 && 分隔。
    单账号（兼容）：QL_BIANJIE_AI_username + QL_BIANJIE_AI_password。
    """
    raw = os.getenv(f"{PREFIX}ACCOUNTS", "").strip()
    accounts = []
    if raw:
        for chunk in re.split(r"\n|&&", raw):
            chunk = chunk.strip()
            if not chunk:
                continue
            # 优先 ":"，其次 "---"，再次 ","
            if ":" in chunk:
                user, _, pwd = chunk.partition(":")
            elif "---" in chunk:
                user, _, pwd = chunk.partition("---")
            elif "," in chunk:
                user, _, pwd = chunk.partition(",")
            else:
                continue
            user, pwd = user.strip(), pwd.strip()
            if user and pwd:
                accounts.append((user, pwd))
    # 兼容单账号环境变量
    user = os.getenv(f"{PREFIX}username", "").strip()
    pwd = os.getenv(f"{PREFIX}password", "").strip()
    if user and pwd and (user, pwd) not in accounts:
        accounts.append((user, pwd))
    return accounts


def _run_one(h, username, password):
    login = h.request("POST", LOGIN_URL, json_data={"user": username, "pass": password})
    yhm = find(r'"user":"(.*?)",', login.text, username)
    token = find(r'"token":"(.*?)",', login.text)
    access = find(r'"access_token":"(.*?)"', login.text)
    uid = find(r'"id":(\d+)', login.text)
    if not (token and access and uid):
        # 响应体可能含 token（正则未命中时原文回显会泄漏进日志/邮件），默认不打印
        detail = login.text[:200] if os.getenv("DEBUG") else "（响应体含敏感字段，DEBUG=true 时打印）"
        raise RuntimeError(f"登录失败（账号 {mask_str(username)}，HTTP {login.code}）: {detail}")
    headers = {"access-token": access, "uid": uid, "token": token}

    # 签到。站点没有独立的签到查询接口（GET/POST 同 URL 都是签到动作），
    # continue_days / reward 只在当天首次签到成功的响应里返回一次，
    # 重复请求一律只得到 {"code":400,"msg":"今天已经签到过了"}。
    s = h.request("POST", SIGNIN_URL, headers=headers, json_data={})
    msg = find(r'"msg":"(.*?)"', s.text, "")
    if find(r'"code":(\d+)', s.text) == "200":
        lxqd = find(r'"continue_days":(\d+)', s.text, "?")
        reward = find(r'"reward":"(.*?)"', s.text, "")
        status = f"签到成功，已连续签到{lxqd}天"
        if reward:
            status += f"，奖励：{reward}"
    elif "已经签到" in msg:
        status = "今日已签到过"
    else:
        raise RuntimeError(f"签到失败: {msg or s.text[:120]}")

    p = h.request("POST", POINTS_URL, headers=headers)
    jf = find(r'"points":(\d+)', p.text, "?")
    return yhm, status, jf


def main():
    accounts = _load_accounts()
    if not accounts:
        raise RuntimeError(
            f"未配置 {PREFIX}ACCOUNTS 或 {PREFIX}username/{PREFIX}password"
        )

    print("【边界 AI 签到】")
    print(f"共 {len(accounts)} 个账号")
    results = []
    for idx, (user, pwd) in enumerate(accounts, 1):
        try:
            yhm, status, jf = _run_one(Http(), user, pwd)
            line = f"[{idx}/{len(accounts)}] 用户名：{mask_str(yhm)}，{status}，累计积分：{jf}。"
            print(line)
            results.append((True, line))
        except Exception as e:
            line = f"[{idx}/{len(accounts)}] 用户名：{mask_str(user)}，签到失败：{e}"
            print(line)
            results.append((False, line))

    ok = sum(1 for ok_flag, _ in results if ok_flag)
    print(f"签到总结：成功 {ok}/{len(accounts)}")
    if ok != len(accounts):
        sys.exit(1)


main_guard(main)
