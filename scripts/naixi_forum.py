#!/usr/bin/env python3
# cron: 30 9 * * *
# new Env("奶昔论坛签到")
import os
import sys
from common import Http, env, env_seq, must_match, find, strip_tags, main_guard, mask_str

PREFIX = "NAIXI_"


def _load_accounts() -> list[tuple[str, str]]:
    """返回 [(username, password), ...] 列表。

    序号序列（推荐）：NAIXI_USERNAME_1 / NAIXI_PASSWORD_1, NAIXI_USERNAME_2 / NAIXI_PASSWORD_2...
    多账号旧格式：NAIXI_ACCOUNTS，每行一个账号，格式 user:pass 或 user---pass，换行或 && 分隔。
    单账号（兼容）：NAIXI_username + NAIXI_password。
    """
    accounts = []

    # 1. 优先扫描序号配对的 USERNAME_1 / PASSWORD_1 序列
    users = env_seq(PREFIX, "username", required=False)
    pwds = env_seq(PREFIX, "password", required=False)
    for u, p in zip(users, pwds):
        u, p = u.strip(), p.strip()
        if u and p and (u, p) not in accounts:
            accounts.append((u, p))

    # 2. 扫描 ACCOUNTS 序列或兼容旧 ACCOUNTS 变量（换行 / && 切分）
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


def _run_one(username: str, password: str) -> str:
    h = Http()
    base = "https://forum.naixi.net"
    login_page = h.request("GET", base + "/member.php?mod=logging&action=login&infloat=yes&handlekey=login&inajax=1&ajaxtarget=fwin_content_login")
    formhash = must_match(r'name="formhash" value="(.+?)"', login_page.text, "formhash")
    loginhash = must_match(r'loginhash=(.+?)"', login_page.text, "loginhash")
    login_resp = h.request("POST", base + f"/member.php?mod=logging&action=login&loginsubmit=yes&handlekey=login&loginhash={loginhash}&inajax=1", form={"formhash": formhash, "referer": base + "/", "username": username, "password": password, "questionid": "0", "answer": ""})
    # 校验登录成功：Discuz inajax 登录成功响应含 succeedhandle/欢迎回来/location.href 跳转，否则视为失败
    # （不能匹配裸词 "location"——错误页脚本/任意含该词的文案都会误判登录成功）
    lt = login_resp.text or ""
    if "succeedhandle" not in lt and "欢迎回来" not in lt and "location.href" not in lt:
        raise RuntimeError(f"登录失败，响应片段: {lt.replace(chr(10), ' ')[:300]}")
    page = h.request("GET", base + "/plugin.php?id=k_misign%3Asign")
    # 幂等检测：已签到时签到按钮不渲染（无 formhash），页面显示「已签到」类字样 → 放行
    # （匹配词须精确：裸「已签到」会命中统计文案「今日已签到 XX 人」→ 整体跳过真实签到）
    already_markers = ("您今日已签到", "今日已签到", "已经签到", "already")
    sign_status = "今日已签到（幂等放行）"
    if not any(m in page.text for m in already_markers):
        fh = must_match(r'formhash=(.*?)"', page.text, "sign formhash")
        sign_r = h.request("GET", base + f"/plugin.php?id=k_misign%3Asign&operation=qiandao&format=global_usernav_extra&formhash={fh}&inajax=1&ajaxtarget=k_misign_topb")
        sign_msg = find(r'<!\[CDATA\[(.+?)\]\]>', sign_r.text, "").strip()
        if sign_msg:
            sign_msg = strip_tags(sign_msg)
            if sign_msg:
                sign_status = f"签到成功：{sign_msg}"
            else:
                sign_status = "签到成功"
        else:
            sign_status = "签到成功"
        page = h.request("GET", base + "/plugin.php?id=k_misign%3Asign")

    lxqd = find(r'id="lxdays" value="(\d+)', page.text, "?")
    tdays = find(r'id="lxtdays" value="(\d+)', page.text, "?")
    if lxqd == "?":
        # 签到页未返回连签天数 = 登录失效或签到未生效，不能假成功
        raise RuntimeError("签到状态获取失败（连签天数未返回，可能登录失效或签到未生效）")
    credit = h.request("GET", base + "/home.php?mod=spacecp&ac=credit&showcredit=1")
    # 论坛已把"金币"改为"经验"，且 <li> 带动态 class，正则不能写死标签属性
    ds = find(r'<em>\s*点数:\s*</em>(\d+)', credit.text, "?")
    jy = find(r'<em>\s*经验:\s*</em>(\d+)', credit.text, "?")
    jf = find(r'<em>\s*积分:\s*</em>(\d+)', credit.text, "?")

    return f"用户名：{mask_str(username)} | {sign_status} | 连续签到：{lxqd}天（累计{tdays}天） | 点数：{ds}，经验：{jy}，积分：{jf}"


def main():
    print("【奶昔论坛 签到】")
    accounts = _load_accounts()
    if not accounts:
        raise RuntimeError(f"未配置 {PREFIX}USERNAME 与 {PREFIX}PASSWORD（或 {PREFIX}USERNAME_1/{PREFIX}PASSWORD_1、{PREFIX}ACCOUNTS）")

    print(f"共 {len(accounts)} 个账号")
    results = []
    for idx, (u, p) in enumerate(accounts, 1):
        try:
            line = _run_one(u, p)
            out = f"[{idx}/{len(accounts)}] {line}"
            print(out)
            results.append((True, out))
        except Exception as e:
            out = f"[{idx}/{len(accounts)}] 用户名：{mask_str(u)} 签到失败：{e}"
            print(out)
            results.append((False, out))

    ok = sum(1 for ok_flag, _ in results if ok_flag)
    print(f"\n========== 签到总结 ==========\n成功 {ok}/{len(accounts)}")
    if ok != len(accounts):
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
