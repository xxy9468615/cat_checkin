#!/usr/bin/env python3
# cron: 30 9 * * *
# new Env("奶昔论坛签到")
import re
import sys
from html import unescape
from urllib.parse import urljoin

from common import Http, env_seq, find, main_guard, mask_str, must_match, sanitize_snippet, strip_tags

PREFIX = "NAIXI_"

# ---- 签到页状态判定 ---------------------------------------------------------
# Discuz k_misign 插件：未签到页渲染「您今天还没有签到」；已签到页渲染
# 「您的签到排名：N」/「您今天已经签到」等。
# 严禁使用裸英文 "already"：站点全站页脚 PWA 脚本含
# 「// If app is already installed, open it」，会让**每个**页面都被判为已签到，
# 于是整段真实签到被跳过 → 「假成功」（2026-09 站点升级引入该页脚后暴露）。
_NOT_SIGNED_MARKERS = (
    "您今天还没有签到", "今天还没有签到", "今日还没有签到",
    "还没有签到", "立即签到", "点击签到",
)
_ALREADY_SIGNED_MARKERS = (
    "您的签到排名", "您今天已经签到", "今天已经签到", "今日已经签到",
    "今天已完成签到", "今日已完成签到", "今天已签", "今日已签",
    "签到成功", "签到完毕", "明天再来", "下次再来",
)
# 签到提交响应中的失败信号（接口未定义 / 登录失效 / 权限不足 / 业务失败）
# 仅用于候选间切换与错误文案，成功与否一律以「提交后签到页状态」为准
_SIGN_FAIL_KEYWORDS = (
    "未定义操作", "请先登录", "需要先登录", "未登录", "登录失效",
    "无权", "没有权限", "失败", "错误",
)


def _page_signed_state(text: str) -> str:
    """判定签到页状态：not_signed / already_signed / unknown。

    必须先判「未签到」：未签到页绝不能命中已签到词（站点统计文案含
    「今日已签到 X 人」，裸「已签到」会误判 → 跳过真实签到）。
    """
    if any(m in text for m in _NOT_SIGNED_MARKERS):
        return "not_signed"
    if any(m in text for m in _ALREADY_SIGNED_MARKERS):
        return "already_signed"
    return "unknown"


def _extract_formhash(html: str) -> str:
    """从签到页提取 formhash（兼容隐藏 input / URL query / JS 常量三种形态）。"""
    for pat in (
        r'name=["\']formhash["\'][^>]*value=["\']([0-9a-zA-Z]+)',
        r'formhash=([0-9a-zA-Z]+)',
        r'FORMHASH\s*[:=]\s*["\']([0-9a-zA-Z]+)',
    ):
        m = re.search(pat, html)
        if m:
            return m.group(1)
    return ""


def _extract_sign_href(html: str, base: str) -> str:
    """按页面签到按钮 href 构造绝对提交地址（站点改 format/ajaxtarget 也能跟随）。"""
    m = re.search(r'href=["\']([^"\']*operation=qiandao[^"\']*)', html, re.I)
    if not m:
        return ""
    return urljoin(base + "/plugin.php?id=k_misign%3Asign", unescape(m.group(1)))


def _submit_sign(h: Http, base: str, page_text: str) -> str:
    """提交签到请求，返回结果文案；失败即 raise（绝不假成功）。

    优先按页面按钮 href 提交（跟随站点 format/ajaxtarget 变更），
    回退到固定 URL（与 qd-today 奶昔模板一致）。
    """
    urls = []
    href = _extract_sign_href(page_text, base)
    if href:
        urls.append(href)
    fh = _extract_formhash(page_text)
    if fh:
        fallback = (
            base
            + f"/plugin.php?id=k_misign%3Asign&operation=qiandao&format=global_usernav_extra&formhash={fh}&inajax=1&ajaxtarget=k_misign_topb"
        )
        if fallback not in urls:
            urls.append(fallback)
    if not urls:
        raise RuntimeError(f"未提取到签到 formhash 与签到链接（响应片段: {sanitize_snippet(page_text)}）")

    last_err = ""
    for url in urls:
        resp = h.request("GET", url)
        msg = strip_tags(find(r'<!\[CDATA\[(.+?)\]\]>', resp.text, "")).strip()
        if msg and any(k in msg for k in _SIGN_FAIL_KEYWORDS):
            last_err = msg
            continue  # 该候选接口不可用，尝试下一个
        return f"签到成功：{msg}" if msg else "签到成功"
    raise RuntimeError(f"签到失败：{last_err}")


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
        raise RuntimeError(f"登录失败，响应片段: {sanitize_snippet(lt)}")

    page = h.request("GET", base + "/plugin.php?id=k_misign%3Asign")
    state = _page_signed_state(page.text)

    if state == "already_signed":
        sign_status = "今日已签到（幂等放行）"
    elif state == "not_signed":
        sign_status = _submit_sign(h, base, page.text)
        page = h.request("GET", base + "/plugin.php?id=k_misign%3Asign")
        # 提交后复核：仍显示「未签到」= 提交未生效，红卡（宁可红卡不可假绿）
        if _page_signed_state(page.text) == "not_signed":
            raise RuntimeError("签到提交后页面仍显示未签到（提交未生效）")
    else:
        raise RuntimeError(f"签到页状态无法识别（未出现已签到/未签到标记，响应片段: {sanitize_snippet(page.text)}）")

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
