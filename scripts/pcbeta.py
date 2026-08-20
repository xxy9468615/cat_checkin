#!/usr/bin/env python3
# cron: 25 9 * * *
# new Env("远景论坛 签到")
import os
import re
from common import Http, env, find, must_match, strip_tags, main_guard, mask_str

PREFIX = "PCBETA_"
BASE_URL = "https://i.pcbeta.com"
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def _login(h: Http, username: str, password: str) -> None:
    """标准 Discuz! 登录流程：探测 formhash/loginhash 并提交登录表单。"""
    web_headers = {
        "User-Agent": DEFAULT_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Referer": f"{BASE_URL}/",
    }
    # 1. 依次尝试个人中心与论坛主站获取登录页面
    resp = None
    urls_to_try = [
        f"{BASE_URL}/member.php?mod=logging&action=login",
        "https://bbs.pcbeta.com/member.php?mod=logging&action=login",
        f"{BASE_URL}/",
        "https://bbs.pcbeta.com/",
    ]
    for url in urls_to_try:
        r = h.request("GET", url, headers=web_headers)
        if r.code == 200 and ("formhash" in r.text or "loginform" in r.text):
            resp = r
            break

    if not resp or resp.code != 200:
        raise RuntimeError(
            "获取登录表单失败（HTTP 403/受限）：远景论坛对海外机房 IP 启用了 WAF 访问控制，\n"
            "账号密码自动登录受阻。建议登录浏览器复制 Cookie 并配置 GitHub Secret `PCBETA_COOKIE` 直接认证。"
        )

    formhash = (
        find(r'name=["\']formhash["\']\s+value=["\']([a-zA-Z0-9_]+)["\']', resp.text)
        or find(r'value=["\']([a-zA-Z0-9_]+)["\']\s+name=["\']formhash["\']', resp.text)
        or find(r'formhash=([a-zA-Z0-9_]+)', resp.text)
    )
    loginhash = (
        find(r'loginhash=([a-zA-Z0-9_]+)', resp.text)
        or find(r'loginform_([a-zA-Z0-9_]+)', resp.text)
        or find(r'id=["\']layer_login_([a-zA-Z0-9_]+)["\']', resp.text)
    )

    if not formhash:
        raise RuntimeError("登录表单解析失败：未找到 formhash")

    # 2. 提交登录表单
    post_url = f"{BASE_URL}/member.php?mod=logging&action=login&loginsubmit=yes"
    if loginhash:
        post_url += f"&loginhash={loginhash}"

    post_headers = {
        "User-Agent": DEFAULT_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Referer": f"{BASE_URL}/member.php?mod=logging&action=login",
        "Origin": BASE_URL,
    }
    form_data = {
        "formhash": formhash,
        "referer": f"{BASE_URL}/",
        "username": username,
        "password": password,
        "cookietime": "2592000",
        "questionid": "0",
        "answer": "",
    }
    login_resp = h.request("POST", post_url, headers=post_headers, form=form_data)
    login_msg = (
        find(r'<!\[CDATA\[([\s\S]+?)\]\]>', login_resp.text, "")
        or find(r'class="c">([\s\S]+?)</div>', login_resp.text, "")
        or find(r'id="messagetext">[\s\S]*?<p>([\s\S]+?)</p>', login_resp.text, "")
    ).strip()
    clean_msg = strip_tags(login_msg).strip()

    # 若响应明确提示失败原因（如密码错误、登录次数超限、验证码等）
    if clean_msg and any(w in clean_msg for w in ["密码错误", "验证码", "尝试次数过多", "无法登录", "登录失败", "抱歉"]):
        raise RuntimeError(f"登录失败：{clean_msg}")


def main():
    print("【PCBeta 远景论坛 签到】")
    cookie = os.getenv(f"{PREFIX}cookie", "").strip() or os.getenv(f"{PREFIX}COOKIE", "").strip() or os.getenv(f"QL_{PREFIX}cookie", "").strip()
    username = os.getenv(f"{PREFIX}username", "").strip() or os.getenv(f"{PREFIX}USERNAME", "").strip() or os.getenv(f"QL_{PREFIX}username", "").strip()
    password = os.getenv(f"{PREFIX}password", "").strip() or os.getenv(f"{PREFIX}PASSWORD", "").strip() or os.getenv(f"QL_{PREFIX}password", "").strip()

    if not cookie and not (username and password):
        raise RuntimeError(f"缺少凭据：请配置 {PREFIX}cookie 或 {PREFIX}username 与 {PREFIX}password")

    h = Http()
    headers = {
        "User-Agent": DEFAULT_UA,
        "Referer": f"{BASE_URL}/",
    }
    if cookie:
        headers["Cookie"] = cookie

    # 若未提供 Cookie，则走账号密码登录
    if not cookie and username and password:
        _login(h, username, password)

    # 3. 依次申请与领取日常任务（id=149 为日常红包/签到任务）
    msgs = []
    task_paths = [
        "/home.php?mod=task",
        "/home.php?mod=task&do=apply&id=149",
        "/home.php?mod=task&do=draw&id=149",
    ]
    for path in task_paths:
        r = h.request("GET", BASE_URL + path, headers=headers)
        m = find(r'<!\[CDATA\[([\s\S]+?)\]\]>', r.text, "")
        if m:
            clean_m = strip_tags(m).strip()
            if clean_m and clean_m not in msgs:
                msgs.append(clean_m)

    # 4. 验证登录状态与获取积分信息
    credit = h.request("GET", f"{BASE_URL}/home.php?mod=spacecp&ac=credit", headers=headers)
    if "访问我的空间" not in credit.text and "个人资料" not in credit.text and "退出" not in credit.text:
        # 回退尝试 bbs 域名
        bbs_credit = h.request("GET", "https://bbs.pcbeta.com/home.php?mod=spacecp&ac=credit", headers=headers)
        if "访问我的空间" in bbs_credit.text or "个人资料" in bbs_credit.text or "退出" in bbs_credit.text:
            credit = bbs_credit
        else:
            snippet = strip_tags(credit.text[:300]).replace("\n", " ").strip()
            raise RuntimeError(f"登录态无效或失效 (HTTP {credit.code})：{snippet or '积分页未检测到用户信息'}")

    nick = (
        find(r'访问我的空间">(.+?)<', credit.text)
        or find(r'class="vwmy[^"]*"><a[^>]*>(.+?)</a>', credit.text)
        or username
        or "用户"
    )
    pb = strip_tags(find(r'<em> PB币[\s\S]+?</ul>', credit.text, ""))
    if not pb:
        # 兼容其他积分展示格式
        credits_list = re.findall(r'<em>\s*([^:<]+?)\s*:\s*</em>\s*(\d+)', credit.text)
        if credits_list:
            pb = "，".join(f"{k}: {v}" for k, v in credits_list)

    task_summary = f"任务响应：{'；'.join(msgs)}" if msgs else "任务已申请/领取"
    print(f"用户：{mask_str(nick)} | {pb or '积分获取成功'}\n{task_summary}")


main_guard(main)
