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
    headers = {
        "User-Agent": DEFAULT_UA,
        "Referer": f"{BASE_URL}/",
    }
    # 1. 获取登录弹窗页面以提取 formhash 和 loginhash
    login_url = (
        f"{BASE_URL}/member.php?mod=logging&action=login"
        "&infloat=yes&handlekey=login&inajax=1&ajaxtarget=fwin_content_login"
    )
    resp = h.request("GET", login_url, headers=headers)
    if resp.code != 200:
        raise RuntimeError(f"获取登录表单失败：HTTP {resp.code}")

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

    # 2. 提交登录 POST
    post_url = (
        f"{BASE_URL}/member.php?mod=logging&action=login&loginsubmit=yes"
        f"&handlekey=login&loginhash={loginhash or ''}&inajax=1"
    )
    form_data = {
        "formhash": formhash,
        "referer": f"{BASE_URL}/",
        "username": username,
        "password": password,
        "cookietime": "2592000",
        "questionid": "0",
        "answer": "",
    }
    login_resp = h.request("POST", post_url, headers=headers, form=form_data)
    login_msg = find(r'<!\[CDATA\[([\s\S]+?)\]\]>', login_resp.text, "").strip()
    clean_msg = strip_tags(login_msg).strip()

    # 若响应明确提示失败原因（如密码错误、登录次数超限、验证码等）
    if clean_msg and ("密码错误" in clean_msg or "验证码" in clean_msg or "尝试次数过多" in clean_msg or "无法登录" in clean_msg):
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
        raise RuntimeError("登录态无效或失效：积分页未检测到用户信息（可能账号密码错误或被风控）")

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
