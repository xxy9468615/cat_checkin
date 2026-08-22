#!/usr/bin/env python3
# cron: 5 10 * * *
# new Env("moxing.vip 签到")
import hashlib, json, re
from common import Http, env, find, findall, strip_tags, main_guard, mask_str
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

def _resolve_domain(h, headers, default):
    """解析存活的论坛域名：member.php 登录页能解析出 formhash+loginhash 才算存活。

    moxing.vip 已改版为纯导航页（2026-08），论坛本体迁移到多点域名（moxing.chat 等）。
    默认域名失效时从导航页抓候选列表自动切换，站点再迁移无需改代码。
    """
    def alive(d):
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

def main():
    print("【moxing.vip 签到】")
    username=env(PREFIX,"username"); password=env(PREFIX,"password"); domain=env(PREFIX,"Domain","https://moxing.chat",False).rstrip('/'); ua=env(PREFIX,"UA","Mozilla/5.0 (Android 14; Mobile; rv:130.0) Gecko/130.0 Firefox/130.0",False)
    h=Http(); headers={"User-Agent":ua}
    domain=_resolve_domain(h,headers,domain); headers["Referer"]=domain+"/"
    login=h.request("GET",domain+"/member.php?mod=logging&action=login",headers=headers).text
    formhash, loginhash = _extract_login_fields(login)
    if not (formhash and loginhash):
        # 解析不到登录表单：站点改版/被风控，静默跳过登录只会假成功
        raise RuntimeError("登录页解析失败（formhash/loginhash 缺失），可能站点改版或被风控")
    h.request("POST",domain+f"/member.php?mod=logging&action=login&loginsubmit=yes&loginhash={loginhash}&inajax=1",headers=headers,form={"formhash":formhash,"username":username,"password":hashlib.md5(password.encode()).hexdigest()})
    page=h.request("GET",domain+"/plugin.php?id=k_misign%3Asign",headers=headers).text
    q=find(r'(plugin.php.+qiandao.+\w+)',page)
    if not q:
        # 无签到入口：已签到日按钮不渲染且页面带「已签到」类字样 → 幂等放行；
        # 无任何标记则属插件变动/被风控，不能当成功上报
        if any(m in page for m in ("您今日已签到","今日已签到","已经签到","already")):
            print("ℹ️ 今日已签到（幂等放行）")
        else:
            raise RuntimeError("签到页无签到入口且无已签到标记（插件变动或被风控），无法确认签到状态")
    else:
        sign_r=h.request("GET",domain+"/"+q,headers=headers)
        sign_msg=strip_tags(find(r'<!\[CDATA\[(.+?)\]\]>',sign_r.text,"")).strip()
        if sign_msg:
            print(f"签到响应：{sign_msg}")
            if "失败" in sign_msg:
                raise RuntimeError(f"签到失败：{sign_msg}")
    prof=h.request("GET",domain+"/home.php?mod=space",headers=headers).text
    # 登录失败时个人资料页是游客/跳转页：显式失败，否则报告假成功
    if "个人资料" not in prof:
        raise RuntimeError("登录失败：个人资料页未检测到用户信息（账号密码错误或被风控）")
    credit=h.request("GET",domain+"/home.php?mod=spacecp&ac=credit&showcredit=1&inajax=1",headers=headers).text
    msg=""
    auth=h.request("GET",domain+"/auth.php",headers=headers)
    sso=auth.headers.get("Location") if auth.headers else ""
    if sso:
        domain2=find(r'https:\/\/[^/]+',sso) or domain
        h.request("GET",sso,headers=headers)
        xsrf=find(r'TOKEN=(\w+)',str(h.jar))
        cap=h.request("GET",domain2+"/api/forum/captcha/generate",headers=headers).text
        k=find(r'y":"(\w+)"',cap); i=find(r'e":"(\w+)"',cap)
        if k and i:
            rr=h.request("POST",domain2+"/api/forum/check-in/sign",headers={**headers,"x-xsrf-token":xsrf},json_data={"captcha":i,"captcha_key":k})
            msg=""
            try:
                _data=rr.json()
                if isinstance(_data,dict) and "message" in _data:
                    msg=str(_data["message"])
            except Exception:
                msg=find(r'message":"([^"]+)"',rr.text,rr.text[:80])
    t=find(r'(在线时间</em>\d+ 小时)',prof); u=find(r'<title>(.+)的个人资料',prof,username); g=find(r'用户组.+</a>',prof); j=find(r'积分.+</a>',prof); cr=find(r'威望.+',credit)
    masked_u = mask_str(strip_tags(u))
    print(f"用户名：{masked_u} {strip_tags(g)} {strip_tags(t)} {strip_tags(j)} {strip_tags(cr)} {msg}".strip())
main_guard(main)
