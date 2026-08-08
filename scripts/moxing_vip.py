#!/usr/bin/env python3
# cron: 5 10 * * *
# new Env("moxing.vip 签到")
import hashlib, re
from common import Http, env, find, findall, strip_tags, main_guard
PREFIX = "MOXING_"
def main():
    print("【moxing.vip 签到】")
    username=env(PREFIX,"username"); password=env(PREFIX,"password"); domain=env(PREFIX,"Domain","https://moxing.vip",False).rstrip('/'); ua=env(PREFIX,"UA","Mozilla/5.0 (Android 14; Mobile; rv:130.0) Gecko/130.0 Firefox/130.0",False)
    h=Http(); headers={"User-Agent":ua,"Referer":domain+"/"}
    first=h.request("GET",domain,headers=headers)
    candidates=[]
    if first.headers and first.headers.get("Location"): candidates.append(first.headers.get("Location"))
    candidates += findall(r'href="(https://\w+\.\w+)"',first.text)
    for c in candidates:
        rr=h.request("GET",c,headers=headers)
        if "登录" in rr.text: domain=c.rstrip('/'); break
    login=h.request("GET",domain+"/member.php?mod=logging&action=login",headers=headers).text
    formhash=find(r'formhash. value=.(\w+).',login); loginhash=find(r'loginhash=(\w+)',login)
    if formhash and loginhash:
        h.request("POST",domain+f"/member.php?mod=logging&action=login&loginsubmit=yes&loginhash={loginhash}&inajax=1",headers=headers,form={"formhash":formhash,"username":username,"password":hashlib.md5(password.encode()).hexdigest()})
    page=h.request("GET",domain+"/plugin.php?id=k_misign%3Asign",headers=headers).text
    q=find(r'(plugin.php.+qiandao.+\w+)',page)
    if q: h.request("GET",domain+"/"+q,headers=headers)
    prof=h.request("GET",domain+"/home.php?mod=space",headers=headers).text
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
            msg=find(r'message":"([^"]+)"',rr.text,rr.text[:80])
    t=find(r'(在线时间</em>\d+ 小时)',prof); u=find(r'<title>(.+)的个人资料',prof,username); g=find(r'用户组.+</a>',prof); j=find(r'积分.+</a>',prof); cr=find(r'威望.+',credit)
    print(f"用户名：{strip_tags(u)} {strip_tags(g)} {strip_tags(t)} {strip_tags(j)} {strip_tags(cr)} {msg}".strip())
main_guard(main)
