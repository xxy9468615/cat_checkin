#!/usr/bin/env python3
# cron: 5 9 * * *
# new Env("小鸟搜索 签到")
from common import Http, env, main_guard
PREFIX = "BIRDIESEARCH_"
def main():
    email=env(PREFIX,"email"); password=env(PREFIX,"password")
    h=Http(); base="https://www.birdiesearch.com"
    headers={"Origin":base,"Referer":base+"/"}
    login=h.request("POST",base+"/user/login",headers=headers,json_data={"email":email,"password":password}).json({})
    if login.get("code") not in (0,"0",None): raise RuntimeError(f"登录失败: {login}")
    info=h.request("POST",base+"/api/user/info",headers=headers,json_data={}).json({})
    user=(info.get("body") or info.get("data") or {}) if isinstance(info,dict) else {}
    sign=h.request("POST",base+"/api/user/sign",headers=headers,json_data={}).json({})
    code=sign.get("code"); msg=sign.get("msg") or sign.get("message") or ""
    date=sign.get("body") or sign.get("data") or ""
    print("【小鸟搜索 签到】")
    if code in (0,"0"):
        print(f"✅ 签到成功 date={date} | email={user.get('email',email)}")
    else:
        print(f"ℹ️ {msg or sign} | email={user.get('email',email)}")
main_guard(main)
