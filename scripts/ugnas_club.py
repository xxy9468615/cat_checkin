#!/usr/bin/env python3
# cron: 20 9 * * *
# new Env("绿联私有云 签到")
from common import Http, env, find, main_guard
PREFIX = "UGNAS_"
def main():
    print("【绿联私有云 签到】")
    cookie=env(PREFIX,"cookie")
    r=Http().request("GET","https://club.ugnas.com/forum.php",headers={"Cookie":cookie})
    print(find(r'积分:\s*\d+',r.text,"未提取到积分，可能 cookie 失效"))
main_guard(main)
