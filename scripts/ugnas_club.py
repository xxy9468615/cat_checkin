#!/usr/bin/env python3
# cron: 20 9 * * *
# new Env("绿联私有云 签到")
from common import Http, env, must_match, main_guard
PREFIX = "UGNAS_"
def main():
    print("【绿联私有云 签到】")
    cookie=env(PREFIX,"cookie")
    r=Http().request("GET","https://club.ugnas.com/forum.php",headers={"Cookie":cookie})
    # cookie 失效时页面无积分信息：必须显式失败，否则报告假成功
    print(must_match(r'积分:\s*\d+',r.text,"积分（未提取到，可能 cookie 失效）"))
main_guard(main)
