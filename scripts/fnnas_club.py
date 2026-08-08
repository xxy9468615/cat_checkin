#!/usr/bin/env python3
# cron: 35 9 * * *
# new Env("飞牛私有云 签到")
from common import Http, env, must_match, find, main_guard
PREFIX = "FNNAS_"
def main():
    cookie=env(PREFIX,"cookie"); h=Http(); headers={"Cookie":cookie}; base="https://club.fnnas.com"
    page=h.request("GET",base+"/plugin.php?id=zqlj_sign",headers=headers)
    sign=must_match(r'sign&sign=(.+?)" class="btna',page.text,"sign")
    h.request("GET",base+f"/plugin.php?id=zqlj_sign&sign={sign}",headers=headers)
    c=h.request("GET",base+"/home.php?mod=spacecp&ac=credit&showcredit=1",headers=headers)
    fnb=find(r'飞牛币: </em>(\d+)',c.text,"?"); nz=find(r'牛值: </em>(\d+)',c.text,"?"); ts=find(r'登陆天数: </em>(\d+)',c.text,"?"); jf=find(r'积分: </em>(\d+)',c.text,"?")
    print("【飞牛私有云社区 签到】")
    print(f"飞牛币:{fnb} | 牛值:{nz} | 登录天数:{ts} | 积分:{jf}")
main_guard(main)
