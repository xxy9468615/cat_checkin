#!/usr/bin/env python3
# cron: 25 9 * * *
# new Env("远景论坛 签到")
from common import Http, env, find, strip_tags, main_guard, mask_str
PREFIX = "PCBETA_"
def main():
    print("【PCBeta 远景论坛 签到】")
    username=env(PREFIX,"username"); password=env(PREFIX,"password")
    h=Http(); base="https://i.pcbeta.com"
    h.request("POST",base+"/member.php?mod=logging&action=login&loginsubmit=yes&inajax=1",form={"username":username,"password":password})
    for path in ["/home.php?mod=task","/home.php?mod=task&do=apply&id=149","/home.php?mod=task&do=draw&id=149"]:
        h.request("GET",base+path)
    credit=h.request("GET",base+"/home.php?mod=spacecp&ac=credit")
    nick=find(r'访问我的空间">(.+?)<',credit.text,username)
    f=strip_tags(find(r'<em> PB币[\s\S]+?</ul>',credit.text,""))
    print(f"{mask_str(nick)} {f}".strip())
main_guard(main)
