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
    msgs=[]
    for path in ["/home.php?mod=task","/home.php?mod=task&do=apply&id=149","/home.php?mod=task&do=draw&id=149"]:
        r=h.request("GET",base+path)
        m=find(r'<!\[CDATA\[(.+?)\]\]>',r.text,"")
        if m: msgs.append(strip_tags(m).strip())
    credit=h.request("GET",base+"/home.php?mod=spacecp&ac=credit")
    # 登录失败时积分页是游客内容：显式失败，否则报告假成功
    if "访问我的空间" not in credit.text:
        raise RuntimeError("登录失败：积分页未检测到用户信息（账号密码错误或被风控）")
    nick=find(r'访问我的空间">(.+?)<',credit.text,username)
    f=strip_tags(find(r'<em> PB币[\s\S]+?</ul>',credit.text,""))
    print(f"{mask_str(nick)} {f}".strip() + (f"\n任务：{'；'.join(msgs)}" if msgs else ""))
main_guard(main)
