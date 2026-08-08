#!/usr/bin/env python3
# cron: 30 9 * * *
# new Env("奶昔论坛签到")
from common import Http, env, must_match, find, main_guard
PREFIX = "NAIXI_"
def main():
    print("【奶昔论坛 签到】")
    username=env(PREFIX,"username"); password=env(PREFIX,"password")
    h=Http(); base="https://forum.naixi.net"
    login_page=h.request("GET",base+"/member.php?mod=logging&action=login&infloat=yes&handlekey=login&inajax=1&ajaxtarget=fwin_content_login")
    formhash=must_match(r'name="formhash" value="(.+?)"',login_page.text,"formhash")
    loginhash=must_match(r'loginhash=(.+?)"',login_page.text,"loginhash")
    h.request("POST",base+f"/member.php?mod=logging&action=login&loginsubmit=yes&handlekey=login&loginhash={loginhash}&inajax=1",form={"formhash":formhash,"referer":base+"/","username":username,"password":password,"questionid":"0","answer":""})
    page=h.request("GET",base+"/plugin.php?id=k_misign%3Asign")
    fh=must_match(r'formhash=(.*?)"',page.text,"sign formhash")
    h.request("GET",base+f"/plugin.php?id=k_misign%3Asign&operation=qiandao&format=global_usernav_extra&formhash={fh}&inajax=1&ajaxtarget=k_misign_topb")
    page=h.request("GET",base+"/plugin.php?id=k_misign%3Asign")
    lxqd=find(r'id="lxdays" value="(\d+)',page.text,"?"); tdays=find(r'id="lxtdays" value="(\d+)',page.text,"?")
    credit=h.request("GET",base+"/home.php?mod=spacecp&ac=credit&showcredit=1")
    # 论坛已把"金币"改为"经验"，且 <li> 带动态 class，正则不能写死标签属性
    ds=find(r'<em>\s*点数:\s*</em>(\d+)',credit.text,"?"); jy=find(r'<em>\s*经验:\s*</em>(\d+)',credit.text,"?"); jf=find(r'<em>\s*积分:\s*</em>(\d+)',credit.text,"?")
    print(f"连续签到：{lxqd}天（累计{tdays}天）\n点数：{ds}，经验：{jy}，积分：{jf}。")
main_guard(main)
