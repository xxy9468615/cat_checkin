#!/usr/bin/env python3
# cron: 30 9 * * *
# new Env("奶昔论坛签到")
from common import Http, env, must_match, find, strip_tags, main_guard
PREFIX = "NAIXI_"
def main():
    print("【奶昔论坛 签到】")
    username=env(PREFIX,"username"); password=env(PREFIX,"password")
    h=Http(); base="https://forum.naixi.net"
    login_page=h.request("GET",base+"/member.php?mod=logging&action=login&infloat=yes&handlekey=login&inajax=1&ajaxtarget=fwin_content_login")
    formhash=must_match(r'name="formhash" value="(.+?)"',login_page.text,"formhash")
    loginhash=must_match(r'loginhash=(.+?)"',login_page.text,"loginhash")
    login_resp=h.request("POST",base+f"/member.php?mod=logging&action=login&loginsubmit=yes&handlekey=login&loginhash={loginhash}&inajax=1",form={"formhash":formhash,"referer":base+"/","username":username,"password":password,"questionid":"0","answer":""})
    # 校验登录成功：Discuz inajax 登录成功响应含 succeedhandle/欢迎回来/location.href 跳转，否则视为失败
    lt=login_resp.text or ""
    if "succeedhandle" not in lt and "欢迎回来" not in lt and "location.href" not in lt and "location" not in lt.lower():
        raise RuntimeError(f"登录失败，响应片段: {lt.replace(chr(10),' ')[:300]}")
    page=h.request("GET",base+"/plugin.php?id=k_misign%3Asign")
    # 幂等检测：已签到时签到按钮不渲染（无 formhash），页面显示「已签到」类字样 → 放行
    already_markers=("您今日已签到","今日已签","已签到","already","签到成功")
    if any(m in page.text for m in already_markers):
        print("今日已签到（幂等放行）")
    else:
        fh=must_match(r'formhash=(.*?)"',page.text,"sign formhash")
        sign_r=h.request("GET",base+f"/plugin.php?id=k_misign%3Asign&operation=qiandao&format=global_usernav_extra&formhash={fh}&inajax=1&ajaxtarget=k_misign_topb")
        sign_msg=find(r'<!\[CDATA\[(.+?)\]\]>',sign_r.text,"").strip()
        if sign_msg:
            sign_msg=strip_tags(sign_msg)
            if sign_msg:
                print(f"签到响应：{sign_msg}")
        page=h.request("GET",base+"/plugin.php?id=k_misign%3Asign")
    lxqd=find(r'id="lxdays" value="(\d+)',page.text,"?"); tdays=find(r'id="lxtdays" value="(\d+)',page.text,"?")
    if lxqd == "?":
        # 签到页未返回连签天数 = 登录失效或签到未生效，不能假成功
        raise RuntimeError("签到状态获取失败（连签天数未返回，可能登录失效或签到未生效）")
    credit=h.request("GET",base+"/home.php?mod=spacecp&ac=credit&showcredit=1")
    # 论坛已把"金币"改为"经验"，且 <li> 带动态 class，正则不能写死标签属性
    ds=find(r'<em>\s*点数:\s*</em>(\d+)',credit.text,"?"); jy=find(r'<em>\s*经验:\s*</em>(\d+)',credit.text,"?"); jf=find(r'<em>\s*积分:\s*</em>(\d+)',credit.text,"?")
    print(f"连续签到：{lxqd}天（累计{tdays}天）\n点数：{ds}，经验：{jy}，积分：{jf}。")
main_guard(main)
