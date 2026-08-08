#!/usr/bin/env python3
# cron: 55 9 * * *
# new Env("Tencent CloudStudio 签到")
from common import Http, env, find, findall, main_guard
PREFIX = "CLOUDSTUDIO_"
def main():
    print("【Tencent CloudStudio 签到】")
    cookie=env(PREFIX,"cookie"); xsrf=env(PREFIX,"xsrf")
    headers={"Cookie":cookie,"X-XSRF-TOKEN":xsrf,"Referer":"https://cloudstudio.net/"}; h=Http()
    # Cookie 失效时 user/info 会 302 到登录页，签到接口返回 401 user_not_authentication
    u=h.request("GET","https://cloudstudio.net/api/user/info",headers=headers)
    if u.code in (301,302,303,307,308) or "nickName" not in u.text:
        raise RuntimeError(f"Cookie 已失效（user/info HTTP {u.code}），请更新 CLOUDSTUDIO_cookie / CLOUDSTUDIO_xsrf")
    nick=find(r'"nickName":"(.*?)"',u.text,"?")
    s=h.request("POST","https://cloudstudio.net/api/billing/activityTask/SIGN_IN_2025Q3/_reward",headers=headers,json_data={})
    if s.code >= 400:
        msg=find(r'"msg":"(.*?)"',s.text,s.text[:120])
        raise RuntimeError(f"签到接口 HTTP {s.code}: {msg}")
    # 首次签到 records 含奖励记录；今日已签到过则 records 为空数组
    reward=int(find(r'"rewardNum":(\d+)',s.text,"0"))/100000000
    status=f"签到成功，获得 {reward:.2f} 机时" if reward>0 else "今日已签到过"
    p=h.request("GET","https://cloudstudio.net/api/billing/resource/package?pageNumber=0&pageSize=10",headers=headers).text
    names=findall(r'"name":"(.*?)"',p); totals=findall(r'"total":(\d+)',p); useds=findall(r'"used":(\d+)',p); exps=findall(r'"expiredTime":"(.*?)"',p)
    lines=[f"用户 {nick} {status}","最新可用资源为：","已用 | 一共 | 到期时间 | 资源名称"]
    for i,name in enumerate(names):
        used=int(useds[i])/100000000 if i < len(useds) else 0; total=int(totals[i])/100000000 if i < len(totals) else 0; exp=(exps[i] if i < len(exps) else '').replace('T',' ').replace('.000+00:00','')
        lines.append(f"{used:.2f} | {int(total)} 机时 | {exp} | {name}")
    print("\n".join(lines))
main_guard(main)
