#!/usr/bin/env python3
# cron: 0 10 * * *
# new Env("DJI 大疆社区签到")
import time
from common import Http, env, find, findall, main_guard
PREFIX = "DJI_"
def nowms(): return int(time.time()*1000)
def main():
    cookie=env(PREFIX,"cookie"); h=Http(); headers={"Cookie":cookie,"Referer":"https://bbs.dji.com/"}; base="https://bbs.dji.com"
    login=h.request("GET",f"{base}/api/v2/users/login-info?device=desktop&t={nowms()}",headers=headers).text
    uid=find(r'"id":\s*(\d+)',login); uuid=find(r'"uuid":\s*"([^"]+)"',login); username=find(r'"name":\s*"([^"]+)"',login,"?"); start=find(r'"credits":\s*(\d+)',login,"?")
    st=h.request("GET",f"{base}/api/v2/home/paulsigns/user?device=desktop&t={nowms()}",headers=headers).text
    signed=find(r'"signed":\s*(true|false)',st,"false"); days=find(r'"days":\s*(\d+)',st,"?")
    sign_points="0"
    if signed != "true":
        sr=h.request("POST",f"{base}/api/v2/home/paulsigns/sign?device=desktop",headers=headers,json_data={}).text
        sign_points=find(r'"increased":\s*(\d+)',sr,"0")
    own_ok=False
    if uid and uuid:
        own_ok=h.request("GET",f"{base}/pro/user-center?uid={uid}&uuid={uuid}&do=thread",headers=headers).code==200
    threads=h.request("GET",f"{base}/api/v2/forum/thread/list?device=desktop&channel_slug=home-square-all&limit=10&offset=10&sort_type=latest_posts",headers=headers).text
    uids=findall(r'"author":\{"id":(\d+),"uuid":"[^"]+"',threads); uuids=findall(r'"author":\{"id":\d+,"uuid":"([^"]+)"',threads)
    other_ok=0
    for auid, auuid in list(zip(uids,uuids))[:10]:
        if h.request("GET",f"{base}/pro/user-center?uid={auid}&uuid={auuid}",headers=headers).code==200: other_ok+=1
    final=h.request("GET",f"{base}/api/v2/users/login-info?device=desktop&t={nowms()}",headers=headers).text
    final_credits=find(r'"credits":\s*(\d+)',final,"?")
    print("【DJI 大疆社区签到】")
    print(f"【个人信息】\n用户：【{username}】 UID：【{uid}】\n任务情况：【{'已签到' if signed=='true' else '本次执行'}】 连签天数：【{days}】\n\n【任务情况】\n签到：【{'已签到' if signed=='true' else '成功'}】 +{sign_points}\n个人空间：【{'成功' if own_ok else '失败'}】\n他人空间：【成功{other_ok}次】\n\n【积分情况】\n积分变化：【{start} -> {final_credits}】")
main_guard(main)
