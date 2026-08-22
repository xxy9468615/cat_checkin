#!/usr/bin/env python3
# cron: 0 10 * * *
# new Env("DJI 大疆社区签到")
import time
from common import Http, env, find, findall, main_guard, mask_str
PREFIX = "DJI_"
def nowms(): return int(time.time()*1000)
def main():
    cookie=env(PREFIX,"cookie"); h=Http(); headers={"Cookie":cookie,"Referer":"https://bbs.dji.com/"}; base="https://bbs.dji.com"
    # 海外 runner 访问国内论坛偶发连不上/极慢，所有请求统一设短超时避免整体卡死
    login=h.request("GET",f"{base}/api/v2/users/login-info?device=desktop&t={nowms()}",headers=headers,timeout=30).text
    uid=find(r'"id":\s*(\d+)',login); uuid=find(r'"uuid":\s*"([^"]+)"',login,""); username=find(r'"name":\s*"([^"]+)"',login,"?"); start=find(r'"credits":\s*(\d+)',login,"?")
    # cookie 失效时 login-info 返回错误体（uid 空），不能继续签到否则假成功
    if not uid or not uuid:
        raise RuntimeError("Cookie 失效（login-info 未返回 uid/uuid），请更新 DJI_cookie")
    st=h.request("GET",f"{base}/api/v2/home/paulsigns/user?device=desktop&t={nowms()}",headers=headers,timeout=30).text
    signed=find(r'"signed":\s*(true|false)',st,"false"); days=find(r'"days":\s*(\d+)',st,"?")
    sign_points="0"
    if signed != "true":
        sr=h.request("POST",f"{base}/api/v2/home/paulsigns/sign?device=desktop",headers=headers,json_data={},timeout=30).text
        sign_points=find(r'"increased":\s*(\d+)',sr,"0")
        # 签到 POST 的响应不校验会假成功（网络错误/业务失败时 increased 缺失）：
        # 复查签到状态，仍未签上则显式失败
        st2=h.request("GET",f"{base}/api/v2/home/paulsigns/user?device=desktop&t={nowms()}",headers=headers,timeout=30).text
        if find(r'"signed":\s*(true|false)',st2,"false") != "true":
            raise RuntimeError(f"签到失败：{sr[:120]}")
        signed="true"
    # 浏览空间(赚积分, 非核心签到): 海外 runner 访问国内论坛偶发慢/超时,
    # 用较短超时 + 总时长上限保护, 即使全失败也不影响核心签到与整体结果。
    own_ok=False; other_ok=0
    browse_deadline=time.monotonic()+60
    try:
        if uid and uuid and time.monotonic()<=browse_deadline:
            own_ok=h.request("GET",f"{base}/pro/user-center?uid={uid}&uuid={uuid}&do=thread",headers=headers,timeout=20).code==200
        if time.monotonic()<=browse_deadline:
            threads=h.request("GET",f"{base}/api/v2/forum/thread/list?device=desktop&channel_slug=home-square-all&limit=10&offset=10&sort_type=latest_posts",headers=headers,timeout=20).text
            uids=findall(r'"author":\{"id":(\d+),"uuid":"[^"]+"',threads); uuids=findall(r'"author":\{"id":\d+,"uuid":"([^"]+)"',threads)
            for auid, auuid in list(zip(uids,uuids))[:10]:
                if time.monotonic()>browse_deadline: break
                try:
                    if h.request("GET",f"{base}/pro/user-center?uid={auid}&uuid={auuid}",headers=headers,timeout=20).code==200: other_ok+=1
                except Exception:
                    pass
    except Exception:
        pass
    final=h.request("GET",f"{base}/api/v2/users/login-info?device=desktop&t={nowms()}",headers=headers,timeout=30).text
    final_credits=find(r'"credits":\s*(\d+)',final,"?")
    print("【DJI 大疆社区签到】")
    masked_user = mask_str(username)
    masked_uid = mask_str(uid)
    print(f"【个人信息】\n用户：【{masked_user}】 UID：【{masked_uid}】\n任务情况：【{'已签到' if signed=='true' else '本次执行'}】 连签天数：【{days}】\n\n【任务情况】\n签到：【{'已签到' if signed=='true' else '成功'}】 +{sign_points}\n个人空间：【{'成功' if own_ok else '失败'}】\n他人空间：【成功{other_ok}次】\n\n【积分情况】\n积分变化：【{start} -> {final_credits}】")
if __name__ == "__main__":
    main_guard(main)
