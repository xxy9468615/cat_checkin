#!/usr/bin/env python3
# cron: 55 9 * * *
# new Env("Tencent CloudStudio 签到")
import datetime as dt
from common import Http, env, find, findall, main_guard, mask_str
PREFIX = "CLOUDSTUDIO_"
def main():
    print("【Tencent CloudStudio 签到】")
    cookie=env(PREFIX,"cookie"); xsrf=env(PREFIX,"xsrf")
    headers={"Cookie":cookie,"X-XSRF-TOKEN":xsrf,"Referer":"https://cloudstudio.net/"}; h=Http()
    # Cookie 失效时 user/info 会 302 到登录页，签到接口返回 401 user_not_authentication
    u = h.request("GET", "https://cloudstudio.net/api/user/info", headers=headers)
    if u.code in (301, 302, 303, 307, 308) or u.code == 401:
        raise RuntimeError(f"Cookie 已失效（user/info HTTP {u.code}），请更新 CLOUDSTUDIO_cookie / CLOUDSTUDIO_xsrf")
    if u.code >= 400 or u.code < 0:
        raise RuntimeError(f"用户信息接口响应异常 HTTP {u.code}: {u.text[:120]}")
    if "nickName" not in u.text:
        raise RuntimeError(f"用户信息解析失败（未包含 nickName）: {u.text[:120]}")
    nick=find(r'"nickName":"(.*?)"',u.text,"?")
    s=h.request("POST","https://cloudstudio.net/api/billing/activityTask/SIGN_IN_2025Q3/_reward",headers=headers,json_data={})
    if s.code >= 400:
        msg=find(r'"msg":"(.*?)"',s.text,s.text[:120])
        raise RuntimeError(f"签到接口 HTTP {s.code}: {msg}")
    # 首次签到 records 含奖励记录；今日已签到过则 records 为空数组
    reward=int(find(r'"rewardNum":(\d+)',s.text,"0"))/100000000
    status=f"签到成功，获得 {reward:.2f} 机时" if reward>0 else "今日已签到过"
    p_resp = h.request("GET", "https://cloudstudio.net/api/billing/resource/package?pageNumber=0&pageSize=10", headers=headers)
    p = p_resp.text
    pkg_list = []
    json_data = p_resp.json({})
    if isinstance(json_data, dict) and isinstance(json_data.get("data"), dict) and isinstance(json_data["data"].get("list"), list):
        for item in json_data["data"]["list"]:
            name = item.get("name", "")
            total = float(item.get("total", 0)) / 100000000
            used = float(item.get("used", 0)) / 100000000
            exp = str(item.get("expiredTime", "")).replace("T", " ").replace(".000+00:00", "")
            pkg_list.append({"name": name, "total": total, "used": used, "exp": exp})
    else:
        names = findall(r'"name":"(.*?)"', p)
        totals = findall(r'"total":(\d+)', p)
        useds = findall(r'"used":(\d+)', p)
        exps = findall(r'"expiredTime":"(.*?)"', p)
        for i, name in enumerate(names):
            total = int(totals[i]) / 100000000 if i < len(totals) else 0
            used = int(useds[i]) / 100000000 if i < len(useds) else 0
            exp = (exps[i] if i < len(exps) else "").replace("T", " ").replace(".000+00:00", "")
            pkg_list.append({"name": name, "total": total, "used": used, "exp": exp})

    bj_now = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    lines = [f"用户 {mask_str(nick)} {status}"]
    if not pkg_list:
        lines.append("暂无可用资源包")
    else:
        groups = {}
        total_rem_sum = 0.0
        total_cap_sum = 0.0
        for item in pkg_list:
            name = item["name"]
            total = item["total"]
            used = item["used"]
            rem = max(0.0, total - used)
            exp = item["exp"]
            total_rem_sum += rem
            total_cap_sum += total
            if name not in groups:
                groups[name] = {"count": 0, "total": 0.0, "used": 0.0, "exps": [], "active_exps": []}
            g = groups[name]
            g["count"] += 1
            g["total"] += total
            g["used"] += used
            if exp:
                g["exps"].append(exp)
                if rem > 0 and exp >= bj_now:
                    g["active_exps"].append(exp)

        tot_cap_str = f"{int(total_cap_sum)}" if total_cap_sum.is_integer() else f"{total_cap_sum:.2f}"
        lines.append(f"可用资源总计：剩余 {total_rem_sum:.2f} / {tot_cap_str} 机时")

        for name, g in groups.items():
            count = g["count"]
            tot = g["total"]
            used = g["used"]
            rem = max(0.0, tot - used)
            valid_exps = g["active_exps"] or g["exps"]
            earliest_exp = min(valid_exps) if valid_exps else ""
            exp_date = earliest_exp.split(" ")[0] if earliest_exp else ""
            exp_info = f"，最早 {exp_date} 到期" if (count > 1 and exp_date) else (f"，{exp_date} 到期" if exp_date else "")

            tot_str = f"{int(tot)}" if tot.is_integer() else f"{tot:.2f}"
            lines.append(f"• {name} ({count}个包): 剩余 {rem:.2f}/{tot_str} 机时{exp_info}")

    print("\n".join(lines))
main_guard(main)
