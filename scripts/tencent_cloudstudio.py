#!/usr/bin/env python3
# cron: 55 9 * * *
# new Env("Tencent CloudStudio 签到")
"""Tencent CloudStudio (cloudstudio.net) 每日签到脚本。

协议逆向结论（2026-08-22，HAR + main-*.js 前端包分析）：
- 认证仍是 Cookie 会话：cloudstudio-session（服务端签发）+ cloudstudio-session-team。
  登录走 Keycloak OIDC（腾讯云/微信/GitHub/手机号验证码），无账密直登接口可程序化复现，
  因此 cookie 过期仍需手动更新 —— 但只需提供 session 一个值。
- X-XSRF-TOKEN 无需人工复制：前端拦截器对每个请求自动计算
  Vq() = djb2 变体哈希（t=5381; t+=(t<<5)+charCode）& 0x7fffffff，
  输入取 cookie skey || cloudstudio-session。本脚本按同算法派生，
  CLOUDSTUDIO_xsrf 仅作为可选覆盖保留（兼容旧配置）。
- 签到两段式（与前端一致）：
  1. GET  /api/billing/activityTask/SIGN_IN_2025Q3?lastRecord=true 查记录状态
     （NOT_STARTED/IN_PROGRESS/COMPLETED/FAILED/REWARDING/REWARDED/REWARD_FAILED）
  2. 可领取（COMPLETED/REWARD_FAILED）→ POST /api/billing/activityTask/SIGN_IN_2025Q3/_reward
     今日记录已 REWARDED → 幂等放行；rewardNum 单位为亿分之一机时（1e8 = 1 机时）
- 资源汇总：GET /api/billing/resource/_summary（total/used/remaining）；
  明细列表沿用 GET /api/billing/resource/package?pageNumber=0&pageSize=10。

支持环境变量：
  CLOUDSTUDIO_cookie  cloudstudio-session 完整值（或含它的整串 Cookie，必填）
  CLOUDSTUDIO_xsrf    X-XSRF-TOKEN 覆盖值（可选；缺省自动按 Vq() 派生）
"""
import datetime as dt
import re

from common import Http, env, find, findall, main_guard, mask_str

PREFIX = "CLOUDSTUDIO_"
BASE = "https://cloudstudio.net/api"
ACTIVITY = "SIGN_IN_2025Q3"


def derive_xsrf(session: str) -> str:
    """复刻前端 Vq()：djb2 变体哈希 session cookie → X-XSRF-TOKEN。"""
    t = 5381
    for ch in session:
        t += (t << 5) + ord(ch)
    return str(t & 2147483647)


def extract_session(raw_cookie: str) -> str:
    """兼容裸 session 值 或 含 cloudstudio-session= 的整串 Cookie。"""
    raw = raw_cookie.strip()
    m = re.search(r"cloudstudio-session=([^;\s]+)", raw)
    if m:
        return m.group(1)
    # 无 cloudstudio-session 键:区分「裸 session 值」与「贴了其他键值对」
    if "=" not in raw:
        # 裸 session 值(无等号),直接当 session 用
        return raw
    # 含键值对但无 cloudstudio-session 键 → 明确报错指引,避免静默构造错误 Cookie(如把 cloudstudio-session-team=xxx 整体当 session → 401)
    keys = [p.split("=", 1)[0].strip() for p in raw.split(";") if "=" in p and p.strip()]
    raise RuntimeError(
        f"CLOUDSTUDIO_cookie 未找到 cloudstudio-session 键（现有键: {keys}）。"
        f"请只贴 cloudstudio-session 的值,或确保整串含 cloudstudio-session=...。"
    )


def bj_now_str() -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")


def bj_date_of_iso(value: str) -> str:
    """ISO8601(UTC) → 北京时间日期串；解析失败返回空。"""
    if not value:
        return ""
    try:
        d = dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
            dt.timezone(dt.timedelta(hours=8))
        )
        return d.strftime("%Y-%m-%d")
    except ValueError:
        return ""


def main():
    print("【Tencent CloudStudio 签到】")
    raw_cookie = env(PREFIX, "cookie")
    session = extract_session(raw_cookie)
    if not session:
        raise RuntimeError("CLOUDSTUDIO_cookie 为空，请填入 cloudstudio-session 的值")
    # 提取结果诊断（仅长度，不打印前缀——session 片段也属凭证）
    print(f"session 提取: 长度 {len(session)}")

    xsrf = env(PREFIX, "xsrf", required=False) or derive_xsrf(session)
    headers = {
        "Cookie": f"cloudstudio-session={session}",
        "X-XSRF-TOKEN": xsrf,
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "https://cloudstudio.net/",
    }
    h = Http()

    # === 1. 签到两段式：先查今日记录，再决定是否领取 ===
    # 不用 /user/info 预判登录态：该端点对 CI 的 session/IP 可能 401，但签到 API 用同一
    # session 可成功（2026-08-22 事故：user/info 401 误判把真实签到 POST 永久跳过，与
    # ai_router「GET 预判字段恒 true 跳过发奖」同型坑）。以签到 API 自身响应为准。
    today = bj_now_str()[:10]
    q = h.request("GET", f"{BASE}/billing/activityTask/{ACTIVITY}?lastRecord=true", headers=headers)
    status, record = "", {}
    if q.code == 200:
        data = (q.json({}) or {}).get("data") or {}
        records = data.get("records") or []
        if records:
            record = records[0]
            status = record.get("status", "")
            # completeTime 非今日的旧记录视为未签（跨日残留）
            if bj_date_of_iso(record.get("completeTime", "")) != today:
                status, record = "", {}

    if status in ("REWARDED", "REWARDING"):
        reward = float(record.get("rewardNum", 0)) / 100000000
        status_line = (
            f"今日已签到过（本次奖励 {reward:.2f} 机时）"
            if reward > 0
            else "今日已签到过"
        )
    else:
        # COMPLETED / REWARD_FAILED / 未查到记录：直接领取，以响应为准
        s = h.request(
            "POST", f"{BASE}/billing/activityTask/{ACTIVITY}/_reward",
            headers=headers, json_data={},
        )
        if s.code in (401, 403) or s.code in (301, 302, 303, 307, 308):
            # 签到 API 本身 401/302 才算 session 真失效（非 user/info 预判）
            raise RuntimeError(
                f"Cookie 已失效（签到接口 HTTP {s.code}），请在浏览器重新登录后更新 CLOUDSTUDIO_cookie"
            )
        if s.code >= 400 or s.code < 0:
            msg = find(r'"msg":"(.*?)"', s.text, s.text[:120])
            raise RuntimeError(f"签到接口 HTTP {s.code}: {msg}")
        sjson = s.json({}) or {}
        records = ((sjson.get("data") or {}).get("records")) or []
        rec = records[0] if records else {}
        reward = float(rec.get("rewardNum", 0) or 0) / 100000000
        fail_msg = rec.get("failMessage") or sjson.get("msg") or ""
        if reward > 0:
            status_line = f"签到成功，获得 {reward:.2f} 机时"
        elif rec.get("status") in ("REWARDED", "REWARDING"):
            status_line = "今日已签到过"
        else:
            raise RuntimeError(f"签到未到账: status={rec.get('status')} {fail_msg}"[:160])

    # nick 仅用于报告展示:签到成功后带同 cookie 再探 user/info,非阻断(401/失败不中断)
    nick = "?"
    u = h.request("GET", f"{BASE}/user/info", headers=headers)
    if u.code == 200:
        ujson = u.json({})
        auth = (ujson.get("data") or {}).get("authenticationUserInfo") or {} if isinstance(ujson, dict) else {}
        nick = auth.get("nickName") or find(r'"nickName":"(.*?)"', u.text, "?")

    # === 3. 资源汇总 + 明细 ===
    p_resp = h.request(
        "GET", f"{BASE}/billing/resource/package?pageNumber=0&pageSize=10", headers=headers
    )
    pkg_list = []
    json_data = p_resp.json({})
    if isinstance(json_data, dict) and isinstance(json_data.get("data"), dict) \
            and isinstance(json_data["data"].get("list"), list):
        for item in json_data["data"]["list"]:
            pkg_list.append({
                "name": item.get("name", ""),
                "total": float(item.get("total", 0)) / 100000000,
                "used": float(item.get("used", 0)) / 100000000,
                "exp": str(item.get("expiredTime", "")).replace("T", " ").replace(".000+00:00", ""),
            })

    summary = h.request("GET", f"{BASE}/billing/resource/_summary", headers=headers)
    sum_total = sum_remain = None
    sdata = (summary.json({}) or {}).get("data") or {}
    pkg = sdata.get("package") if isinstance(sdata, dict) else None
    if isinstance(pkg, dict):
        sum_total = float(pkg.get("total", 0)) / 100000000
        sum_remain = float(pkg.get("remaining", 0)) / 100000000

    # === 4. 报告输出 ===
    bj_now = bj_now_str()
    lines = [f"用户 {mask_str(nick)} {status_line}"]
    if not pkg_list:
        lines.append("暂无可用资源包")
    else:
        groups = {}
        total_rem_sum = 0.0
        total_cap_sum = 0.0
        for item in pkg_list:
            name, total, used, exp = item["name"], item["total"], item["used"], item["exp"]
            rem = max(0.0, total - used)
            total_rem_sum += rem
            total_cap_sum += total
            g = groups.setdefault(name, {"count": 0, "total": 0.0, "used": 0.0,
                                         "exps": [], "active_exps": []})
            g["count"] += 1
            g["total"] += total
            g["used"] += used
            if exp:
                g["exps"].append(exp)
                if rem > 0 and exp >= bj_now:
                    g["active_exps"].append(exp)

        tot_cap_str = f"{int(total_cap_sum)}" if total_cap_sum.is_integer() else f"{total_cap_sum:.2f}"
        lines.append(f"可用资源总计：剩余 {total_rem_sum:.2f} / {tot_cap_str} 机时")
        if sum_total is not None:
            lines.append(f"服务端汇总：剩余 {sum_remain:.2f} / {sum_total:.2f} 机时")

        for name, g in groups.items():
            rem = max(0.0, g["total"] - g["used"])
            valid_exps = g["active_exps"] or g["exps"]
            earliest_exp = min(valid_exps) if valid_exps else ""
            exp_date = earliest_exp.split(" ")[0] if earliest_exp else ""
            count = g["count"]
            tot = g["total"]
            exp_info = (
                f"，最早 {exp_date} 到期" if (count > 1 and exp_date)
                else (f"，{exp_date} 到期" if exp_date else "")
            )
            tot_str = f"{int(tot)}" if tot.is_integer() else f"{tot:.2f}"
            lines.append(f"• {name} ({count}个包): 剩余 {rem:.2f}/{tot_str} 机时{exp_info}")

    print("\n".join(lines))


main_guard(main)
