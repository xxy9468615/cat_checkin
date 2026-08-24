#!/usr/bin/env python3
# cron: 55 9 * * *
# new Env("Tencent CloudStudio 签到")
"""Tencent CloudStudio (cloudstudio.net) 每日签到脚本。

协议逆向结论（2026-08-24，HAR + main-*.js 前端包分析）：
- 认证体系：业务活动与账单端点强制依赖 Cookie 会话（cloudstudio-session）。
  控制台生成的个人访问令牌（API Key / OpenToken）归属于 Open API 开放生态/应用管理体系，
  传入业务接口会被网关判定为工作空间容器专用的 Workspace Token 而报 1044 错误，无法用于活动签到。
- Keycloak SSO 自动换票与续期链（2026-08-25 升级）：
  当环境变量传入完整 Cookie（包含 KEYCLOAK_IDENTITY 长期 SSO 票据）时，若 session 过期，
  脚本将自动请求 /api/public/login 重定向至 Keycloak OIDC 端点无感换取最新 session，
  并通过 Upstash Redis（cat_checkin:state:cloudstudio_{idx}）与本地 JSON 状态跨 CI 自动滚动续期。
- X-XSRF-TOKEN 无需人工复制：前端拦截器对每个请求自动计算
  Vq() = djb2 变体哈希（t=5381; t+=(t<<5)+charCode）& 0x7fffffff，
  输入取 cookie skey || cloudstudio-session。本脚本按同算法派生。
- 签到两段式（与前端一致）：
  1. GET  /api/billing/activityTask/SIGN_IN_2025Q3?lastRecord=true 查记录状态
     （NOT_STARTED/IN_PROGRESS/COMPLETED/FAILED/REWARDING/REWARDED/REWARD_FAILED）
  2. 可领取（COMPLETED/REWARD_FAILED）→ POST /api/billing/activityTask/SIGN_IN_2025Q3/_reward
     今日记录已 REWARDED → 幂等放行；rewardNum 单位为亿分之一机时（1e8 = 1 机时）
- 资源汇总：GET /api/billing/resource/_summary（total/used/remaining）；
  明细列表沿用 GET /api/billing/resource/package?pageNumber=0&pageSize=10。

支持环境变量：
  CLOUDSTUDIO_cookie    cloudstudio-session 完整值（或包含它的完整浏览器 Cookie，必填）
  CLOUDSTUDIO_COOKIE_1  序列多账号
  CLOUDSTUDIO_xsrf      X-XSRF-TOKEN 覆盖值（可选；缺省自动按 Vq() 派生）
"""
import datetime as dt
import re
import sys
from typing import Dict, List, Optional, Tuple

from common import Http, env_seq, find, findall, load_kv_state, main_guard, mask_str, save_kv_state

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
    if "=" not in raw:
        return raw
    return ""


def try_keycloak_sso(raw_cookie: str) -> Tuple[bool, str]:
    """尝试利用包含 KEYCLOAK_IDENTITY / 会话票据的完整 Cookie 重换 session。"""
    if not raw_cookie or "=" not in raw_cookie:
        return False, ""
    h = Http(follow_redirects=True)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Referer": "https://cloudstudio.net/",
        "Cookie": raw_cookie,
    }
    url = "https://cloudstudio.net/api/public/login?client_id=cloudstudio-apiserver-club"
    r = h.request("GET", url, headers=headers)
    for c in h.jar:
        if c.name == "cloudstudio-session" and c.value:
            return True, c.value
    return False, ""


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


def _do_checkin_and_query(session: str, xsrf_override: str) -> Tuple[bool, str, Http]:
    xsrf = xsrf_override or derive_xsrf(session)
    headers = {
        "Cookie": f"cloudstudio-session={session}",
        "X-XSRF-TOKEN": xsrf,
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "https://cloudstudio.net/",
    }
    h = Http()

    # === 1. 签到两段式：先查今日记录，再决定是否领取 ===
    today = bj_now_str()[:10]
    q = h.request("GET", f"{BASE}/billing/activityTask/{ACTIVITY}?lastRecord=true", headers=headers)

    if q.code in (401, 403) or q.code in (301, 302, 303, 307, 308):
        return False, f"AUTH_EXPIRED_{q.code}", h
    qjson = q.json({}) or {}
    if qjson.get("code") in (1022, 1044):
        return False, f"AUTH_EXPIRED_{qjson.get('code')}", h

    status, record = "", {}
    if q.code == 200:
        data = qjson.get("data") or {}
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
            return False, f"AUTH_EXPIRED_{s.code}", h
        sjson = s.json({}) or {}
        if sjson.get("code") in (1022, 1044):
            return False, f"AUTH_EXPIRED_{sjson.get('code')}", h
        if s.code >= 400 or s.code < 0:
            msg = find(r'"msg":"(.*?)"', s.text, s.text[:120])
            raise RuntimeError(f"签到接口 HTTP {s.code}: {msg}")
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

    # nick 仅用于报告展示
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
            name, total_val, used_val, exp = item["name"], item["total"], item["used"], item["exp"]
            rem = max(0.0, total_val - used_val)
            total_rem_sum += rem
            total_cap_sum += total_val
            g = groups.setdefault(name, {"count": 0, "total": 0.0, "used": 0.0,
                                         "exps": [], "active_exps": []})
            g["count"] += 1
            g["total"] += total_val
            g["used"] += used_val
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

    return True, "\n".join(lines), h


def _run_one(raw_cookie: str, xsrf_override: str, idx: int, total: int) -> Tuple[bool, str]:
    state_file = f".cloudstudio_state_{idx}.json"
    redis_key = f"cat_checkin:state:cloudstudio_{idx}"
    saved_state = load_kv_state(redis_key, state_file) or {}
    saved_session = str(saved_state.get("session") or "").strip()

    session = saved_session or extract_session(raw_cookie)
    if not session:
        # 无直接 session，尝试从 raw_cookie 进行 Keycloak SSO 换票
        sso_ok, sso_session = try_keycloak_sso(raw_cookie)
        if sso_ok:
            session = sso_session
            print(f"[{idx}/{total}] 🔑 通过 Keycloak SSO 初始化换取到最新 session: {session[:12]}***")
            save_kv_state(redis_key, state_file, {"session": session, "updated_at": bj_now_str()})

    if not session:
        raise RuntimeError(
            "CLOUDSTUDIO_cookie 未找到 cloudstudio-session，且无法通过 SSO 自动登录。"
            "请在浏览器重新登录后更新 CLOUDSTUDIO_cookie（建议粘贴包含 KEYCLOAK_IDENTITY 的整串 Cookie 以支持长期免维护）"
        )

    ok, report, h = _do_checkin_and_query(session, xsrf_override)
    if not ok and report.startswith("AUTH_EXPIRED"):
        # Session 过期，尝试通过 Keycloak SSO 续期
        print(f"[{idx}/{total}] 🔄 session 已过期（{report}），正在尝试通过 Keycloak SSO 自动换取新 session...")
        sso_ok, new_session = try_keycloak_sso(raw_cookie)
        if sso_ok and new_session != session:
            session = new_session
            print(f"[{idx}/{total}] 🔑 SSO 续期成功，获取到新 session: {session[:12]}***，正在重新签到...")
            save_kv_state(redis_key, state_file, {"session": session, "updated_at": bj_now_str()})
            ok, report, h = _do_checkin_and_query(session, xsrf_override)

    if not ok:
        raise RuntimeError(
            "Cookie 已失效，请在浏览器重新登录并更新 CLOUDSTUDIO_cookie。"
            "（提示：在浏览器 Network 请求头中复制整串 Cookie 填入 Secrets，即可永久启用 Keycloak SSO 自动续期）"
        )

    # 检查服务端是否在本次请求中下发了最新的 Set-Cookie
    for c in h.jar:
        if c.name == "cloudstudio-session" and c.value and c.value != session:
            session = c.value
            save_kv_state(redis_key, state_file, {"session": session, "updated_at": bj_now_str()})

    prefix_label = f"[{idx}/{total}] " if total > 1 else ""
    return True, f"{prefix_label}{report}"


def main():
    print("【Tencent CloudStudio 签到】")
    cookies = env_seq(PREFIX, "cookie")
    xsrfs = env_seq(PREFIX, "xsrf", required=False)

    total = len(cookies)
    results: List[Tuple[bool, str]] = []

    for idx, c in enumerate(cookies, 1):
        c = c.strip()
        if not c:
            continue
        xsrf = xsrfs[idx - 1].strip() if (idx - 1) < len(xsrfs) else ""
        try:
            ok, msg = _run_one(c, xsrf, idx, total)
            print(msg)
            results.append((ok, msg))
        except Exception as e:
            prefix_label = f"[{idx}/{total}] " if total > 1 else ""
            err_msg = f"{prefix_label}签到失败：{e}"
            print(err_msg)
            results.append((False, err_msg))

    ok_count = sum(1 for ok, _ in results if ok)
    if total > 1:
        print(f"\n========== 签到总结 ==========\n成功 {ok_count}/{total}")

    if ok_count != total:
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
