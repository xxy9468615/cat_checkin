#!/usr/bin/env python3
# cron: 55 9 * * *
# new Env("Tencent CloudStudio 签到")
"""Tencent CloudStudio (cloudstudio.net) 每日签到脚本。

协议逆向结论（2026-08-24，HAR + main-*.js 前端包分析）：
- 认证体系：业务活动与账单端点强制依赖 Cookie 会话（cloudstudio-session）。
  控制台生成的个人访问令牌（API Key / OpenToken）归属于 Open API 开放生态/应用管理体系，
  传入业务接口会被网关判定为工作空间容器专用的 Workspace Token 而报 1044 错误，无法用于活动签到。
- Keycloak SSO 滚动续期链（2026-08-29 升级：主动续票 + 全量 Cookie 持久化）：
  当 Cookie 中包含 KEYCLOAK_IDENTITY / KEYCLOAK_SESSION 长期 SSO 票据（约 1 年有效期）时，
  脚本每次运行都会先请求 /api/public/login 重定向至 Keycloak OIDC 端点无感换取最新
  session（30 天期）——短期 session 每天滚动换新，长期票据保持新鲜；签到成功后再把
  本次链路全部 Set-Cookie（含 KEYCLOAK_*）合并持久化到 Upstash Redis
  （cat_checkin:state:cloudstudio_{idx}）与本地 JSON 状态，跨 CI 滚动续期。
  只有裸 cloudstudio-session 的配置无法 SSO 续票，30 天后仍会失效（报错给出精确指引）。
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
  CLOUDSTUDIO_cookie    完整浏览器 Cookie（必须包含 cloudstudio-session；推荐同时包含
                        KEYCLOAK_IDENTITY / KEYCLOAK_SESSION 长期票以启用 SSO 滚动续期，必填）
  CLOUDSTUDIO_COOKIE_1  序列多账号
  CLOUDSTUDIO_xsrf      X-XSRF-TOKEN 覆盖值（可选；缺省自动按 Vq() 派生）
"""
import datetime as dt
import hashlib
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

from common import Http, env_seq, find, findall, load_kv_state, main_guard, mask_str, save_kv_state

PREFIX = "CLOUDSTUDIO_"
BASE = "https://cloudstudio.net/api"
ACTIVITY = "SIGN_IN_2025Q3"


def _get_proxy() -> str:
    return (os.getenv("CLOUDSTUDIO_PROXY") or "").strip()


def derive_xsrf(session: str) -> str:
    """复刻前端 Vq()：djb2 变体哈希 session cookie → X-XSRF-TOKEN。"""
    t = 5381
    for ch in session:
        t += (t << 5) + ord(ch)
    return str(t & 2147483647)


def extract_session(raw_cookie: str) -> str:
    """兼容裸 session 值、含 cloudstudio-session= 的键值对 或 完整浏览器 Cookie 字符串。"""
    raw = raw_cookie.strip()
    if not raw:
        return ""
    m = re.search(r"cloudstudio-session=([^;\s]+)", raw, re.IGNORECASE)
    if m:
        return m.group(1).rstrip(";")
    if raw.startswith("s:") or raw.startswith("s%3A"):
        return raw.split(";")[0].strip()
    if ";" not in raw and not re.search(r"^[a-zA-Z0-9_-]+=", raw):
        return raw
    return ""


def _merge_cookie_str(base: str, jar: Any) -> str:
    """合并已有 Cookie 串与 urllib CookieJar 中的最新 Set-Cookie（同名覆盖）。"""
    cookie_dict: Dict[str, str] = {}
    if base:
        for part in base.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k.strip():
                    cookie_dict[k.strip()] = v.strip()
    for c in jar or ():
        if getattr(c, "name", None) and getattr(c, "value", None):
            cookie_dict[c.name] = c.value
    return "; ".join(f"{k}={v}" for k, v in cookie_dict.items())


def _set_session_in_cookie(cookie_str: str, session: str) -> str:
    """强制覆写 cookie 串中的 cloudstudio-session 值（无则追加），保留其余票据。"""
    parts = [
        p.strip()
        for p in (cookie_str or "").split(";")
        if "=" in p
        and p.strip().split("=", 1)[0].strip()
        and p.strip().split("=", 1)[0].strip().lower() != "cloudstudio-session"
    ]
    parts.append(f"cloudstudio-session={session}")
    return "; ".join(parts)


def try_keycloak_sso(raw_cookie: str) -> Tuple[bool, str, str]:
    """尝试利用包含 KEYCLOAK_IDENTITY / KEYCLOAK_SESSION 长期票据的完整 Cookie 静默重换 session。

    返回 (是否成功, 新 session, 合并了本次 SSO 全部 Set-Cookie 的完整 Cookie 串)。
    合并结果即使换票失败也返回——其中 KEYCLOAK_* 票据的更新对后续重试仍有价值。
    """
    if not raw_cookie or "=" not in raw_cookie:
        return False, "", raw_cookie or ""
    h = Http(follow_redirects=True, proxy=_get_proxy())
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Referer": "https://cloudstudio.net/",
        "Cookie": raw_cookie,
    }
    url = "https://cloudstudio.net/api/public/login?client_id=cloudstudio-apiserver-club"
    r = h.request("GET", url, headers=headers)
    merged = _merge_cookie_str(raw_cookie, h.jar)
    for c in h.jar:
        if c.name == "cloudstudio-session" and c.value:
            return True, c.value, merged
    print(
        f"    [diag] SSO 未取到新 session（HTTP {r.code}，最终 URL: {r.url}）——"
        "KEYCLOAK 长期票据可能已失效或被要求交互式重新登录"
    )
    return False, "", merged


def _cookie_issue_hint(raw_cookie: str) -> str:
    """根据 Secrets 中 Cookie 的形态给出精确的失效原因与修复指引。"""
    raw = (raw_cookie or "").strip()
    if not raw:
        return "CLOUDSTUDIO_cookie 未配置"
    if "=" not in raw:
        return (
            "Secrets 中只有裸 cloudstudio-session 值，无法进行 Keycloak SSO 自动续票"
            "（30 天后必失效）。请重新登录后复制完整浏览器 Cookie：必须包含 "
            "KEYCLOAK_IDENTITY、KEYCLOAK_SESSION 与 cloudstudio-session 三项"
            "（KEYCLOAK_* 路径限定在 /auth/realms/cloudstudio/，需从 Network 面板任一请求"
            "的 Cookie 请求头整串复制，或在 Application→Cookies 中逐条合并）"
        )
    if "KEYCLOAK_IDENTITY" not in raw:
        return (
            "完整 Cookie 中缺少 KEYCLOAK_IDENTITY 长期票（1 年期 SSO 票据，路径 "
            "/auth/realms/cloudstudio/）。document.cookie 读不到路径限定的 Cookie，"
            "请从 Network 面板任一请求的 Cookie 请求头整串复制，或 "
            "Application→Cookies→cloudstudio.net 中合并 /auth/realms/cloudstudio "
            "路径下的 KEYCLOAK_IDENTITY 与 KEYCLOAK_SESSION"
        )
    if "cloudstudio-session" not in raw:
        return "完整 Cookie 中缺少 cloudstudio-session，请重新登录后整串复制"
    return (
        "KEYCLOAK 长期票据已无法静默换票（可能已被服务端吊销或要求交互式重新登录）。"
        "请在浏览器重新登录 CloudStudio 后整串复制最新完整 Cookie 更新 Secrets"
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


def _do_checkin_and_query(session: str, xsrf_override: str) -> Tuple[bool, str, Http]:
    xsrf = xsrf_override or derive_xsrf(session)
    headers = {
        "Cookie": f"cloudstudio-session={session}",
        "X-XSRF-TOKEN": xsrf,
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "https://cloudstudio.net/",
    }
    h = Http(proxy=_get_proxy())

    # === 1. 签到两段式：先查今日记录，再决定是否领取 ===
    today = bj_now_str()[:10]
    # 优先新接口（全量任务列表），兼容旧接口（按 ACTIVITY ID 查询）
    q = h.request("GET", f"{BASE}/billing/activityTask?lastRecord=true", headers=headers)

    if q.code in (401, 403) or q.code in (301, 302, 303, 307, 308):
        return False, f"AUTH_EXPIRED_{q.code}", h
    qjson = q.json({}) or {}
    if qjson.get("code") in (1022, 1044):
        return False, f"AUTH_EXPIRED_{qjson.get('code')}", h

    status, record = "", {}
    if q.code == 200:
        data = qjson.get("data")
        records = []
        if isinstance(data, list):
            for task in data:
                if task.get("taskId") == ACTIVITY:
                    records = task.get("records") or []
                    break
        elif isinstance(data, dict):
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
        sdata = sjson.get("data")
        records = []
        if isinstance(sdata, list):
            for task in sdata:
                if task.get("taskId") == ACTIVITY:
                    records = task.get("records") or []
                    break
        elif isinstance(sdata, dict):
            records = sdata.get("records") or []
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
    saved_cookie = str(saved_state.get("cookie") or "").strip()
    saved_session = str(saved_state.get("session") or "").strip()  # 兼容旧版仅存 session 的状态
    saved_env_hash = str(saved_state.get("env_hash") or "").strip()
    raw_session = extract_session(raw_cookie)
    env_hash = hashlib.md5(raw_cookie.encode("utf-8")).hexdigest() if raw_cookie else ""

    # 起始 Cookie：env 更新感知（用户更新了 Secrets → 新 env 优先）；否则滚动 state 优先
    if raw_cookie and env_hash and env_hash != saved_env_hash:
        print(f"[{idx}/{total}] 🆕 检测到环境变量 Cookie 已更新，优先使用最新配置")
        base_cookie = raw_cookie
    else:
        base_cookie = saved_cookie or raw_cookie

    session = extract_session(base_cookie) or raw_session
    if not session and saved_session:
        # 旧版状态迁移：只有裸 session（KEYCLOAK 长期票已丢失，保底使用）
        session = saved_session
        base_cookie = f"cloudstudio-session={saved_session}"

    if not session:
        raise RuntimeError(
            f"CLOUDSTUDIO_cookie 未找到 cloudstudio-session。{_cookie_issue_hint(raw_cookie)}"
        )

    # 主动 Keycloak 续票（滚动续期核心）：每次运行先用长期票据静默换新 session，
    # 让 30 天期 session 永远保持新鲜；换票失败只打诊断，不影响本次签到（当前 session 仍有效）
    if "=" in base_cookie:
        sso_ok, sso_session, merged = try_keycloak_sso(base_cookie)
        if sso_ok and sso_session:
            print(f"[{idx}/{total}] 🔑 SSO 主动续票成功，使用新 session: {sso_session[:12]}***")
            session = sso_session
            base_cookie = merged
        elif not session:
            base_cookie = merged

    ok, report, h = _do_checkin_and_query(session, xsrf_override)
    if not ok and report.startswith("AUTH_EXPIRED"):
        # 回退 1：环境变量中的 session（用户可能刚更新过）
        if raw_session and raw_session != session:
            print(f"[{idx}/{total}] 🔄 session 失效（{report}），回退使用环境变量中的 session...")
            ok, report, h = _do_checkin_and_query(raw_session, xsrf_override)
            if ok:
                session = raw_session
        # 回退 2：Keycloak SSO 重新换票
        if not ok and report.startswith("AUTH_EXPIRED") and "=" in (base_cookie or ""):
            print(f"[{idx}/{total}] 🔄 正在通过 Keycloak SSO 重新换票...")
            sso_ok, new_session, merged = try_keycloak_sso(base_cookie)
            if sso_ok and new_session and new_session != session:
                print(f"[{idx}/{total}] 🔑 SSO 换票成功: {new_session[:12]}***，重新签到...")
                ok, report, h = _do_checkin_and_query(new_session, xsrf_override)
                if ok:
                    session = new_session
                    base_cookie = merged

    if not ok:
        raise RuntimeError(f"Cookie 已失效且自动续票失败。{_cookie_issue_hint(raw_cookie)}")

    # 签到成功：合并本次链路全部 Set-Cookie（含 KEYCLOAK_* 长期票与可能滚动的 session）
    # 持久化——下次运行 SSO 主动续票直接复用长期票据，这是 cookie 长期存活的关键
    merged_full = _merge_cookie_str(_set_session_in_cookie(base_cookie, session), h.jar)
    save_kv_state(
        redis_key,
        state_file,
        {
            "cookie": merged_full,
            "session": extract_session(merged_full) or session,
            "env_hash": env_hash,
            "updated_at": bj_now_str(),
        },
    )

    prefix_label = f"[{idx}/{total}] " if total > 1 else ""
    return True, f"{prefix_label}{report}"


def main():
    print("【Tencent CloudStudio 签到】")
    proxy = _get_proxy()
    if proxy:
        print(f"代理出口: {mask_str(proxy, 6, 3)}")
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
