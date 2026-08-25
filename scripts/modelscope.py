#!/usr/bin/env python3
# cron: 0 10 * * *
# new Env("ModelScope 社区签到")
# new Env("ModelScope 国际站 签到")
"""ModelScope 魔搭社区每日签到（国内站 + 国际站分开处理）。

机制：登录奖励（每日 200 魔粒）在用户产生活跃会话后被动发放。
接口路径已变更：magic_cube → magicubes（2026-08 前后迁移）。
判断字段：today_used > 0 表示今日已领取；余额增长为辅助判据。

多认证与长效支持（2026-08 升级）：
1. SDK 访问令牌（Access Token / API Token）直连：
   支持 MODELSCOPE_TOKEN / MODELSCOPE_TOKEN_1 等，通过 Authorization: Bearer 头鉴权，
   有效期长，无需担心 Cookie 频繁过期。
2. Cookie 滑动续期与持久化：
   对于使用 MODELSCOPE_COOKIE 的账号，自动捕获服务端 Set-Cookie 并通过 Upstash Redis
   及本地 state 进行每日滚动续期（解决 source 1 天过期问题）。
3. 会话触碰：访问 personal overview 与模型/数据集接口，触发「日活」埋点。
4. 渐进式退避复查（8s→15s→25s），双判据保障。

环境变量：
  MODELSCOPE_TOKEN / MODELSCOPE_TOKEN_1, _2...：SDK 访问令牌（国内站，推荐）
  MODELSCOPE_COOKIE / MODELSCOPE_COOKIE_1, _2...：Cookie（国内站）
  MODELSCOPE_AI_TOKEN / MODELSCOPE_AI_COOKIE：国际站专用 Token / Cookie
  MODELSCOPE_HOST：国内站主机（默认 www.modelscope.cn）
  MODELSCOPE_AI_HOST：国际站主机（默认 www.modelscope.ai）
"""
from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from common import Http, env, env_seq, load_kv_state, main_guard, mask_str, save_kv_state

PREFIX = "MODELSCOPE_"

# daily_active 奖励未到账时的渐进式复查间隔（秒）：逐次递增，控制多账号总等待时间
RETRY_WAITS = [8, 15, 25]


DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def _default_host() -> str:
    return os.getenv("MODELSCOPE_HOST", "www.modelscope.cn").strip() or "www.modelscope.cn"


def _ai_host() -> str:
    return os.getenv(f"{PREFIX}AI_HOST", "www.modelscope.ai").strip() or "www.modelscope.ai"


def _merge_cookies(existing_cookie: Optional[str], jar: Any) -> str:
    """合并已有 Cookie 与 urllib CookieJar 中的最新 Set-Cookie。"""
    cookie_dict: Dict[str, str] = {}
    if existing_cookie:
        for part in existing_cookie.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k.strip():
                    cookie_dict[k.strip()] = v.strip()
    for c in jar:
        if getattr(c, "name", None):
            cookie_dict[c.name] = c.value
    return "; ".join(f"{k}={v}" for k, v in cookie_dict.items())


def _headers(
    host: str, token: Optional[str] = None, cookie: Optional[str] = None
) -> Dict[str, str]:
    """构造带浏览器上下文或 Token 鉴权的请求头，避免被风控/埋点中间件忽略。"""
    headers = {
        "Origin": f"https://{host}",
        "Referer": f"https://{host}/my/overview",
        "User-Agent": DEFAULT_UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["OpenAPI-Token"] = token
        headers["X-Modelfun-Token"] = token
    if cookie:
        headers["Cookie"] = cookie
    return headers


def _touch_user(
    h: Http, host: str, token: Optional[str] = None, cookie: Optional[str] = None
) -> Dict[str, Any]:
    """全链路触碰会话并验证登录态。

    1. 若有 Cookie，访问个人中心 Web 页面与首页，触发 Web 端活跃埋点中间件。
    2. 访问 OpenAPI 模型与数据集轻量端点，激活用户活动。
    3. GET /openapi/v1/users/me 验证登录态并提取用户信息。
    """
    if cookie:
        web_headers = {
            "User-Agent": DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"https://{host}/",
            "Cookie": cookie,
        }
        try:
            h.request("GET", f"https://{host}/my/overview", headers=web_headers, timeout=15)
            h.request("GET", f"https://{host}/", headers=web_headers, timeout=15)
        except Exception:
            pass

    hdrs = _headers(host, token=token, cookie=cookie)
    try:
        h.request(
            "GET",
            f"https://{host}/openapi/v1/models?page_number=1&page_size=5",
            headers=hdrs,
            timeout=15,
        )
        h.request(
            "GET",
            f"https://{host}/openapi/v1/datasets?page_number=1&page_size=5",
            headers=hdrs,
            timeout=15,
        )
    except Exception:
        pass

    resp = h.request(
        "GET",
        f"https://{host}/openapi/v1/users/me",
        headers=hdrs,
        timeout=20,
    )
    data = resp.json({})
    if resp.code in (401, 403) or (isinstance(data, dict) and data.get("code") in (401, 403)):
        auth_type = (
            "Token"
            if token and not cookie
            else ("Cookie" if cookie and not token else "Token / Cookie")
        )
        raise RuntimeError(
            f"{auth_type} 已失效/未登录 (HTTP {resp.code})，请重新获取 {host} 的访问凭证"
        )
    if not data or not data.get("success"):
        raise RuntimeError(f"users/me 返回异常：{resp.text[:200]}")
    user = data.get("data", {})
    if not isinstance(user, dict):
        raise RuntimeError(f"users/me 数据结构异常：{resp.text[:200]}")
    return user


def _get_rules(
    h: Http, host: str, token: Optional[str] = None, cookie: Optional[str] = None
) -> Dict[str, Any]:
    """获取 earn 规则，返回 daily_active 规则字典。"""
    resp = h.request(
        "GET",
        f"https://{host}/openapi/v1/magicubes/earn/rules",
        headers=_headers(host, token=token, cookie=cookie),
        timeout=20,
    )
    if resp.code != 200:
        raise RuntimeError(f"earn/rules 请求失败：HTTP {resp.code}")
    data = resp.json()
    if not data or not data.get("success"):
        raise RuntimeError(f"earn/rules 返回异常：{resp.text[:200]}")
    for r in data.get("data", []):
        if r.get("rule_key") == "daily_active":
            return r
    raise RuntimeError("未找到 daily_active 规则")


def _get_balance(
    h: Http, host: str, token: Optional[str] = None, cookie: Optional[str] = None
) -> Optional[int]:
    """查询魔粒余额（int），失败返回 None。"""
    resp = h.request(
        "GET",
        f"https://{host}/openapi/v1/magicubes/balance",
        headers=_headers(host, token=token, cookie=cookie),
        timeout=20,
    )
    if resp.code != 200:
        return None
    bal_data = resp.json()
    if not bal_data or not bal_data.get("success"):
        return None
    raw = bal_data.get("data", {}).get("available_balance")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _resolve_cookie(env_cookie: str, idx: int, site: str) -> Tuple[str, str]:
    """解析某账号的最终 Cookie：滚动 state（远端权威、每日刷新 source）优先于环境变量。

    返回 (cookie, cookie来源标签)；state 与 env 皆空时返回 ("", "")。
    优先级依据：state 里的 Cookie 是上一次 run 合并 Set-Cookie 后的最新滚动版本，
    比人工粘贴的 env Cookie 更新鲜。
    """
    state_file = f".modelscope_{site}_state_{idx}.json"
    redis_key = f"cat_checkin:state:modelscope_{site}_{idx}"
    saved_state = load_kv_state(redis_key, state_file)
    state_cookie = str((saved_state or {}).get("cookie", "") or "").strip()
    if state_cookie:
        return state_cookie, "state"
    if env_cookie:
        return env_cookie, "env"
    return "", ""


def _load_accounts(site: str = "cn") -> List[Dict[str, Any]]:
    """加载指定站点（cn / ai）的所有账号凭证，支持 Token 与 Cookie 混合、多账号索引扫描及 Redis 滚动状态。

    凭证优先级：**Cookie 优先，Token 回退**（2026-08-25 修复）。
    实测 Bearer Token 虽能通过 OpenAPI 鉴权，但 OpenAPI 调用不计入「日活」，
    daily_active 每日魔粒不会发放；只有 Web 会话（Cookie）活动才触发奖励。
    故同时配置 Token 与 Cookie 时，一律走 Cookie（state 滚动续期版本优先）。
    """
    accounts: List[Dict[str, Any]] = []
    seen = set()

    if site == "cn":
        prefixes = [PREFIX, f"QL_{PREFIX}"]
        token_keys = ["TOKEN", "API_TOKEN", "ACCESS_TOKEN", "SDK_TOKEN"]
        cookie_keys = ["COOKIE", "COOKIES"]
    else:
        prefixes = [
            f"{PREFIX}AI_",
            f"{PREFIX}ai_",
            f"QL_{PREFIX}AI_",
            f"QL_{PREFIX}ai_",
        ]
        token_keys = ["TOKEN", "API_TOKEN", "ACCESS_TOKEN", "SDK_TOKEN"]
        cookie_keys = ["COOKIE", "COOKIES"]

    # 1. 扫描 1..20 显式序号
    for idx in range(1, 21):
        token_val = ""
        env_cookie_val = ""

        # 同时收集环境变量中的 Token 与 Cookie（不再因 Token 存在而跳过 Cookie）
        for pfx in prefixes:
            if not token_val:
                for k in token_keys:
                    token_val = (
                        os.getenv(f"{pfx}{k}_{idx}")
                        or os.getenv(f"{pfx}{k.lower()}_{idx}")
                        or ""
                    ).strip()
                    if token_val:
                        break
            if not env_cookie_val:
                for k in cookie_keys:
                    env_cookie_val = (
                        os.getenv(f"{pfx}{k}_{idx}")
                        or os.getenv(f"{pfx}{k.lower()}_{idx}")
                        or ""
                    ).strip()
                    if env_cookie_val:
                        break

        # Cookie 解析：滚动 state（远端权威）优先于 env（详见 _resolve_cookie）
        cookie_val, _src = _resolve_cookie(env_cookie_val, idx, site)
        token_val = token_val.strip()
        if token_val or cookie_val:
            ident = cookie_val or token_val
            if ident not in seen:
                seen.add(ident)
                # Cookie 优先：Bearer Token 不触发 daily_active 日活奖励（见函数 docstring）
                if cookie_val:
                    accounts.append(
                        {
                            "token": None,
                            "cookie": cookie_val,
                            "index": idx,
                            "site": site,
                        }
                    )
                else:
                    accounts.append(
                        {
                            "token": token_val,
                            "cookie": None,
                            "index": idx,
                            "site": site,
                        }
                    )

    # 2. 如果未扫描到序号 1，回退扫描非序号变量
    if not accounts:
        token_val = ""
        env_cookie_val = ""

        for pfx in prefixes:
            if not token_val:
                for k in token_keys:
                    token_val = (
                        os.getenv(f"{pfx}{k}")
                        or os.getenv(f"{pfx}{k.lower()}")
                        or ""
                    ).strip()
                    if token_val:
                        break
            if not env_cookie_val:
                for k in cookie_keys:
                    env_cookie_val = (
                        os.getenv(f"{pfx}{k}")
                        or os.getenv(f"{pfx}{k.lower()}")
                        or ""
                    ).strip()
                    if env_cookie_val:
                        break

        cookie_val, _src = _resolve_cookie(env_cookie_val, 1, site)
        token_val = token_val.strip()

        # 针对单变量 && 或换行切分多账号（Cookie 优先：Token 不触发日活奖励）
        if cookie_val and ("&&" in cookie_val or "\n" in cookie_val):
            raw_cookies = [
                x.strip()
                for x in cookie_val.replace("&&", "\n").splitlines()
                if x.strip()
            ]
            for sub_idx, c_item in enumerate(raw_cookies, 1):
                accounts.append(
                    {
                        "token": None,
                        "cookie": c_item,
                        "index": sub_idx,
                        "site": site,
                    }
                )
        elif token_val and ("&&" in token_val or "\n" in token_val):
            raw_tokens = [
                x.strip()
                for x in token_val.replace("&&", "\n").splitlines()
                if x.strip()
            ]
            for sub_idx, t_item in enumerate(raw_tokens, 1):
                accounts.append(
                    {
                        "token": t_item,
                        "cookie": None,
                        "index": sub_idx,
                        "site": site,
                    }
                )
        elif token_val or cookie_val:
            # Cookie 优先（同序号分支注释）；Token 仅作为无 Cookie 时的回退
            accounts.append(
                {
                    "token": None if cookie_val else token_val,
                    "cookie": cookie_val or None,
                    "index": 1,
                    "site": site,
                }
            )

    return accounts


def _run_one(account: Dict[str, Any], host: str) -> Tuple[bool, str]:
    """执行单个账号的签到逻辑。返回 (成功, 描述)。"""
    token = account.get("token")
    cookie = account.get("cookie")
    idx = account.get("index", 1)
    site = account.get("site", "cn")

    proxy = (
        os.getenv("MODELSCOPE_PROXY", "").strip()
        or os.getenv("HTTPS_PROXY", "").strip()
        or os.getenv("https_proxy", "").strip()
    )
    h = Http(proxy=proxy)

    # 1. 会话触碰 + 登录态验证 + 账号脱敏（该请求同时是「日活」触发的活跃信号）
    try:
        user = _touch_user(h, host, token=token, cookie=cookie)
    except Exception as e:
        return False, f"登录态验证失败：{e}"

    name = user.get("nickname") or user.get("username") or ""
    uid = user.get("user_id") or user.get("id")
    parts = []
    if name:
        parts.append(mask_str(str(name)))
    if uid:
        parts.append(f"UID:{mask_str(str(uid))}")
    auth_tag = "Token" if token else "Cookie"
    parts.append(f"[{auth_tag}]")
    user_tag = " ".join(parts) or "未知用户"

    # 2. 记录初始余额（辅助判据：余额增长 = 到账）
    initial_balance = _get_balance(h, host, token=token, cookie=cookie)

    # 3. 首次查询 earn/rules
    try:
        daily_rule = _get_rules(h, host, token=token, cookie=cookie)
    except Exception as e:
        return False, f"{user_tag} 查询失败：{e}"

    today_used = daily_rule.get("today_used", 0)
    amount = daily_rule.get("amount", 200)

    # 4. 渐进式退避复查：未到账时 touch 会话 + 递增等待 + 复查
    current_balance = initial_balance
    current_today_used = today_used

    def is_credited(used_val: int, bal_val: Optional[int]) -> bool:
        if bool(used_val):
            return True
        return (
            bal_val is not None
            and initial_balance is not None
            and bal_val > initial_balance
        )

    for attempt, wait in enumerate(RETRY_WAITS, 1):
        if is_credited(current_today_used, current_balance):
            break
        print(
            f"  {user_tag} 今日奖励尚未到账（today_used={current_today_used}），"
            f"{wait}s 后第 {attempt}/{len(RETRY_WAITS)+1} 次复查（全链路 touch 会话激活中）..."
        )
        time.sleep(wait)
        try:
            _touch_user(h, host, token=token, cookie=cookie)  # 复查前再次触碰，触发活跃事件
            daily_rule = _get_rules(h, host, token=token, cookie=cookie)
            current_today_used = daily_rule.get("today_used", 0)
            current_balance = _get_balance(h, host, token=token, cookie=cookie)
        except Exception as e:
            return False, f"{user_tag} 复查失败：{e}"

    final_balance = (
        current_balance
        if current_balance is not None
        else _get_balance(h, host, token=token, cookie=cookie)
    )
    credited = is_credited(current_today_used, final_balance)

    # 5. 持久化并滚动更新 Cookie（仅针对纯 Cookie 账号，Token 账号本身长期有效无需滚动）
    if cookie and not token:
        updated_cookie = _merge_cookies(cookie, h.jar)
        if updated_cookie:
            state_file = f".modelscope_{site}_state_{idx}.json"
            redis_key = f"cat_checkin:state:modelscope_{site}_{idx}"
            save_kv_state(
                redis_key,
                state_file,
                {
                    "cookie": updated_cookie,
                    "updated_at": int(time.time()),
                    "user_tag": user_tag,
                },
            )

    if credited:
        status = f"签到成功，今日已领取 {amount} 魔粒"
    elif token and not cookie:
        # 2026-08-25 实测：Bearer Token 能通过 OpenAPI 鉴权，但 OpenAPI 调用不计入
        # 「日活」，daily_active 奖励永不发放——红卡必须直指根因，不再猜「重置时间」
        status = (
            f"今日奖励未到账（{len(RETRY_WAITS)+1} 次复查后仍无增长）："
            f"Bearer Token 不触发 daily_active 日活奖励，"
            f"请配置浏览器 Cookie 环境变量 {PREFIX}COOKIE_{idx}（{site} 站）"
        )
    else:
        status = f"今日奖励未到账（{len(RETRY_WAITS)+1} 次复查后仍无增长，Cookie 可能已失效需手动刷新）"

    balance_desc = (
        "当前余额：？"
        if final_balance is None
        else f"当前余额：{final_balance} 魔粒"
    )
    return credited, f"{user_tag} {status}，{balance_desc}"


def _run_site(
    accounts: List[Dict[str, Any]], host: str, site: str, title: str
) -> Tuple[bool, List[str]]:
    """运行单个站点的所有账号。返回 (全部成功, 各行输出)。"""
    print(f"【{title}】")
    if not accounts:
        print(f"  未提供 {title} 凭证（Token / Cookie），跳过")
        return True, []

    print(f"  {len(accounts)} 个账号 @ {host}")
    results = []
    for idx, acc in enumerate(accounts, 1):
        try:
            ok, msg = _run_one(acc, host)
            line = f"  [{idx}/{len(accounts)}] {msg}"
            print(line)
            results.append((ok, line))
        except Exception as e:
            line = f"  [{idx}/{len(accounts)}] 签到失败：{e}"
            print(line)
            results.append((False, line))

    ok_count = sum(1 for ok, _ in results if ok)
    all_ok = ok_count == len(accounts)
    print(f"  {title} 总结：成功 {ok_count}/{len(accounts)}")
    return all_ok, [line for _, line in results]


def main():
    print("【ModelScope 签到】")

    # 国内站
    cn_accounts = _load_accounts("cn")
    # 国际站
    ai_accounts = _load_accounts("ai")
    if not cn_accounts and not ai_accounts:
        raise RuntimeError(
            f"缺少环境变量：{PREFIX}TOKEN（或 {PREFIX}TOKEN_1 / {PREFIX}COOKIE_1，国内站）"
            f" 或 {PREFIX}AI_TOKEN / {PREFIX}AI_COOKIE（国际站）"
        )

    cn_host = _default_host()
    ai_host = _ai_host()

    print(
        f"共 {len(cn_accounts) + len(ai_accounts)} 个账号"
        f"（国内 {len(cn_accounts)}，国际 {len(ai_accounts)}）\n"
    )

    # 分开运行，互不影响
    cn_ok, cn_lines = _run_site(cn_accounts, cn_host, "cn", "ModelScope 国内站 签到")
    print()
    ai_ok, ai_lines = _run_site(ai_accounts, ai_host, "ai", "ModelScope 国际站 签到")

    print(f"\n国内站：{'✅ 成功' if cn_ok else '❌ 失败'}")
    print(f"国际站：{'✅ 成功' if ai_ok else '❌ 失败'}")

    # 国内站失败 → 整体失败（国际站因凭证/时区偶发问题不阻塞整体）
    if not cn_ok:
        sys.exit(1)
    # 国际站失败时，打印警告但不退出（避免误报影响整体）
    if not ai_ok:
        print("\n⚠️ 国际站签到异常（通常为凭证需手动刷新，不影响国内站）")


if __name__ == "__main__":
    main_guard(main)
