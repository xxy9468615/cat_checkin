#!/usr/bin/env python3
# cron: 0 10 * * *
# new Env("ModelScope 社区签到")
# new Env("ModelScope 国际站 签到")
"""ModelScope 魔搭社区每日签到（国内站 + 国际站分开处理）。

机制：登录奖励（每日 200 魔粒）在用户产生活跃会话后被动发放。
接口路径已变更：magic_cube → magicubes（2026-08 前后迁移）。
判断字段：today_used > 0 表示今日已领取；余额增长为辅助判据。

稳定性要点（2026-08-19 深度修复）：
1. 会话触碰：直接调 earn/rules 属轻量查询，服务端可能不触发「日活/登录」事件。
   先 GET /openapi/v1/users/me 验证登录态并触碰会话，模拟真实活跃。
2. 请求头补齐浏览器上下文（Origin / Referer / UA），避免被埋点/风控中间件忽略。
3. Cookie 失效前置判定：users/me 401/403 → 明确报错提示重新获取，而非盲目重试。
4. 渐进式退避复查（10s→20s→30s→45s），复查前再 touch，双判据（today_used / 余额增长）。

国内站（.cn）运行稳定；国际站（.ai）因 cookie 刷新/时区差异偶发 today_used=0，
单独报告不影响国内站结果。

环境变量：
  MODELSCOPE_cookie 普通格式：多账号 && 或换行分隔（国内站）
  MODELSCOPE_AI_COOKIE：国际站专用 cookie，独立运行
  MODELSCOPE_HOST：国内站主机（默认 www.modelscope.cn）
  MODELSCOPE_AI_HOST：国际站主机（默认 www.modelscope.ai）
"""
from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from common import Http, env, main_guard, mask_str

PREFIX = "MODELSCOPE_"

# daily_active 奖励未到账时的渐进式复查间隔（秒）：逐次递增，避免盲等 90s
RETRY_WAITS = [10, 20, 30, 45]


def _default_host() -> str:
    return os.getenv("MODELSCOPE_HOST", "www.modelscope.cn").strip() or "www.modelscope.cn"


def _ai_host() -> str:
    return os.getenv(f"{PREFIX}AI_HOST", "www.modelscope.ai").strip() or "www.modelscope.ai"


def _parse_cookies(raw: str) -> List[str]:
    """解析多账号 Cookie，支持换行或 && 分隔。"""
    if not raw:
        return []
    return [x.strip() for x in raw.replace("&&", "\n").splitlines() if x.strip()]


def _headers(host: str, cookie: str) -> Dict[str, str]:
    """构造带浏览器上下文的请求头，避免被风控/埋点中间件忽略。"""
    return {
        "Cookie": cookie,
        "Origin": f"https://{host}",
        "Referer": f"https://{host}/my/overview",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "application/json, text/plain, */*",
    }


def _touch_user(h: Http, cookie: str, host: str) -> Dict[str, Any]:
    """触碰会话并验证登录态。GET /openapi/v1/users/me。

    成功返回用户信息 dict（可含 username/nickname/user_id）；cookie 失效时抛 RuntimeError。
    """
    resp = h.request(
        "GET",
        f"https://{host}/openapi/v1/users/me",
        headers=_headers(host, cookie),
    )
    data = resp.json({})
    if resp.code in (401, 403) or (isinstance(data, dict) and data.get("code") in (401, 403)):
        raise RuntimeError(f"Cookie 已失效/未登录 (HTTP {resp.code})，请重新获取 {host} 的 cookie")
    if not data or not data.get("success"):
        raise RuntimeError(f"users/me 返回异常：{resp.text[:200]}")
    user = data.get("data", {})
    if not isinstance(user, dict):
        raise RuntimeError(f"users/me 数据结构异常：{resp.text[:200]}")
    return user


def _get_rules(h: Http, cookie: str, host: str) -> Dict[str, Any]:
    """获取 earn 规则，返回 daily_active 规则字典。"""
    resp = h.request(
        "GET",
        f"https://{host}/openapi/v1/magicubes/earn/rules",
        headers=_headers(host, cookie),
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


def _get_balance(h: Http, cookie: str, host: str) -> Optional[int]:
    """查询魔粒余额（int），失败返回 None。"""
    resp = h.request(
        "GET",
        f"https://{host}/openapi/v1/magicubes/balance",
        headers=_headers(host, cookie),
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


def _run_one(cookie: str, host: str) -> Tuple[bool, str]:
    """执行单个账号的签到逻辑。返回 (成功, 描述)。"""
    h = Http()

    # 1. 会话触碰 + 登录态验证 + 账号脱敏（该请求同时是「日活」触发的活跃信号）
    try:
        user = _touch_user(h, cookie, host)
    except Exception as e:
        return False, f"登录态验证失败：{e}"
    name = user.get("nickname") or user.get("username") or ""
    uid = user.get("user_id") or user.get("id")
    parts = []
    if name:
        parts.append(mask_str(str(name)))
    if uid:
        parts.append(f"UID:{mask_str(str(uid))}")
    user_tag = " ".join(parts) or "未知用户"

    # 2. 记录初始余额（辅助判据：余额增长 = 到账）
    initial_balance = _get_balance(h, cookie, host)

    # 3. 首次查询 earn/rules
    try:
        daily_rule = _get_rules(h, cookie, host)
    except Exception as e:
        return False, f"{user_tag} 查询失败：{e}"

    today_used = daily_rule.get("today_used", 0)
    amount = daily_rule.get("amount", 200)

    def _credit_ok(current_balance: Optional[int]) -> bool:
        """双重到账判据：today_used > 0 或 余额较初始增长。"""
        if bool(today_used):
            return True
        return (
            current_balance is not None
            and initial_balance is not None
            and current_balance > initial_balance
        )

    # 4. 渐进式退避复查：未到账时 touch 会话 + 递增等待 + 复查
    current_balance = initial_balance
    for attempt, wait in enumerate(RETRY_WAITS, 1):
        if _credit_ok(current_balance):
            break
        print(f"  {user_tag} 今日奖励尚未到账（today_used=0），{wait}s 后第 {attempt}/{len(RETRY_WAITS)+1} 次复查（touch 会话激活中）...")
        time.sleep(wait)
        try:
            _touch_user(h, cookie, host)  # 复查前再次触碰，触发活跃事件
            daily_rule = _get_rules(h, cookie, host)
            today_used = daily_rule.get("today_used", 0)
            current_balance = _get_balance(h, cookie, host)
        except Exception as e:
            return False, f"{user_tag} 复查失败：{e}"

    final_balance = current_balance if current_balance is not None else _get_balance(h, cookie, host)
    credited = _credit_ok(final_balance)

    if credited:
        status = f"签到成功，今日已领取 {amount} 魔粒"
    else:
        status = f"今日奖励未到账（{len(RETRY_WAITS)+1} 次复查后仍无增长，可能 cookie 未刷新或未到重置时间）"

    balance_desc = "当前余额：？" if final_balance is None else f"当前余额：{final_balance} 魔粒"
    return credited, f"{user_tag} {status}，{balance_desc}"


def _run_site(
    cookies: List[str], host: str, site: str, title: str
) -> Tuple[bool, List[str]]:
    """运行单个站点的所有账号。返回 (全部成功, 各行输出)。"""
    print(f"【{title}】")
    if not cookies:
        print(f"  未提供 {title} cookie，跳过")
        return True, []

    print(f"  {len(cookies)} 个账号 @ {host}")
    results = []
    for idx, cookie in enumerate(cookies, 1):
        try:
            ok, msg = _run_one(cookie, host)
            line = f"  [{idx}/{len(cookies)}] {msg}"
            print(line)
            results.append((ok, line))
        except Exception as e:
            line = f"  [{idx}/{len(cookies)}] 签到失败：{e}"
            print(line)
            results.append((False, line))

    ok_count = sum(1 for ok, _ in results if ok)
    all_ok = ok_count == len(cookies)
    print(f"  {title} 总结：成功 {ok_count}/{len(cookies)}")
    return all_ok, [line for _, line in results]


def main():
    print("【ModelScope 签到】")

    # 国内站
    cn_raw = env(PREFIX, "cookie", required=False)
    # 国际站
    ai_raw = env(PREFIX, "AI_COOKIE", required=False)
    if not cn_raw and not ai_raw:
        raise RuntimeError(f"缺少环境变量：{PREFIX}COOKIE（国内站）或 {PREFIX}AI_COOKIE（国际站）")

    cn_host = _default_host()
    ai_host = _ai_host()

    cn_cookies = _parse_cookies(cn_raw)
    ai_cookies = _parse_cookies(ai_raw)
    print(f"共 {len(cn_cookies) + len(ai_cookies)} 个账号（国内 {len(cn_cookies)}，国际 {len(ai_cookies)}）\n")

    # 分开运行，互不影响
    cn_ok, cn_lines = _run_site(cn_cookies, cn_host, "cn", "ModelScope 国内站 签到")
    print()
    ai_ok, ai_lines = _run_site(ai_cookies, ai_host, "ai", "ModelScope 国际站 签到")

    print(f"\n国内站：{'✅ 成功' if cn_ok else '❌ 失败'}")
    print(f"国际站：{'✅ 成功' if ai_ok else '❌ 失败'}")

    # 国内站失败 → 整体失败（国际站因 cookie 偶发问题不阻塞整体）
    if not cn_ok:
        sys.exit(1)
    # 国际站失败时，打印警告但不退出（避免误报影响整体）
    if not ai_ok:
        print("\n⚠️ 国际站签到异常（通常为 cookie 需手动刷新，不影响国内站）")


main_guard(main)
