#!/usr/bin/env python3
# cron: 0 10 * * *
# new Env("ModelScope 社区签到")
# new Env("ModelScope 国际站 签到")
"""ModelScope 魔搭社区每日签到（国内站 + 国际站分开处理）。

机制：登录奖励（每日 200 魔粒）在访问 earn/rules 接口时被动发放。
接口路径已变更：magic_cube → magicubes（2026-08 前后迁移）。
判断字段：today_used > 0 表示今日已领取。

国内站（.cn）运行稳定；国际站（.ai）因 cookie 刷新/时区差异偶发
today_used=0，单独报告不影响国内站结果。

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
from typing import Any, Dict, List, Tuple

from common import Http, env, main_guard

PREFIX = "MODELSCOPE_"


def _default_host() -> str:
    return os.getenv("MODELSCOPE_HOST", "www.modelscope.cn").strip() or "www.modelscope.cn"


def _ai_host() -> str:
    return os.getenv(f"{PREFIX}AI_HOST", "www.modelscope.ai").strip() or "www.modelscope.ai"


def _parse_cookies(raw: str) -> List[str]:
    """解析多账号 Cookie，支持换行或 && 分隔。"""
    if not raw:
        return []
    return [x.strip() for x in raw.replace("&&", "\n").splitlines() if x.strip()]


def _get_rules(h: Http, cookie: str, host: str) -> Dict[str, Any]:
    """获取 earn 规则，返回 daily_active 规则字典。"""
    resp = h.request(
        "GET",
        f"https://{host}/openapi/v1/magicubes/earn/rules",
        headers={"Cookie": cookie},
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


def _get_balance(h: Http, cookie: str, host: str) -> str:
    """查询魔粒余额，失败返回 '?'。"""
    resp = h.request(
        "GET",
        f"https://{host}/openapi/v1/magicubes/balance",
        headers={"Cookie": cookie},
    )
    if resp.code != 200:
        return "?"
    bal_data = resp.json()
    if not bal_data or not bal_data.get("success"):
        return "?"
    return str(bal_data.get("data", {}).get("available_balance", "?"))


def _run_one(cookie: str, host: str) -> Tuple[bool, str]:
    """执行单个账号的签到逻辑。返回 (成功, 描述)。"""
    h = Http()

    try:
        daily_rule = _get_rules(h, cookie, host)
    except Exception as e:
        return False, f"查询失败：{e}"

    today_used = daily_rule.get("today_used", 0)
    amount = daily_rule.get("amount", 200)

    # 09:10 开跑时奖励偶发尚未发放可见（发放到接口可见有延迟）：
    # today_used=0 时等 90 秒复查，最多 3 轮查询（总耗时 ~3 分钟，TASK_TIMEOUT=600 内）
    for attempt in range(2):
        if bool(today_used):
            break
        print(f"  今日奖励尚未到账（today_used=0），90 秒后第 {attempt + 2}/3 次复查...")
        time.sleep(90)
        try:
            daily_rule = _get_rules(h, cookie, host)
        except Exception as e:
            return False, f"复查失败：{e}"
        today_used = daily_rule.get("today_used", 0)

    if bool(today_used):
        status = f"签到成功，今日已领取 {amount} 魔粒"
    else:
        # 3 轮复查后仍 today_used=0：cookie 未刷新/当日未到重置时间/发放异常
        status = f"今日奖励未到账（3 轮复查后 today_used 仍为 0，可能 cookie 未刷新或未到重置时间）"

    balance = _get_balance(h, cookie, host)
    return bool(today_used), f"{status}，当前余额：{balance} 魔粒"


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
