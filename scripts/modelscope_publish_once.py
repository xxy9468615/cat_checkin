#!/usr/bin/env python3
# new Env("ModelScope AIGC 一次性发布")
"""ModelScope AIGC 作品一次性发布工具（手动运行，不进日常调度）。

用途：2026-10-27 封禁复盘后互动任务默认全停（ENABLE_BONUS_TASKS=False）；
需要临时发布作品（如抓包删除接口前准备删除目标）时手动运行本脚本。

用法：
  python3 scripts/modelscope_publish_once.py --site ai --count 5
  python3 scripts/modelscope_publish_once.py --site cn --index 1 --count 3

发布数量默认 5，不超过该账号当日剩余配额；输出每个作品的 ID 与分享页 URL，
便于浏览器里对照删除/抓包。
"""
from __future__ import annotations

import argparse
import sys
from typing import Any, Dict, List

try:
    import dotenv
    dotenv.load_dotenv(override=False)
except ImportError:
    pass

from common import Http, main_guard, mask_str
import modelscope as ms


def _publish_account(acc: Dict[str, Any], host: str, site: str, count: int) -> bool:
    """对单个账号执行一次发布。返回是否成功。"""
    idx = acc.get("index", 1)
    token = acc.get("token")
    cookie = acc.get("cookie")

    proxy = (
        (ms.os.getenv(f"{ms.PREFIX}PROXY_{idx}", "") or "").strip()
        or (ms.os.getenv("MODELSCOPE_PROXY", "") or "").strip()
        or (ms.os.getenv("HTTPS_PROXY", "") or "").strip()
        or (ms.os.getenv("https_proxy", "") or "").strip()
    )
    h = Http(proxy=proxy)

    # 每账号固定 UA（与主任务同规则：state 恢复 → 校验 → 池中选定并固化）
    acc_state = ms.load_kv_state(
        f"cat_checkin:state:modelscope_{site}_{idx}",
        f".modelscope_{site}_state_{idx}.json",
    ) or {}
    ua = str(acc_state.get("ua") or "").strip()
    if not ms._valid_ua(ua):
        ua = ms.random.choice(ms.UA_POOL)
        acc_state["ua"] = ua
        ms.save_kv_state(
            f"cat_checkin:state:modelscope_{site}_{idx}",
            f".modelscope_{site}_state_{idx}.json",
            acc_state,
        )

    try:
        user = ms._touch_user(h, host, token=token, cookie=cookie, ua=ua)
    except Exception as e:
        print(f"  [{idx}] ❌ 登录态验证失败：{e}")
        return False

    name = user.get("nickname") or user.get("username") or ""
    uname = user.get("username") or user.get("user_name") or ""
    uid = user.get("user_id") or user.get("id")
    print(f"  [{idx}] 登录 OK：{mask_str(str(name))} UID:{mask_str(str(uid or ''))} [Cookie]")

    rules = ms._fetch_all_earn_rules(h, host, token=token, cookie=cookie, ua=ua)
    rule = rules.get("opensource_aigcworks_publish", {})
    daily_cap = int(rule.get("daily_cap") or 10)
    used = int(rule.get("today_used") or 0)
    remaining = max(0, daily_cap - used)
    plan = min(count, remaining)
    if plan <= 0:
        print(f"  [{idx}] 今日配额已用完（{used}/{daily_cap}），跳过发布")
        return True

    print(f"  [{idx}] 计划发布 {plan} 个（今日已用 {used}/{daily_cap}）...")
    done, _earned, _last_id = ms._do_daily_aigc_publish(
        h,
        host,
        token=token,
        cookie=cookie,
        count=plan,
        amount_per_publish=int(rule.get("amount") or 10),
        username=uname,
        ua=ua,
    )
    print(f"  [{idx}] ✅ 实际发布 {done} 个作品")

    # 重新拉账本确认今日用量，并列出今日作品 ID 供浏览器删除时对照
    latest = ms._fetch_all_earn_rules(h, host, token=token, cookie=cookie, ua=ua)
    lr = latest.get("opensource_aigcworks_publish", {})
    print(
        f"  [{idx}] 服务端账本：今日发布 {lr.get('today_used')}/{lr.get('daily_cap')}，"
        f"今日收益 {lr.get('today_earned_amount')} 魔粒"
    )
    if uname:
        print(f"  [{idx}] 作品列表页：https://{host}/profile/{uname} （删除/抓包入口）")
    return done > 0 or remaining == 0


def main() -> None:
    parser = argparse.ArgumentParser(description="ModelScope AIGC 一次性发布（手动）")
    parser.add_argument("--site", choices=("ai", "cn"), default="ai", help="站点（默认 ai）")
    parser.add_argument("--count", type=int, default=5, help="每账号发布数量（默认 5，不超过剩余配额）")
    parser.add_argument("--index", type=int, default=0, help="只跑指定序号账号（默认全部）")
    args = parser.parse_args()

    if args.count <= 0:
        print("--count 必须为正整数")
        sys.exit(2)

    host = ms._ai_host() if args.site == "ai" else ms._default_host()
    accounts: List[Dict[str, Any]] = ms._load_accounts(args.site)
    if args.index > 0:
        accounts = [a for a in accounts if a.get("index") == args.index]
        if not accounts:
            print(f"{args.site} 站账号 {args.index} 不存在（或被暂停名单挡下）")
            sys.exit(1)
    if not accounts:
        var = f"{ms.PREFIX}AI_COOKIE" if args.site == "ai" else f"{ms.PREFIX}COOKIE"
        print(f"{args.site} 站无可用凭证：请在 .env 配置 {var}（或对应 _N 序号变量）")
        sys.exit(1)

    print(f"【ModelScope AIGC 一次性发布】{len(accounts)} 个账号 @ {host}\n")
    failed = 0
    for i, acc in enumerate(accounts, 1):
        if i > 1:
            gap = ms.random.uniform(20, 60)
            print(f"  ⏳ 账号间隔 {gap:.0f}s（反多账号时序聚类）")
            ms.time.sleep(gap)
        if not _publish_account(acc, host, args.site, args.count):
            failed += 1

    print(f"\n总结：{'✅ 全部完成' if failed == 0 else f'❌ {failed} 个账号失败'}")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
