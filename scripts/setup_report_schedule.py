#!/usr/bin/env python3
# new Env("日报定时排程（QStash）")
"""把「每日 20:00 BJT 发送统一日报」注册为 QStash Cron，摆脱 GitHub cron 漂移。

背景（2026-09-15 排查）：
  GitHub Actions 的 `schedule` 事件不保证按时投递，延迟可达数小时。实测本仓库
  本应 20:00 BJT 送达的 "0 12 * * *" 日报 cron，屡次延迟约 5~6.7 小时，直到
  次日凌晨 00:59 / 01:16 / 02:44 BJT 才落地（run 34873705030 于
  2026-09-14T17:16:04Z 启动 = 晚 5h16m）。unified_report 在运行时才计算 TODAY，
  于是这封「昨天的日报」取到新一天几乎无任务的数据，发出「成功 4、待执行 25」
  的空报告，并写下新一天的 sent marker，把当天真正的 20:00 主发幂等秒退——
  用户看到的就是「每天凌晨推邮件」。

方案：
  - 定时主力交给 QStash Cron（本脚本注册，精确到分，延迟以秒计），
    GitHub cron 仅保留为兜底；
  - unified_report.py 侧设 19:00~23:59 BJT 时间窗守卫：晚到的日报只归档，
    不发信也不写 marker，杜绝推错日期数据与压制当日主发；

用法：
  python3 scripts/setup_report_schedule.py            # 创建/更新排程（幂等）
  python3 scripts/setup_report_schedule.py --list     # 查看现有排程
  python3 scripts/setup_report_schedule.py --delete   # 删除排程

所需环境变量：QSTASH_URL / QSTASH_TOKEN / GH_PAT / GITHUB_REPO
（与 schedule_repo_dispatch 一致；GH_PAT 需具备 actions: write 以调用
 repository_dispatch 派发 API）。
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from common import Http, create_qstash_schedule  # noqa: E402

# 排程标识（固定 ID => 重复执行即原地更新，不会堆积多条排程）
SCHEDULE_ID = "cat-checkin-daily-report"

# 每日 20:00 北京时间（UTC 12:00）——唯一日常发信点
REPORT_CRON_UTC = "0 12 * * *"

# 派发事件名（checkin.yml 的 report-fallback 已认此 action）
EVENT_TYPE = "daily_report"


def _qstash_base() -> str:
    url = os.getenv("QSTASH_URL") or os.getenv("WORKBUDDY_QSTASH_URL") or ""
    return url.split("/v2/publish", 1)[0].rstrip("/")


def _token() -> str:
    return os.getenv("QSTASH_TOKEN") or os.getenv("WORKBUDDY_QSTASH_TOKEN") or ""


def list_schedules() -> int:
    base, token = _qstash_base(), _token()
    if not base or not token:
        print("❌ 未配置 QSTASH_URL / QSTASH_TOKEN")
        return 1
    resp = Http(proxy="").request(
        "GET", f"{base}/v2/schedules", headers={"Authorization": f"Bearer {token}"}, timeout=15
    )
    if resp.code != 200:
        print(f"❌ 查询排程失败: HTTP {resp.code} {resp.text[:200]}")
        return 1
    data = resp.json()
    schedules = data if isinstance(data, list) else data.get("schedules", [])
    if not schedules:
        print("ℹ️ 当前没有任何 QStash 排程")
        return 0
    print(f"共 {len(schedules)} 条排程：")
    for s in schedules:
        if not isinstance(s, dict):
            continue
        flag = "⭐ " if s.get("scheduleId") == SCHEDULE_ID else "   "
        print(
            f"{flag}id={s.get('scheduleId')}  cron={s.get('cron')}  "
            f"dest={s.get('destination')}  method={s.get('method', 'POST')}"
        )
    return 0


def delete_schedule() -> int:
    base, token = _qstash_base(), _token()
    if not base or not token:
        print("❌ 未配置 QSTASH_URL / QSTASH_TOKEN")
        return 1
    resp = Http(proxy="").request(
        "DELETE",
        f"{base}/v2/schedules/{SCHEDULE_ID}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )
    if resp.code in (200, 202, 204):
        print(f"🗑️ 已删除排程 {SCHEDULE_ID}")
        return 0
    print(f"❌ 删除失败: HTTP {resp.code} {resp.text[:200]}")
    return 1


def create_schedule() -> int:
    repo = os.getenv("GITHUB_REPO", "")
    gh_pat = os.getenv("GH_PAT") or os.getenv("GH_TOKEN") or os.getenv("WORKFLOW_TOKEN")
    missing = [k for k, v in (("GITHUB_REPO", repo), ("GH_PAT", gh_pat)) if not v]
    if missing:
        print(f"❌ 缺少环境变量: {', '.join(missing)}")
        return 1

    destination = f"https://api.github.com/repos/{repo}/dispatches"
    body = json.dumps({"event_type": EVENT_TYPE}, ensure_ascii=False)
    ok, detail = create_qstash_schedule(
        destination,
        REPORT_CRON_UTC,
        body,
        forward_headers={
            "Authorization": f"Bearer {gh_pat}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        schedule_id=SCHEDULE_ID,
        retries=3,  # 派发失败可重试：report-fallback 幂等，重复派发不会重复发信
    )
    if not ok:
        print(f"❌ 创建排程失败: {detail}")
        return 1
    now = dt.datetime.now(dt.timezone(dt.timedelta(hours=8)))
    print("✅ 日报定时排程已注册")
    print(f"   scheduleId : {detail or SCHEDULE_ID}")
    print(f"   cron       : {REPORT_CRON_UTC} (UTC) = 每日 20:00 北京时间")
    print(f"   destination: {destination}")
    print(f"   event_type : {EVENT_TYPE}")
    print(f"   当前时间   : {now:%Y-%m-%d %H:%M:%S} BJT")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="日报 QStash 定时排程管理")
    parser.add_argument("--list", action="store_true", help="列出全部 QStash 排程")
    parser.add_argument("--delete", action="store_true", help="删除日报排程")
    args = parser.parse_args()
    if args.list:
        return list_schedules()
    if args.delete:
        return delete_schedule()
    return create_schedule()


if __name__ == "__main__":
    sys.exit(main())