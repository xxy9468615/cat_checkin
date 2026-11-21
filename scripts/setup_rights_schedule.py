#!/usr/bin/env python3
# new Env("0点抢兑定时排程（QStash）")
"""把「telecom-exchange 每日 0 点场」注册为 QStash Cron 精准派发 + 窗口补发兜底。

背景（2026-11-19 实战丢场）：
  GitHub Actions `*/30` 心跳 cron 在 23:03~03:45 BJT 之间整体断档约 4.5 小时
  （run 44550481353 之后直到 44601589464 才落地），23:30 BJT 的 rolling 到期
  无人拾取，0 点场（每日限量 102 份，先到先得）整场错过。日报早已用 QStash
  Cron 解决同类问题（setup_report_schedule.py，20:00 精准投递），0 点场照搬。

方案（双排程，GitHub 心跳仅保留兜底）：
  - 主力 cat-checkin-rights-window：23:30 BJT（UTC 15:30）精准派发
    repository_dispatch(checkin_rights)，拉起 telecom-exchange，任务内等到
    23:59:20 预检 + 00:00:00 突发；
  - 补发 cat-checkin-rights-catchup：23:50 BJT（UTC 15:50）再派发一次——
    主力派发失败/runner 排队过长时接力。两次派发都经 rolling 冷却 + 服务端
    remainCount/库存裁决幂等：已终局（成功/售罄/限兑）的场次重复拉起只会
    秒退，不会重复兑换。0 点后的迟到派发由任务内「场次已过」判定直接排下一场。

用法：
  python3 scripts/setup_rights_schedule.py            # 创建/更新双排程（幂等）
  python3 scripts/setup_rights_schedule.py --list     # 查看现有排程
  python3 scripts/setup_rights_schedule.py --delete   # 删除双排程

所需环境变量：QSTASH_URL / QSTASH_TOKEN / GH_PAT / GITHUB_REPO
（与 setup_report_schedule 一致）。

GH_PAT 权限要求（PR #34 第五轮评审更正）：/repos/{repo}/dispatches API
要求 **Contents: write**（fine-grained PAT）或 classic PAT 的 `repo` scope——
仅有 Actions: write 的令牌排程注册能成功，但后续派发会被 GitHub 拒绝。
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

from common import Http, create_qstash_schedule, sanitize_snippet  # noqa: E402

# 派发事件名（checkin.yml Precheck 的 case 分支认此 action → telecom-exchange）
EVENT_TYPE = "checkin_rights"

# (scheduleId, UTC cron, BJT 说明)：主力 23:30 + 补发 23:50
SCHEDULES = [
    ("cat-checkin-rights-window", "30 15 * * *", "每日 23:30 北京时间（0 点场预检主力）"),
    ("cat-checkin-rights-catchup", "50 15 * * *", "每日 23:50 北京时间（窗口补发兜底）"),
]


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
    ours = {sid for sid, _, _ in SCHEDULES}
    print(f"共 {len(schedules)} 条排程：")
    for s in schedules:
        if not isinstance(s, dict):
            continue
        flag = "⭐ " if s.get("scheduleId") in ours else "   "
        # destination 可能含 query token（如 webhook ?token=...）：展示前
        # 必须脱敏，不得把完整凭据写进输出（PR #34 第五轮评审指认）
        dest = sanitize_snippet(str(s.get("destination") or ""), None)
        print(
            f"{flag}id={s.get('scheduleId')}  cron={s.get('cron')}  "
            f"dest={dest}  method={s.get('method', 'POST')}"
        )
    return 0


def delete_schedules() -> int:
    base, token = _qstash_base(), _token()
    if not base or not token:
        print("❌ 未配置 QSTASH_URL / QSTASH_TOKEN")
        return 1
    rc = 0
    for sid, _, _ in SCHEDULES:
        resp = Http(proxy="").request(
            "DELETE", f"{base}/v2/schedules/{sid}",
            headers={"Authorization": f"Bearer {token}"}, timeout=15,
        )
        if resp.code in (200, 202, 204):
            print(f"🗑️ 已删除排程 {sid}")
        else:
            print(f"❌ 删除 {sid} 失败: HTTP {resp.code} {resp.text[:200]}")
            rc = 1
    return rc


def create_schedules() -> int:
    repo = os.getenv("GITHUB_REPO", "")
    gh_pat = os.getenv("GH_PAT") or os.getenv("GH_TOKEN") or os.getenv("WORKFLOW_TOKEN")
    missing = [k for k, v in (("GITHUB_REPO", repo), ("GH_PAT", gh_pat)) if not v]
    if missing:
        print(f"❌ 缺少环境变量: {', '.join(missing)}")
        return 1

    destination = f"https://api.github.com/repos/{repo}/dispatches"
    body = json.dumps({"event_type": EVENT_TYPE}, ensure_ascii=False)
    rc = 0
    for sid, cron, desc in SCHEDULES:
        ok, detail = create_qstash_schedule(
            destination,
            cron,
            body,
            forward_headers={
                "Authorization": f"Bearer {gh_pat}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            schedule_id=sid,
            retries=3,  # 派发失败可重试：rolling 冷却 + 服务端裁决幂等，重复派发不重复兑换
        )
        if not ok:
            print(f"❌ 创建排程 {sid} 失败: {detail}")
            rc = 1
            continue
        print(f"✅ 排程已注册: {sid}")
        print(f"   cron       : {cron} (UTC) = {desc}")
        print(f"   event_type : {EVENT_TYPE}")
    now = dt.datetime.now(dt.timezone(dt.timedelta(hours=8)))
    print(f"   destination: {destination}")
    print(f"   当前时间   : {now:%Y-%m-%d %H:%M:%S} BJT")
    return rc


def main() -> int:
    parser = argparse.ArgumentParser(description="0 点抢兑 QStash 定时排程管理")
    parser.add_argument("--list", action="store_true", help="列出全部 QStash 排程")
    parser.add_argument("--delete", action="store_true", help="删除 0 点场双排程")
    args = parser.parse_args()
    if args.list:
        return list_schedules()
    if args.delete:
        return delete_schedules()
    return create_schedules()


if __name__ == "__main__":
    sys.exit(main())