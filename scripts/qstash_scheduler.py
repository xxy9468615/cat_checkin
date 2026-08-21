#!/usr/bin/env python3
# cron: 0 0 * * *
# new Env("QStash 云端定时调度与接力管理器")
"""Upstash QStash 云端高精度定时调度管理器。"""

from __future__ import annotations
import argparse, json, os, sys
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from common import Http

STANDARD_SCHEDULES = [
    {"name": "stats_weekly", "cron": "5 2 * * 1", "desc": "自动周度统计分析报告 (周一 10:05 BJT)", "event_type": "stats_weekly"},
    {"name": "stats_monthly", "cron": "5 2 1 * *", "desc": "自动月度统计总结报告 (每月1日 10:05 BJT)", "event_type": "stats_monthly"},
]

def _get_qstash_client() -> Tuple[str, str, str, str]:
    qstash_url = os.getenv("QSTASH_URL") or os.getenv("WORKBUDDY_QSTASH_URL", "")
    qstash_token = os.getenv("QSTASH_TOKEN") or os.getenv("WORKBUDDY_QSTASH_TOKEN", "")
    gh_pat = os.getenv("GH_PAT") or os.getenv("WORKFLOW_TOKEN", "")
    repo = os.getenv("GITHUB_REPO", "")
    base_url = qstash_url.split("/v2/publish", 1)[0].rstrip("/") if qstash_url else ""
    return base_url, qstash_token, gh_pat, repo

def list_schedules() -> List[Dict[str, Any]]:
    base_url, token, _, _ = _get_qstash_client()
    if not base_url or not token:
        return []
    url = f"{base_url}/v2/schedules"
    resp = Http().request("GET", url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    return resp.json([]) if resp.code == 200 and isinstance(resp.json([]), list) else []

def create_or_update_schedule(spec: Dict[str, str]) -> Tuple[bool, str]:
    base_url, token, gh_pat, repo = _get_qstash_client()
    if not base_url or not token:
        return False, "未配置 QSTASH_URL / QSTASH_TOKEN"
    if not gh_pat or not repo:
        return False, "未配置 GH_PAT / GITHUB_REPO"
    destination = f"https://api.github.com/repos/{repo}/dispatches"
    create_url = f"{base_url}/v2/schedules/{destination}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Upstash-Cron": spec["cron"],
        "Upstash-Forward-Authorization": f"Bearer {gh_pat}",
        "Upstash-Forward-Accept": "application/vnd.github+json",
        "Upstash-Forward-X-GitHub-Api-Version": "2022-11-28",
        "Upstash-Retries": "2",
    }
    body = json.dumps({"event_type": spec["event_type"]}, ensure_ascii=False)
    resp = Http().request("POST", create_url, headers=headers, data=body)
    if resp.code in (200, 201):
        data = resp.json({})
        return True, data.get("scheduleId", "ok") if isinstance(data, dict) else "ok"
    return False, f"HTTP {resp.code}: {resp.text[:200]}"

def delete_schedule(schedule_id: str) -> bool:
    base_url, token, _, _ = _get_qstash_client()
    if not base_url or not token:
        return False
    resp = Http().request("DELETE", f"{base_url}/v2/schedules/{schedule_id}", headers={"Authorization": f"Bearer {token}"})
    return resp.code in (200, 204)

def sync_all_schedules() -> None:
    base_url, token, gh_pat, repo = _get_qstash_client()
    print(f"🚀 开始同步 QStash 云端高精度调度 (目标仓库: {repo or '未指定'})...")
    if not base_url or not token or not gh_pat or not repo:
        print("❌ 缺少凭据 (QSTASH_URL, QSTASH_TOKEN, GH_PAT, GITHUB_REPO)")
        sys.exit(1)
    existing = list_schedules()
    existing_map = {}
    for item in existing:
        body_raw = item.get("body", "")
        try:
            bdict = json.loads(body_raw) if isinstance(body_raw, str) else body_raw
            if isinstance(bdict, dict) and "event_type" in bdict:
                existing_map[bdict["event_type"]] = item.get("scheduleId")
        except Exception:
            pass

    for spec in STANDARD_SCHEDULES:
        etype = spec["event_type"]
        old_id = existing_map.get(etype)
        if old_id:
            delete_schedule(old_id)
            print(f"  🔄 更新调度 [{spec['name']}]: {spec['desc']}")
        else:
            print(f"  ➕ 创建调度 [{spec['name']}]: {spec['desc']}")
        ok, detail = create_or_update_schedule(spec)
        print(f"     {'✅ 成功' if ok else '❌ 失败'}: {detail}")

    # 清理已退役的旧调度（单 run 全内联后不再需要）
    retired = {"checkin_morning", "checkin_modelscope", "daily_report", "checkin_latvi",
               "checkin_latvi_anchor", "latvi_next_sign", "workbuddy_travel_claim"}
    for etype, sid in list(existing_map.items()):
        if etype not in {s["event_type"] for s in STANDARD_SCHEDULES} and etype in retired:
            if delete_schedule(sid):
                print(f"  🗑️ 已清理退役调度: {etype} ({sid})")
            else:
                print(f"  ⚠️ 清理退役调度失败: {etype} ({sid})")
    print("\n✨ QStash 云端调度同步完成！")

def main() -> None:
    parser = argparse.ArgumentParser(description="QStash Scheduler CLI")
    parser.add_argument("--list", action="store_true", help="列出所有调度")
    parser.add_argument("--sync", action="store_true", help="同步 QStash 云端调度")
    args = parser.parse_args()
    if args.sync:
        sync_all_schedules()
    else:
        schedules = list_schedules()
        print(f"📋 QStash 云端定时调度列表 ({len(schedules)} 个):")
        for s in schedules:
            print(f"  • {s.get('scheduleId')} | {s.get('cron')} | {s.get('destination')}")

if __name__ == "__main__":
    main()
