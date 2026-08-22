#!/usr/bin/env python3
# cron: 0 0 * * *
# new Env("统一任务注册表与调度队列")
"""统一任务注册表与调度队列管理器。

定义项目中全部 16 个签到任务的元数据（脚本、结果文件、超时、账号、调度标签），
作为统一执行引擎（checkin.yml）与统一报告（unified_report.py）
的唯一事实来源（Single Source of Truth）。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

# === 全量任务元数据注册表 ===
TASKS: Dict[str, Dict[str, Any]] = {
    # --- 常规矩阵站点（单 run 阶段 A 内联并发，BATCH_PARALLEL=4） ---
    "glados": {
        "id": "glados",
        "script": "glados.py",
        "name": "GLaDOS 签到兑换",
        "result": "glados.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    "2libra": {
        "id": "2libra",
        "script": "2libra.py",
        "name": "2Libra 签到",
        "result": "2libra.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    "bianjie_ai": {
        "id": "bianjie_ai",
        "script": "bianjie_ai.py",
        "name": "边界 AI 签到",
        "result": "bianjie_ai.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    "dji": {
        "id": "dji",
        "script": "dji.py",
        "name": "DJI 大疆社区签到",
        "result": "dji.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    "monkeycode": {
        "id": "monkeycode",
        "script": "monkeycode.py",
        "name": "Monkeycode 签到",
        "result": "monkeycode.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    "moxing_vip": {
        "id": "moxing_vip",
        "script": "moxing_vip.py",
        "name": "moxing.vip 签到",
        "result": "moxing_vip.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    "naixi_forum": {
        "id": "naixi_forum",
        "script": "naixi_forum.py",
        "name": "奶昔论坛签到",
        "result": "naixi_forum.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    "sophnet": {
        "id": "sophnet",
        "script": "sophnet.py",
        "name": "Sophnet 签到",
        "result": "sophnet.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    "tencent_cloudstudio": {
        "id": "tencent_cloudstudio",
        "script": "tencent_cloudstudio.py",
        "name": "Tencent CloudStudio 签到",
        "result": "tencent_cloudstudio.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    "ugnas_club": {
        "id": "ugnas_club",
        "script": "ugnas_club.py",
        "name": "绿联私有云 签到",
        "result": "ugnas_club.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    "ai_router": {
        "id": "ai_router",
        "script": "ai_router.py",
        "name": "AI-ROUTER 签到",
        "result": "ai_router.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    # --- AgentRouter（New API 面板，签到=登录；2026-08-21 SS 代理出口绕过 WAF 滑块后重新纳入晨间批次）---
    "agentrouter": {
        "id": "agentrouter",
        "script": "agentrouter.py",
        "name": "AgentRouter 签到",
        "result": "agentrouter.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },

    # --- 多账号站点（单 run 阶段 A 内联并发；旧 QStash 回程接力已退役） ---
    "workbuddy-account-1": {
        "id": "workbuddy-account-1",
        "script": "workbuddy.py",
        "name": "WorkBuddy 签到与成长中心 (账号1)",
        "result": "workbuddy-account-1.json",
        "timeout": 1500,
        "account": "1",
        "tags": ["00:50", "workbuddy", "relay", "daily"],
    },
    "workbuddy-account-2": {
        "id": "workbuddy-account-2",
        "script": "workbuddy.py",
        "name": "WorkBuddy 签到与成长中心 (账号2)",
        "result": "workbuddy-account-2.json",
        "timeout": 1500,
        "account": "2",
        "tags": ["00:50", "workbuddy", "relay", "daily"],
    },

    # --- 特殊窗口站点（09:10 BJT 窗口；单 run 中 max(now,09:10) 零等待） ---
    "modelscope": {
        "id": "modelscope",
        "script": "modelscope.py",
        "name": "ModelScope 社区签到",
        "result": "modelscope.json",
        "timeout": 600,
        "account": "",
        "tags": ["09:10", "modelscope", "daily"],
    },

    # --- 24h 动态冷却站点（Latvi：last_sign_ts+24h 状态驱动，硬墙前 2min 进场） ---
    "latvi": {
        "id": "latvi",
        "script": "latvi.py",
        "name": "Latvi 每日奖励及服务器自动续期",
        "result": "latvi.json",
        "timeout": 7000,
        "account": "",
        "tags": ["18:00", "latvi", "relay", "daily"],
    },
}


def get_expected_results() -> Dict[str, str]:
    """返回期望结果文件名到脚本名的映射表（供 unified_report.py 使用）。"""
    return {cfg["result"]: cfg["script"] for cfg in TASKS.values()}


def resolve_execution_queue(
    event_name: str = "",
    cron: str = "",
    dispatch_type: str = "",
    input_tasks: str = "",
) -> List[Dict[str, Any]]:
    """根据触发上下文解析应执行的任务队列列表。"""
    event = (event_name or "").strip().lower()
    cron_expr = (cron or "").strip()
    dtype = (dispatch_type or "").strip()
    raw_tasks = (input_tasks or "").strip()

    # 1. 优先解析显式指定的 tasks 参数（手动触发 / 报告自动重跑 / 外部调用）
    if raw_tasks:
        wanted_keys = [k.strip() for k in raw_tasks.replace(" ", ",").split(",") if k.strip()]
        matched: List[Dict[str, Any]] = []
        matched_keys: set[str] = set()

        for key in wanted_keys:
            # 关键字全选 / 分组别名
            if key.lower() in ("all", "full", "all_tasks"):
                for t in TASKS.values():
                    if t["id"] not in matched_keys:
                        matched_keys.add(t["id"])
                        matched.append(t)
                continue
            if key.lower() in ("matrix", "basic_matrix"):
                for t in TASKS.values():
                    if "matrix" in t["tags"] and t["id"] not in matched_keys:
                        matched_keys.add(t["id"])
                        matched.append(t)
                continue
            if key.lower() in ("workbuddy", "workbuddy_all"):
                for t in TASKS.values():
                    if "workbuddy" in t["tags"] and t["id"] not in matched_keys:
                        matched_keys.add(t["id"])
                        matched.append(t)
                continue

            # 按 task_id、script_name 或 result_name 精准或前缀匹配
            found = False
            for tid, tcfg in TASKS.items():
                target_keys = (
                    tid,
                    tcfg["script"],
                    tcfg["result"],
                    tcfg["script"][:-3] if tcfg["script"].endswith(".py") else "",
                )
                if key in target_keys:
                    if tid not in matched_keys:
                        matched_keys.add(tid)
                        matched.append(tcfg)
                    found = True
            if not found:
                print(f"⚠️ 未找到匹配的任务定义: {key}", file=sys.stderr)

        if matched:
            return matched
        raise ValueError(f"指定任务 '{raw_tasks}' 未匹配到任何有效注册任务（可选: {', '.join(TASKS.keys())}）")

    # 2. 定时调度 (schedule cron) — 旧三 cron 映射保留作兼容，主流程由 daily_orchestrator 排布
    if event == "schedule" or cron_expr:
        # 晨间主批次（兼容旧调度）：00:50 BJT (UTC 16:50) -> 12 矩阵 + 2 WorkBuddy
        if "16:50" in cron_expr or "50 16" in cron_expr or cron_expr == "50 16 * * *":
            return [t for t in TASKS.values() if "00:50" in t["tags"]]
        # 魔粒奖励窗口：09:10 BJT (UTC 01:10) -> ModelScope
        if "01:10" in cron_expr or "10 1" in cron_expr or cron_expr == "10 1 * * *":
            return [t for t in TASKS.values() if "09:10" in t["tags"]]
        # Latvi 兜底锚点：18:00 BJT (UTC 10:00) -> Latvi
        if "10:00" in cron_expr or "0 10" in cron_expr or cron_expr == "0 10 * * *":
            return [t for t in TASKS.values() if "18:00" in t["tags"]]

        # 兜底默认全量 00:50 任务
        return [t for t in TASKS.values() if "00:50" in t["tags"]]

    # 3. 动态接力与云端调度 (repository_dispatch)
    if event == "repository_dispatch" or dtype:
        if dtype in ("checkin_morning", "morning", "daily_morning"):
            return [t for t in TASKS.values() if "00:50" in t["tags"]]
        if dtype in ("checkin_modelscope", "modelscope_window"):
            return [TASKS["modelscope"]]
        if dtype in ("checkin_latvi", "latvi_anchor", "latvi_next_sign"):
            return [TASKS["latvi"]]
        if dtype in ("workbuddy_travel_claim", "workbuddy_claim"):
            return [TASKS["workbuddy-account-1"], TASKS["workbuddy-account-2"]]
        if dtype in TASKS:
            return [TASKS[dtype]]

    # 4. 手动默认全量矩阵站点
    return [t for t in TASKS.values() if "matrix" in t["tags"]]


def main() -> None:
    parser = argparse.ArgumentParser(description="Task Registry & Execution Queue Resolver")
    parser.add_argument("--event", type=str, default="", help="GitHub event name (schedule, repository_dispatch, workflow_dispatch)")
    parser.add_argument("--cron", type=str, default="", help="Cron expression for schedule event")
    parser.add_argument("--type", type=str, default="", help="Dispatch type for repository_dispatch event")
    parser.add_argument("--tasks", type=str, default="", help="Specified task names, comma-separated")
    parser.add_argument("--list", action="store_true", help="List all registered tasks")
    parser.add_argument("--json", action="store_true", help="Output execution queue as raw JSON")
    args = parser.parse_args()

    if args.list:
        print(f"📋 已注册全量任务 ({len(TASKS)} 个):")
        for tid, tcfg in TASKS.items():
            print(f"  • {tid:<22} -> 脚本: {tcfg['script']:<22} 超时: {tcfg['timeout']:<5}s 标签: {tcfg['tags']}")
        sys.exit(0)

    queue = resolve_execution_queue(
        event_name=args.event or os.getenv("GITHUB_EVENT_NAME", ""),
        cron=args.cron or os.getenv("CRON_EXPR", ""),
        dispatch_type=args.type or os.getenv("DISPATCH_TYPE", ""),
        input_tasks=args.tasks or os.getenv("INPUT_TASKS", ""),
    )

    if args.json:
        print(json.dumps(queue, ensure_ascii=False, indent=2))
        return

    # 输出为 GitHub Actions matrix.include 格式
    matrix_include = {
        "include": [
            {
                "id": t["id"],
                "script": t["script"],
                "result": t["result"],
                "timeout": str(t["timeout"]),
                "account": t["account"],
                "name": t["name"],
            }
            for t in queue
        ]
    }

    matrix_json = json.dumps(matrix_include, separators=(",", ":"))
    gh_output = os.getenv("GITHUB_OUTPUT")
    if gh_output:
        with open(gh_output, "a", encoding="utf-8") as fh:
            fh.write(f"matrix={matrix_json}\n")
            fh.write(f"task_count={len(queue)}\n")

    print(f"▶️ 调度队列解析完成（共 {len(queue)} 个任务）:")
    for t in queue:
        acc_str = f" [账号{t['account']}]" if t['account'] else ""
        print(f"  • [{t['id']}] {t['name']}{acc_str} -> {t['script']} (超时: {t['timeout']}s)")


if __name__ == "__main__":
    main()
