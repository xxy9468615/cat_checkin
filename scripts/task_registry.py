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
    # --- u1s1.io（AI Token 平台，每日打卡领 200 万 Token，连续第 3 天额外 +100 万 Token）---
    "u1s1": {
        "id": "u1s1",
        "script": "u1s1.py",
        "name": "u1s1.io 签到",
        "result": "u1s1.json",
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
    # ModelScope CN 站与国际站（AI）拆为两个独立任务实例：分开调度、独立失败卡、
    # 独立通知状态；MODELSCOPE_SITE 由 orchestrator 按 cfg["env"] 注入。
    # 显式 tasks=modelscope 仍同时命中两实例（resolve_execution_queue 按脚本名匹配）。
    "modelscope": {
        "id": "modelscope",
        "script": "modelscope.py",
        "name": "ModelScope 国内站签到",
        "result": "modelscope.json",
        "timeout": 600,
        "account": "",
        "tags": ["09:10", "modelscope", "daily"],
        "env": {"MODELSCOPE_SITE": "cn"},
        # 滚动冷却型调度：daily_active 领取后 24h 才可再领，由心跳 run 按
        # last_credit_ts 状态驱动（DUE_ONLY），不依赖固定启动时刻
        "sched": {"type": "rolling", "period_h": 24},
    },
    "modelscope_ai": {
        "id": "modelscope_ai",
        "script": "modelscope.py",
        "name": "ModelScope 国际站签到",
        "result": "modelscope_ai.json",
        "timeout": 600,
        "account": "",
        "tags": ["09:10", "modelscope", "modelscope_ai", "daily"],
        "env": {"MODELSCOPE_SITE": "ai"},
        "sched": {"type": "rolling", "period_h": 24},
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


def resolve_execution_queue(input_tasks: str = "") -> List[Dict[str, Any]]:
    """解析显式指定的任务队列（唯一调用方：daily_orchestrator --tasks）。

    支持：逗号分隔的 task_id / 脚本名 / 结果文件名精确匹配，及分组别名
    all / matrix / workbuddy。旧的 schedule-cron 与 repository_dispatch
    映射分支已删除——checkin.yml 的 Resolve 步骤自行做 dispatch->tasks 映射，
    且原 cron 匹配用带冒号写法（"16:50"）永远匹配不到 GitHub cron 格式，属死代码。
    """
    raw_tasks = (input_tasks or "").strip()

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

        # 按 task_id / 脚本名 / 结果文件名 / 去扩展名脚本名 精确匹配
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Task Registry & Execution Queue Resolver")
    parser.add_argument("--tasks", type=str, default="", help="Specified task names, comma-separated")
    parser.add_argument("--list", action="store_true", help="List all registered tasks")
    parser.add_argument("--json", action="store_true", help="Output execution queue as raw JSON")
    args = parser.parse_args()

    if args.list:
        print(f"📋 已注册全量任务 ({len(TASKS)} 个):")
        for tid, tcfg in TASKS.items():
            print(f"  • {tid:<22} -> 脚本: {tcfg['script']:<22} 超时: {tcfg['timeout']:<5}s 标签: {tcfg['tags']}")
        sys.exit(0)

    queue = resolve_execution_queue(input_tasks=args.tasks or os.getenv("INPUT_TASKS", ""))

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
