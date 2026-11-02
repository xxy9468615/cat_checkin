#!/usr/bin/env python3
# cron: 0 0 * * *
# new Env("统一任务注册表与调度队列")
"""统一任务注册表与调度队列管理器。

定义项目中全部 26 个签到任务的元数据（脚本、结果文件、超时、账号、调度标签），
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
    "railgun": {
        "id": "railgun",
        "script": "railgun.py",
        "name": "Railgun 签到兑换",
        "result": "railgun.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    # --- 2Libra（2026-11-01 用户指令下线：脚本/解析器/工作流接线已随本次清理移除，
    #     恢复：从 git 历史恢复 scripts/2libra.py + 注册表条目 + checkin.yml 接线，
    #     GH Secret TWO_LIBRA_COOKIE_1 清理时保留未删）---
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
    # --- moxing.vip（2026-11-01 用户指令下线：任务退役。脚本 moxing_vip.py 与
    #     report_fields 解析器保留；恢复时加回本表 + checkin.yml 环境变量段 +
    #     GH Secrets（MOXING_USERNAME/PASSWORD/UA，2026-11-01 清理时已保留未删））---
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
    # --- Tencent CloudStudio（2026-10-11 退役：上游凭据 7 天短命、更新成本高，
    #     2026-09-22 熔断后停用至今；脚本 tencent_cloudstudio.py 保留，恢复时加回本表即可）---
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
    # --- 掘金社区（juejin.cn 签到、免费抽奖、沾喜气、矿石资产）---
    "juejin": {
        "id": "juejin",
        "script": "juejin.py",
        "name": "掘金社区 签到",
        "result": "juejin.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    # --- OPPO商城（hd.opposhop.cn 打卡签到与浏览任务；2026-10-11 曾因 HeyTap
    #     acIdAuthSession 7 天短命凭据退役，2026-11-01 逆向 App 端 TOKENSID
    #     长效令牌（约 30 天寿命）后恢复）---
    "oppo": {
        "id": "oppo",
        "script": "oppo.py",
        "name": "OPPO商城 签到",
        "result": "oppo.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    # --- 腾讯 IMA（ima.qq.com 每日登录福利签到、满签奖励与算力资产；
    #     2026-11-02 逆向 H5 签到页接口接入：x-ima-cookie 根凭据（REFRESH-TOKEN，
    #     寿命以周/月计）每次运行现签约 2h 叶令牌 IMA-TOKEN，bkn=djb2(token) 本地推导）---
    "ima": {
        "id": "ima",
        "script": "ima.py",
        "name": "腾讯 IMA 签到",
        "result": "ima.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    # --- NodeSeek（nodeseek.com 每日随机/固定鸡腿签到，支持代理出口）---
    "nodeseek": {
        "id": "nodeseek",
        "script": "nodeseek.py",
        "name": "NodeSeek 签到",
        "result": "nodeseek.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    # --- 飞桨 AI Studio（aistudio.baidu.com 每日签到、积分与大模型 Token）---
    "aistudio": {
        "id": "aistudio",
        "script": "aistudio.py",
        "name": "飞桨 AI Studio 签到",
        "result": "aistudio.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    # --- 阿里云盘（alipan.com 每日签到、容量延期/扩容礼包与网盘空间）---
    "alipan": {
        "id": "alipan",
        "script": "alipan.py",
        "name": "阿里云盘 签到",
        "result": "alipan.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    # --- 什么值得买（smzdm.com 每日签到、积分金币提取与连签统计）---
    "smzdm": {
        "id": "smzdm",
        "script": "smzdm.py",
        "name": "什么值得买 签到",
        "result": "smzdm.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },

    # --- 天翼云盘（cloud.189.cn 每日签到、三次抽奖与容量统计，密码盲登）---
    "cloud189": {
        "id": "cloud189",
        "script": "cloud189.py",
        "name": "天翼云盘 签到",
        "result": "cloud189.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },
    # --- 吾爱破解（52pojie.cn 每日签到、2 吾爱币、积分与资产，固定 CN 出口代理）---
    "52pojie": {
        "id": "52pojie",
        "script": "52pojie.py",
        "name": "吾爱破解 签到",
        "result": "52pojie.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },

    # --- 夸克网盘（pan.quark.cn 每日签到领容量、资产统计与 __puus 滑动保活，
    #     App 抓包串 query 鉴权；2026-09-07 用户提供 kps_wg/sign_wg 抓包后启用）---
    "quark": {
        "id": "quark",
        "script": "quark.py",
        "name": "夸克网盘 签到",
        "result": "quark.json",
        "timeout": 300,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },

    # --- 中国电信（营业厅 / 天翼生活 / 10000 每日签到、免费抽奖、任务金豆与资产统计）---
    "telecom": {
        "id": "telecom",
        "script": "telecom.py",
        "name": "中国电信 签到",
        "result": "telecom.json",
        # 540s：wappark 现签链路 + 30 项任务扫描 + 乐园/资产 + imusic 子活动，
        # 实测正常耗时已达 264~300s，旧 300s 上限正压在悬崖上（2026-10-06 CI 复盘）。
        # 另：首个死节点 HK09 每次空耗一次 getSingle 连接超时，也需在预算内消化。
        "timeout": 540,
        "account": "",
        "tags": ["00:50", "matrix", "daily"],
    },

    # --- 中国电信 金豆商城话费抢兑（专项任务，TELECOM_MODE=exchange）---
    # 场次（北京时间）：上午 10:00 / 下午 14:00 开抢（先到先得），00:50 主链路
    # 时点必然错过场次（旧「已达标即直兑」从未成功过）。调度用 rolling 自排程：
    # 任务运行后把 last_credit_ts 写为「目标时刻 - 24h」，due = ts + 24h 精确落在
    # 场次前 30 分钟，由任务内等待对齐 09:59:15 突发——绕开心跳半点量化（若走
    # 重试梯，07:15/08:45 会被量化到 07:30/09:00，突发实际落在 10:00 后，错过
    # 开抢最激烈的头几十秒）。rolling 检查先于退避检查，此前一切触发被屏蔽。
    # 退出码 0=今日终局（成功/售罄/限兑/无券/未达标），1=暂时性失败继续重试。
    "telecom-exchange": {
        "id": "telecom-exchange",
        "script": "telecom.py",
        "name": "中国电信 金豆商城抢兑",
        "result": "telecom-exchange.json",
        # 任务内可能等待开场最长 31 分钟 + 突发连发，预算 40 分钟
        "timeout": 2400,
        "account": "",
        "env": {"TELECOM_MODE": "exchange"},
        "sched": {"type": "rolling", "period_h": 24},
        "tags": ["exchange", "daily"],
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
    # --- ModelScope 魔搭社区（2026-10-28 全站停用：国内站账号2封禁 + 测试号风控拉黑，
    #     风控「可疑活动」判定呈账号簇关联态势，暂停全部自动化流量保住剩余账号。
    #     脚本 modelscope.py 保留且已完成反风控加固（每账号UA/拟人间隔/黑名单自动
    #     停用/纯登录最小足迹），恢复时把两个实例加回本表即可；互动任务由
    #     MODELSCOPE_ENABLE_LIKE_TASKS / _AIGC_PUBLISH / _PROFILE_TASKS 开关独立控制）---

    # --- Latvi（2026-11-01 用户指令下线：24h 动态冷却/18:00 场次/QStash latvi_next_sign
    #     接力随本次清理一并移除；恢复：从 git 历史恢复 scripts/latvi.py + 注册表条目 +
    #     checkin.yml 接线（dispatch 类型/cache 路径/contains 过滤），
    #     GH Secrets LATVI_EMAIL/LATVI_PASSWORD 清理时保留未删）---
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
    if not raw_tasks or raw_tasks.lower() in ("none", "null", "nil", "empty", "[]"):
        return []

    wanted_keys = [k.strip() for k in raw_tasks.replace(" ", ",").split(",") if k.strip()]
    if not wanted_keys or all(k.lower() in ("none", "null", "nil", "empty", "[]") for k in wanted_keys):
        return []

    matched: List[Dict[str, Any]] = []
    matched_keys: set[str] = set()

    for key in wanted_keys:
        if key.lower() in ("none", "null", "nil", "empty", "[]"):
            continue
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
