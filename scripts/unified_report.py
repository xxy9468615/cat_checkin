#!/usr/bin/env python3
# cron: 0 2 * * *
# new Env("每日统一通知汇总")
"""统一汇总报告：自动扫描并汇聚各异步/独立签到任务结果，Resend/SMTP 统一邮件推送。

由 report.yml 在每天 02:00 UTC（10:00 北京时间）触发。
从 .task_results/ 目录或 GitHub Actions cache/artifact 收集所有当天完成的任务结果 JSON。
Latvi 因 24h 签到间隔约束固定在 18:00 运行，10:00 报告取其昨日结果（最近一次签到）。
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from daily_report import build_report, send_email, send_resend  # noqa: E402

# Latvi 的结果文件名（24h 间隔约束，18:00 运行，报告取昨日结果）
# 注意 run_task.py 用 Path.stem 命名：latvi.py → latvi.json（.py 后缀被剥掉）
LATVI_RESULT_FILE = "latvi.json"

# 期望任务清单：结果文件名 → 真实脚本（卡片标题从脚本读取）。
# 与 checkin.yml 矩阵 + 各独立 workflow 一一对应；新增站点/账号时同步维护。
# 缺席的结果会合成显式失败卡片，杜绝「某站点结果丢失 → 邮件里静默少一张卡」。
EXPECTED_RESULTS: Dict[str, str] = {
    **{f"{name}.json": f"{name}.py" for name in (
        "glados", "2libra", "bianjie_ai", "dji", "monkeycode",
        "moxing_vip", "naixi_forum", "pcbeta", "sophnet", "tencent_cloudstudio",
        "ugnas_club", "ai_router",
    )},
    "workbuddy-account-1.json": "workbuddy.py",
    "workbuddy-account-2.json": "workbuddy.py",
    "modelscope.json": "modelscope.py",
    "latvi.json": "latvi.py",
}


def _load_single_result(path: Path, accepted_dates: Set[str]) -> Optional[dict]:
    """读取并校验单个任务结果 JSON（date 须在 accepted_dates 白名单内）。"""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        date_val = data.get("date")
        # date 缺失/为空同样不放行：历史无日期文件不能冒充今日结果
        if not date_val or date_val not in accepted_dates:
            print(f"⚠️ 跳过过期/无日期数据: {path.name} (日期 {date_val}，要求 {sorted(accepted_dates)})")
            return None
        return data
    except Exception as e:
        print(f"⚠️ 读取 {path.name} 失败: {e}")
        return None


def collect_all_results(today: str, yesterday: str) -> List[Tuple[bool, Path, str, float]]:
    """收集所有任务结果并转换为 build_report 所需格式。"""
    collected: Dict[str, dict] = {}

    # 递归扫描 .task_results/（主路径：gh run download 会按 artifact 名建子目录，
    # 如 .task_results/task-result-glados.py/glados.json，不能只扫顶层）
    task_results_dir = Path(os.getenv("TASK_OUTPUT_DIR", ".task_results"))
    if task_results_dir.exists() and task_results_dir.is_dir():
        for json_file in sorted(task_results_dir.rglob("*.json")):
            # 以唯一文件名作为 key，避免同一脚本的多账号结果被脚本名覆盖合并；
            # sorted 字典序让 artifact 子目录（task-result-*）后遍历、覆盖 cache 恢复的同名旧文件
            dates = {today, yesterday} if json_file.name == LATVI_RESULT_FILE else {today}
            res = _load_single_result(json_file, dates)
            if res:
                collected[json_file.name] = res

    # 期望清单比对：缺席任务合成显式失败卡片（红卡），让「任务没跑/结果丢失」可见
    for missing in sorted(set(EXPECTED_RESULTS) - set(collected)):
        print(f"⚠️ 期望结果缺失: {missing}")
        collected[missing] = {
            "ok": False,
            "script": EXPECTED_RESULTS[missing],
            "output": "结果未收集到（任务未运行或 artifact/cache 丢失）",
            "elapsed": 0.0,
        }

    # 转换为元组并按脚本名排序
    out: List[Tuple[bool, Path, str, float]] = []
    for _key, data in sorted(collected.items()):
        ok = bool(data.get("ok"))
        # 卡片标题以结果内的 script 字段为准（如 workbuddy.py），而非去重的文件名 key
        script_name = data.get("script") or (_key[:-5] if _key.endswith(".json") else _key)
        path = BASE_DIR / script_name if (BASE_DIR / script_name).exists() else Path(script_name)
        # 字段防御：单个坏结果（elapsed 非数字 / output 为 null）只影响自己，不炸整条链
        try:
            elapsed = float(data.get("elapsed") or 0.0)
        except (TypeError, ValueError):
            elapsed = 0.0
        output = str(data.get("output") or "")
        out.append((ok, path, output, elapsed))

    return out


def main() -> None:
    tz = dt.timezone(dt.timedelta(hours=8))
    now = dt.datetime.now(tz)
    today = os.getenv("TODAY") or now.strftime("%Y-%m-%d")
    yesterday = (now - dt.timedelta(days=1)).strftime("%Y-%m-%d")

    results = collect_all_results(today, yesterday)

    if not results:
        print("❌ 今日（10:00 前）未收集到任何完成的签到任务结果，跳过推送。")
        sys.exit(1)

    title, report, fail_count = build_report(results)
    print("\n========== 每日统一汇总 ==========")
    print(report)

    push_enabled = os.getenv("DAILY_PUSH", "true").lower() not in {"0", "false", "no"}
    if push_enabled:
        sent_smtp = send_email(title, report, results)
        sent_resend, resend_msg_id = send_resend(title, report, results)
        if not (sent_smtp or sent_resend):
            print("❌ 所有邮件通道推送失败：不写发送标记并退出非零，等待 10:30 兜底重试")
            sys.exit(1)
        # 邮件已送达或已交接 QStash（至少一个通道）才写当日标记：report.yml 靠它去重。
        # resend_msg_id 可为空（SMTP-only / 直发失败 / QStash publish 失败回退直发但 Resend 未返回 id），
        # 有值时 10:30 兜底 run 可查询 QStash /v2/logs 确认投递状态。
        marker = {"date": today, "sent_at": dt.datetime.now(tz).isoformat()}
        if resend_msg_id:
            marker["resend_msg_id"] = resend_msg_id
        Path(".report_sent").write_text(
            json.dumps(marker, ensure_ascii=False),
            encoding="utf-8",
        )
        print("🔖 已写入今日发送标记 .report_sent")
        # 邮件已送达即视为本次运行成功（任务失败详情已在邮件正文的红卡片里）：
        # exit 0 让 run 结论为 success，report.yml 的 API 去重（只认 success run）
        # 才能兜住 marker cache 保存静默失败时的重复发送场景
        return

    # 未启用推送（本地调试）：保留「有任务失败则 exit 1」的 CLI 语义
    if fail_count:
        sys.exit(1)


if __name__ == "__main__":
    main()
