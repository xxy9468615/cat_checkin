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


def _load_single_result(path: Path, accepted_dates: Set[str]) -> Optional[dict]:
    """读取并校验单个任务结果 JSON（date 须在 accepted_dates 白名单内）。"""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        date_val = data.get("date")
        if date_val and date_val not in accepted_dates:
            print(f"⚠️ 跳过历史过期数据: {path.name} (日期 {date_val}，要求 {sorted(accepted_dates)})")
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
            # 以唯一文件名作为 key，避免同一脚本的多账号结果被脚本名覆盖合并
            dates = {today, yesterday} if json_file.name == LATVI_RESULT_FILE else {today}
            res = _load_single_result(json_file, dates)
            if res:
                collected[json_file.name] = res

    # 转换为元组并按脚本名排序
    out: List[Tuple[bool, Path, str, float]] = []
    for _key, data in sorted(collected.items()):
        ok = bool(data.get("ok"))
        # 卡片标题以结果内的 script 字段为准（如 workbuddy.py），而非去重的文件名 key
        script_name = data.get("script") or (_key[:-5] if _key.endswith(".json") else _key)
        path = BASE_DIR / script_name if (BASE_DIR / script_name).exists() else Path(script_name)
        output = str(data.get("output", ""))
        elapsed = float(data.get("elapsed", 0.0))
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
        send_email(title, report, results)
        send_resend(title, report, results)
        # 邮件已推送（无论任务成败）即写当日标记：report.yml 靠它去重，
        # 避免「有任务失败 → exit 1 → 标记未写 → 10:30 兜底重发」的重复邮件。
        # 结果为空时在上面已提前 exit，不会走到这里。
        Path(".report_sent").write_text(
            json.dumps({"date": today, "sent_at": dt.datetime.now(tz).isoformat()}, ensure_ascii=False),
            encoding="utf-8",
        )
        print("🔖 已写入今日发送标记 .report_sent")

    if fail_count:
        sys.exit(1)


if __name__ == "__main__":
    main()
