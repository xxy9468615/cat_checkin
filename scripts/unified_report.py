#!/usr/bin/env python3
# cron: 0 12 * * *
# new Env("每日统一通知汇总")
"""统一汇总报告：自动扫描并汇聚各异步/独立签到任务结果，Resend/SMTP 统一邮件推送。

由 report.yml 在每天 12:00 UTC（20:00 北京时间）触发。
从 .task_results/ 目录或 GitHub Actions cache/artifact 收集所有当天完成的任务结果 JSON。
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from daily_report import build_report, send_email, send_resend  # noqa: E402


def _load_single_result(path: Path, expected_date: str) -> Optional[dict]:
    """读取并校验单个任务结果 JSON 文件。"""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        date_val = data.get("date")
        if date_val and date_val != expected_date:
            print(f"⚠️ 跳过历史过期数据: {path.name} (日期 {date_val} != 今日 {expected_date})")
            return None
        return data
    except Exception as e:
        print(f"⚠️ 读取 {path.name} 失败: {e}")
        return None


def collect_all_results(expected_date: str) -> List[Tuple[bool, Path, str, float]]:
    """收集所有任务结果并转换为 build_report 所需格式。"""
    collected: Dict[str, dict] = {}

    # 1. 扫描 .task_results/ 目录（全异步任务主路径）
    task_results_dir = Path(os.getenv("TASK_OUTPUT_DIR", ".task_results"))
    if task_results_dir.exists() and task_results_dir.is_dir():
        for json_file in sorted(task_results_dir.glob("*.json")):
            res = _load_single_result(json_file, expected_date)
            if res:
                # 以唯一文件名作为 key，避免同一脚本的多账号结果被脚本名覆盖合并
                collected[json_file.name] = res

    # 2. 兼容回退读取传统汇总文件（如 .checkin_report.json）
    legacy_files = [
        Path(os.getenv("CHECKIN_RESULT_FILE", ".checkin_report.json")),
        Path(os.getenv("LATVI_RESULT_FILE", ".latvi_result.json")),
        Path(os.getenv("WORKBUDDY_RESULT_FILE", ".workbuddy_result.json")),
    ]
    for leg in legacy_files:
        if leg.exists():
            try:
                raw = json.loads(leg.read_text(encoding="utf-8"))
                items = raw if isinstance(raw, list) else [raw]
                for item in items:
                    if isinstance(item, dict):
                        d_val = item.get("date")
                        if not d_val or d_val == expected_date:
                            s_name = str(item.get("script", ""))
                            if s_name and s_name not in collected:
                                collected[s_name] = item
            except Exception as e:
                print(f"⚠️ 解析回退文件 {leg.name} 失败: {e}")

    # 3. 转换为元组并按脚本名排序
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
    expected_date = os.getenv("TODAY") or dt.datetime.now(tz).strftime("%Y-%m-%d")

    results = collect_all_results(expected_date)

    if not results:
        print("❌ 今日（20:00 前）未收集到任何完成的签到任务结果，跳过推送。")
        sys.exit(1)

    title, report, fail_count = build_report(results)
    print("\n========== 每日统一汇总 ==========")
    print(report)

    push_enabled = os.getenv("DAILY_PUSH", "true").lower() not in {"0", "false", "no"}
    if push_enabled:
        send_email(title, report, results)
        send_resend(title, report, results)

    if fail_count:
        sys.exit(1)


if __name__ == "__main__":
    main()
