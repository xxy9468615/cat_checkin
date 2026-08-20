#!/usr/bin/env python3
"""将现有的 .task_results/*.json 迁移到 SQLite 数据库，供统计看板查询使用。

用法：
  python3 scripts/migrate_to_db.py          # 迁移所有已有 JSON 结果
  python3 scripts/migrate_to_db.py --force  # 强制覆盖已有库

注意：此脚本只在第一次运行时创建表；后续每次运行会自动把新的/更新的 JSON 记录 upsert 进去。
数据库文件位于：.task_results_stats.db（与 .task_results 同级，已 .gitignore 保护）。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
TASK_RESULTS_DIR = ROOT / ".task_results"
DB_PATH = ROOT / ".task_results_stats.db"

# 只迁移这些字段；其它（如 elapsed、output 等）保留但不强求
REQUIRED_JSON_FIELDS = {"ok", "script", "elapsed", "date"}
# 期望 JSON 的 key 结构（由 unified_report.py collect_all_results 产出）
# {ok, script, output, elapsed} 或者更精简的 {ok, script, elapsed, date}

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS daily_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    script_name     TEXT NOT NULL,       -- 脚本名（不含 .py 后缀，如 ai_router）
    result_json     TEXT NOT NULL,       -- 原始 JSON 文本（存储完整结果）
    date            TEXT,              -- 签到日期（YYYY-MM-DD）
    ok              INTEGER NOT NULL DEFAULT 0, -- 是否成功
    elapsed         REAL DEFAULT 0,     -- 耗时秒数
    output_text     TEXT,              -- output 字段文本片段（用于快速检索）
    collected_at    TEXT NOT NULL,      -- 何时被收集入库（ISO 8601）
    source_file     TEXT NOT NULL,      -- 原始 JSON 文件名（相对于任务输出目录）
    UNIQUE(script_name, date)
)
"""

INDEX_SQLS = [
    "CREATE INDEX IF NOT EXISTS idx_daily_script ON daily_results(script_name)",
    "CREATE INDEX IF NOT EXISTS idx_daily_date ON daily_results(date)",
    "CREATE INDEX IF NOT EXISTS idx_daily_ok ON daily_results(ok)",
]

INSERT_SQL = """
INSERT INTO daily_results(script_name, result_json, date, ok, elapsed, output_text, collected_at, source_file)
VALUES (:script_name, :result_json, :date, :ok, :elapsed, :output_text, :collected_at, :source_file)
ON CONFLICT(script_name, date) DO UPDATE SET
    result_json = EXCLUDED.result_json,
    ok = EXCLUDED.ok,
    elapsed = EXCLUDED.elapsed,
    output_text = EXCLUDED.output_text,
    collected_at = EXCLUDED.collected_at,
    source_file = EXCLUDED.source_file
"""


def parse_result(path: Path) -> Optional[Dict[str, Any]]:
    """读取单个 task result JSON 并提取关键字段。"""
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except Exception as e:
        print(f"⚠️ 无法读取 {path}: {e}", file=sys.stderr)
        return None

    if not isinstance(data, dict):
        print(f"⚠️ {path.name} 非字典结构，跳过", file=sys.stderr)
        return None

    # 提取 date
    date_val = data.get("date")
    if not date_val:
        # 有些结果可能没有 date（如 latvi 昨日宽限），仍然入库但 date 为 NULL
        date_val = None

    # 提取 ok / elapsed
    ok = bool(data.get("ok", False))
    elapsed = 0.0
    try:
        elapsed = float(data.get("elapsed") or 0)
    except (TypeError, ValueError):
        pass

    # 从 output 中截取前 200 字符用于快速检索
    output_raw = str(data.get("output") or "")
    output_snip = (output_raw[:200] + "...") if len(output_raw) > 200 else output_raw

    # 脚本名：从文件名推导，如 glados.py -> glados
    stem = path.stem  # 已去掉 .py 后缀（run_task.py 用 Path.stem）
    # 但 task_result 的文件名是 glados.json，stem 会是 "glados"，符合预期

    return {
        "script_name": stem,
        "result_json": raw,
        "date": date_val,
        "ok": ok,
        "elapsed": elapsed,
        "output_text": output_snip,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "source_file": path.name,
    }


def init_db(conn: sqlite3.Connection) -> None:
    """建表 + 建索引。"""
    cur = conn.cursor()
    cur.execute(CREATE_TABLE_SQL)
    for sql in INDEX_SQLS:
        cur.execute(sql)
    conn.commit()


def migrate(force: bool = False) -> None:
    """将 .task_results/ 目录下的所有 *.json 迁移入库。"""
    if not TASK_RESULTS_DIR.exists():
        print(f"⚠️ 目录不存在: {TASK_RESULTS_DIR}", file=sys.stderr)
        return

    # 如果库已存在且非 force，询问/跳过建表
    need_init = not DB_PATH.exists() or force
    conn = sqlite3.connect(str(DB_PATH))
    if need_init:
        init_db(conn)
        print(f"🆕 初始化数据库: {DB_PATH}")
    else:
        # 检查表是否存在（即使文件存在也可能缺表）
        cur = conn.cursor()
        try:
            cur.execute("SELECT 1 FROM daily_results LIMIT 1")
            print(f"♻️ 数据库已存在: {DB_PATH}，将增量导入新文件")
        except sqlite3.OperationalError:
            init_db(conn)

    # 扫描所有 *.json 文件
    json_files = sorted(TASK_RESULTS_DIR.rglob("*.json"))
    if not json_files:
        print("ℹ️ 未在 .task_results/ 下发现 *.json 文件")
        conn.close()
        return

    print(f"🔍 发现 {len(json_files)} 个 JSON 结果文件，开始迁移…")

    migrated = 0
    skipped = 0
    for jf in json_files:
        rec = parse_result(jf)
        if rec is None:
            skipped += 1
            continue
        try:
            cur = conn.cursor()
            cur.execute(INSERT_SQL, rec)
            conn.commit()
            migrated += 1
        except Exception as e:
            print(f"⚠️ 迁移失败 {jf.name}: {e}", file=sys.stderr)
            skipped += 1

    # 汇总统计
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM daily_results")
    total = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM daily_results WHERE ok = 1")
    ok_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(DISTINCT date) FROM daily_results")
    distinct_dates = cur.fetchone()[0]

    print(f"✅ 迁移完成: 成功 {migrated}，已存在/跳过 {skipped}，数据库总记录 {total}")
    print(f"   ✅ 成功记录 {ok_count} 条 | 涵盖日期 {distinct_dates} 天")
    conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="迁移现有 task result JSON 到 SQLite")
    parser.add_argument("--force", action="store_true", help="如库存在仍强制重建表（慎用）")
    args = parser.parse_args()
    migrate(force=args.force)


if __name__ == "__main__":
    main()