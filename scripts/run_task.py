#!/usr/bin/env python3
"""统一单任务运行器：执行单个签到脚本并生成标准结构化结果 JSON。

用法：
  python3 scripts/run_task.py glados.py
  python3 scripts/run_task.py workbuddy.py
  python3 scripts/run_task.py scripts/latvi.py

环境变量：
  TASK_OUTPUT_DIR       结果 JSON 保存目录，默认 .task_results
  TASK_TIMEOUT          任务超时秒数，默认 300
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent


def get_task_title(path: Path) -> str:
    """提取脚本中的 # new Env("站点名称") 注释。"""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r'#\s*new\s+Env\(["\'](.+?)["\']\)', content)
        if m:
            return m.group(1).strip()
    except Exception:
        pass
    return path.stem


def main() -> None:
    if len(sys.argv) < 2:
        print("❌ 用法: python3 scripts/run_task.py <script_name_or_path>")
        sys.exit(1)

    target_raw = sys.argv[1].strip()
    target_path = Path(target_raw)
    if not target_path.is_absolute():
        if (BASE_DIR / target_path).exists():
            target_path = BASE_DIR / target_path
        elif (ROOT_DIR / target_path).exists():
            target_path = ROOT_DIR / target_path
        elif (BASE_DIR / f"{target_raw}.py").exists():
            target_path = BASE_DIR / f"{target_raw}.py"

    if not target_path.exists():
        print(f"❌ 目标脚本不存在: {target_raw}")
        sys.exit(1)

    timeout = int(os.getenv("TASK_TIMEOUT", "300"))
    out_dir = Path(os.getenv("TASK_OUTPUT_DIR", ".task_results"))
    out_dir.mkdir(parents=True, exist_ok=True)

    # 多账号矩阵：允许覆盖结果文件名，避免同一脚本的多个账号结果互相覆盖。
    # 仅影响落盘文件名；结果 JSON 内的 script 字段仍用真实脚本名（保证邮件卡片标题正确）。
    result_name = os.getenv("TASK_RESULT_NAME") or f"{target_path.stem}.json"
    if not result_name.endswith(".json"):
        result_name += ".json"

    task_name = get_task_title(target_path)
    print(f"▶️ 开始执行任务: {task_name} ({target_path.name})")

    start_time = time.monotonic()
    timestamp = int(time.time())
    tz = dt.timezone(dt.timedelta(hours=8))
    today_bj = dt.datetime.now(tz).strftime("%Y-%m-%d")

    ok = False
    output = ""
    try:
        proc = subprocess.run(
            [sys.executable, str(target_path)],
            cwd=str(ROOT_DIR),
            env=os.environ.copy(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        elapsed = time.monotonic() - start_time
        output = (proc.stdout or "").strip()
        ok = proc.returncode == 0
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start_time
        out_part = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        output = f"任务超时（>{timeout}s）\n{out_part.strip()}".strip()
        ok = False
    except Exception as exc:
        elapsed = time.monotonic() - start_time
        output = f"执行异常: {exc}"
        ok = False

    # 打印脚本执行输出
    if output:
        print(output)

    # 构造标准结果字典
    result_dict = {
        "ok": ok,
        "script": target_path.name,
        "name": task_name,
        "output": output,
        "elapsed": round(elapsed, 2),
        "date": today_bj,
        "timestamp": timestamp,
    }

    result_file = out_dir / result_name
    result_file.write_text(json.dumps(result_dict, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"💾 任务结果已写入: {result_file} (ok={ok}, elapsed={elapsed:.1f}s)")

    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
