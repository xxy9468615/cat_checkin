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
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from common import upstash_redis_pipeline


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

    try:
        if os.getenv("TASK_TIMEOUT"):
            timeout = int(os.getenv("TASK_TIMEOUT", "300"))
        else:
            try:
                from task_registry import TASKS
                script_key = target_path.stem
                reg_task = TASKS.get(script_key) or next(
                    (t for t in TASKS.values() if t.get("script") == target_path.name),
                    None,
                )
                timeout = int(reg_task.get("timeout", 300)) if reg_task else 300
            except Exception:
                timeout = 300
    except ValueError:
        timeout = 300
        print("⚠️ TASK_TIMEOUT 格式不正确，已回退默认 300 秒")
    out_dir = Path(os.getenv("TASK_OUTPUT_DIR", ".task_results"))
    out_dir.mkdir(parents=True, exist_ok=True)

    # 多账号矩阵：允许覆盖结果文件名，避免同一脚本的多个账号结果互相覆盖。
    # 仅影响落盘文件名；结果 JSON 内的 script 字段仍用真实脚本名（保证邮件卡片标题正确）。
    result_name = os.getenv("TASK_RESULT_NAME") or f"{target_path.stem}.json"
    if not result_name.endswith(".json"):
        result_name += ".json"

    # 任务标题：orchestrator 可经 TASK_TITLE 注入实例化名称（同脚本多实例，
    # 如 ModelScope 国内站/国际站），缺省回退脚本 # new Env 注释
    task_name = (os.getenv("TASK_TITLE") or "").strip() or get_task_title(target_path)
    print(f"▶️ 开始执行任务: {task_name} ({target_path.name})")

    start_time = time.monotonic()
    timestamp = int(time.time())
    tz = dt.timezone(dt.timedelta(hours=8))
    today_bj = dt.datetime.now(tz).strftime("%Y-%m-%d")

    ok = False
    output = ""
    try:
        # 独立进程组：超时可整组击杀。只杀直接子进程时，继承 stdout 管道的孙进程
        # （如浏览器子进程）不退出会让 communicate 迟迟拿不到 EOF，
        # 实际挂到 job 级超时才死
        proc = subprocess.Popen(
            [sys.executable, str(target_path)],
            cwd=str(ROOT_DIR),
            env=os.environ.copy(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            stdout_data, _ = proc.communicate(timeout=timeout)
            elapsed = time.monotonic() - start_time
            output = (stdout_data or "").strip()
            ok = proc.returncode == 0
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
            try:
                stdout_data, _ = proc.communicate(timeout=10)
            except Exception:
                stdout_data = ""
            elapsed = time.monotonic() - start_time
            output = f"任务超时（>{timeout}s）\n{(stdout_data or '').strip()}".strip()
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
    try:
        result_file.write_text(json.dumps(result_dict, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"💾 任务结果已写入: {result_file} (ok={ok}, elapsed={elapsed:.1f}s)")
    except Exception as exc:
        # 结果写不出时该任务会在每日报告里「缺席」而非标红——降级写系统临时目录并显式报错
        fallback = Path(tempfile.gettempdir()) / result_name
        try:
            fallback.write_text(json.dumps(result_dict, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"❌ 结果写入 {result_file} 失败（{exc}），已降级写入 {fallback}")
        except Exception as exc2:
            print(f"❌ 结果写入彻底失败: {exc} / {exc2}")

    # 直写 Upstash Redis 数据库（免依赖 GitHub Actions artifact 跨 run 传输）
    try:
        url = os.getenv("UPSTASH_REDIS_REST_URL", "")
        token = os.getenv("UPSTASH_REDIS_REST_TOKEN", "")
        if url and token:
            prefix = os.getenv("CAT_CHECKIN_REDIS_PREFIX", "cat_checkin:").rstrip(":")
            raw_key = f"{prefix}:raw:{today_bj}"
            res_json = json.dumps(result_dict, ensure_ascii=False, separators=(",", ":"))
            # 写入当日本日任务结果 Hash 并设置 14 天 TTL
            ok_redis, detail = upstash_redis_pipeline([
                ["HSET", raw_key, result_name, res_json],
                ["EXPIRE", raw_key, 1209600],
            ])
            if ok_redis:
                print(f"📡 任务结果已同步 → Upstash Redis ({raw_key}[{result_name}])")
            else:
                print(f"⚠️ Upstash Redis 同步失败: {detail}")
    except Exception as exc:
        print(f"ℹ️ Upstash Redis 暂存未写入: {exc}")

    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
