#!/usr/bin/env python3
# cron: 30 10 * * *
# new Env("每日签到统一汇总推送")
"""Run standalone sign-in scripts sequentially and send one Telegram daily report.

Environment:
  TG_BOT_TOKEN            Telegram Bot token, required for push.
  TG_CHAT_ID              Telegram chat_id, preferred.
  TG_USER_ID              Alias of TG_CHAT_ID.
  TG_API_HOST             Optional, default: https://api.telegram.org
  DAILY_TASKS             Optional comma-separated script list. Default: all *.py except common/report.
  DAILY_EXCLUDE           Optional comma-separated script list to skip.
  DAILY_TIMEOUT           Per-task timeout seconds, default: 180.
  DAILY_PUSH              true/false, default: true. If false only prints report.
  DAILY_MAX_TASK_OUTPUT   Max characters per task block, default: 1500.
"""

from __future__ import annotations

import datetime
import os
import re
import subprocess
import sys
import textwrap
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable, List, Tuple

BASE_DIR = Path(__file__).resolve().parent
SELF_NAME = Path(__file__).name
DEFAULT_EXCLUDE = {"common.py", SELF_NAME}


def bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "y", "on"}


def split_csv(value: str) -> List[str]:
    return [x.strip() for x in value.split(",") if x.strip()]


def normalize_script_name(name: str) -> str:
    name = name.strip()
    if not name.endswith(".py"):
        name += ".py"
    return name


def get_task_title(path: Path) -> str:
    """提取脚本注释中的 # new Env("站点名称")"""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r'#\s*new\s+Env\(["\'](.+?)["\']\)', content)
        if m:
            return m.group(1).strip()
    except Exception:
        pass
    return path.stem


def discover_tasks() -> List[Path]:
    raw_tasks = os.getenv("DAILY_TASKS") or os.getenv("QL_DAILY_TASKS", "")
    raw_excludes = os.getenv("DAILY_EXCLUDE") or os.getenv("QL_DAILY_EXCLUDE", "")
    explicit = split_csv(raw_tasks)
    excludes = {normalize_script_name(x) for x in split_csv(raw_excludes)}
    excludes |= DEFAULT_EXCLUDE

    if explicit:
        tasks = [BASE_DIR / normalize_script_name(x) for x in explicit]
    else:
        tasks = sorted([p for p in BASE_DIR.glob("*.py") if not p.name.startswith("_")])

    return [p for p in tasks if p.name not in excludes and p.exists()]


def run_task(path: Path, timeout: int) -> Tuple[bool, Path, str, float]:
    start = time.monotonic()
    try:
        proc = subprocess.run(
            [sys.executable, str(path)],
            cwd=str(BASE_DIR),
            env=os.environ.copy(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        elapsed = time.monotonic() - start
        output = (proc.stdout or "").strip()
        return proc.returncode == 0, path, output, elapsed
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start
        output = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        return False, path, f"任务超时（>{timeout}s）\n{output.strip()}", elapsed
    except Exception as exc:
        elapsed = time.monotonic() - start
        return False, path, f"执行异常: {exc}", elapsed


def truncate_block(text: str, limit: int = 1500) -> str:
    """智能首尾保留截断。

    签到脚本的关键信息（如积分、Token余额、最终成功/失败统计、异常堆栈）通常在输出末尾。
    若超长，保留头部（前 400 字）和尾部（后 1000 字），防止关键数据缺失。
    """
    text = text.strip()
    if len(text) <= limit:
        return text

    head_len = min(400, limit // 3)
    tail_len = max(limit - head_len - 60, 400)
    omitted = len(text) - head_len - tail_len

    if omitted <= 0:
        return text[:limit].rstrip() + "\n...（已截断）"

    head = text[:head_len].rstrip()
    tail = text[-tail_len:].lstrip()
    return f"{head}\n...（中间省略 {omitted} 字）...\n{tail}"


def build_report(results: Iterable[Tuple[bool, Path, str, float]], max_output_limit: int = 1500) -> Tuple[str, str, int]:
    rows = list(results)
    ok_count = sum(1 for ok, *_ in rows if ok)
    fail_count = len(rows) - ok_count
    today_str = datetime.date.today().strftime("%Y-%m-%d")

    summary_header = f"📢 每日签到汇总 ({today_str})"
    stat_line = f"📊 状态统计：成功 {ok_count} | 失败 {fail_count} | 总计 {len(rows)}"

    lines = [summary_header, stat_line, ""]
    for ok, path, output, elapsed in rows:
        status = "✅" if ok else "❌"
        task_title = get_task_title(path)
        lines.append(f"{status} 【{task_title}】 ({path.name} - {elapsed:.1f}s)")
        if output:
            lines.append(textwrap.indent(truncate_block(output, limit=max_output_limit), "  "))
        else:
            lines.append("  无输出")
        lines.append("")
    return summary_header, "\n".join(lines).strip(), fail_count


def telegram_chunks(header: str, task_blocks: List[str], limit: int = 3800) -> List[str]:
    """按任务块边界智能分片 Telegram 消息，避免中断单个任务的输出内容。"""
    if not task_blocks:
        return [header]

    raw_chunks: List[str] = []
    current_lines: List[str] = []
    current_len = 0

    for block in task_blocks:
        block = block.strip()
        if not block:
            continue
        block_len = len(block) + 2  # plus \n\n

        if len(block) > limit:
            if current_lines:
                raw_chunks.append("\n\n".join(current_lines))
                current_lines = []
                current_len = 0

            lines = block.split("\n")
            sub_chunk: List[str] = []
            sub_len = 0
            for line in lines:
                if sub_len + len(line) + 1 > limit:
                    if sub_chunk:
                        raw_chunks.append("\n".join(sub_chunk))
                        sub_chunk = []
                        sub_len = 0
                sub_chunk.append(line)
                sub_len += len(line) + 1
            if sub_chunk:
                raw_chunks.append("\n".join(sub_chunk))
            continue

        if current_lines and (current_len + block_len > limit):
            raw_chunks.append("\n\n".join(current_lines))
            current_lines = [block]
            current_len = block_len
        else:
            current_lines.append(block)
            current_len += block_len

    if current_lines:
        raw_chunks.append("\n\n".join(current_lines))

    total = len(raw_chunks)
    if total <= 1:
        body = raw_chunks[0] if raw_chunks else ""
        return [f"{header}\n\n{body}".strip()]

    formatted_chunks: List[str] = []
    header_lines = [h.strip() for h in header.split("\n") if h.strip()]
    title_line = header_lines[0] if header_lines else "📢 每日签到汇总"
    rest_header = "\n".join(header_lines[1:]) if len(header_lines) > 1 else ""

    for idx, chunk in enumerate(raw_chunks, 1):
        if idx == 1:
            first_header = f"{title_line} [{idx}/{total}]"
            if rest_header:
                first_header += f"\n{rest_header}"
            formatted_chunks.append(f"{first_header}\n\n{chunk}".strip())
        else:
            formatted_chunks.append(f"📢 每日签到汇总 (续 {idx}/{total})\n\n{chunk}".strip())
    return formatted_chunks


def send_telegram(title: str, content: str) -> None:
    token = os.getenv("TG_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TG_CHAT_ID", "").strip() or os.getenv("TG_USER_ID", "").strip()
    if not token or not chat_id:
        print("未配置 TG_BOT_TOKEN + TG_CHAT_ID/TG_USER_ID，跳过 Telegram 推送。")
        return

    api_host = os.getenv("TG_API_HOST", "https://api.telegram.org").rstrip("/")
    url = f"{api_host}/bot{token}/sendMessage"

    # 按任务标题行切分，不能用 split("\n\n")：脚本输出内部常含空行
    # （如 Sophnet 每个账号之间），否则单个任务会被拆散，分片时标题与内容分离。
    header_parts: List[str] = []
    task_blocks: List[str] = []
    current: List[str] = []

    for line in content.split("\n"):
        if line.startswith("📢") or line.startswith("📊"):
            header_parts.append(line)
        elif re.match(r"^[✅❌]\s*【", line):
            if current:
                task_blocks.append("\n".join(current).strip())
            current = [line]
        elif current:
            current.append(line)
    if current:
        task_blocks.append("\n".join(current).strip())

    header = "\n".join(header_parts)
    chunks = telegram_chunks(header, task_blocks)

    for chunk in chunks:
        payload = {
            "chat_id": chat_id,
            "text": chunk,
            "disable_web_page_preview": "true",
        }
        data = urllib.parse.urlencode(payload).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=60) as resp:
            if resp.status < 200 or resp.status >= 300:
                raise RuntimeError(f"Telegram 推送失败: HTTP {resp.status}")
    print("✅ Telegram 推送完成")


def main() -> None:
    timeout = int(os.getenv("DAILY_TIMEOUT") or os.getenv("QL_DAILY_TIMEOUT", "180"))
    max_output_limit = int(os.getenv("DAILY_MAX_TASK_OUTPUT", "1500"))
    tasks = discover_tasks()
    if not tasks:
        raise SystemExit("未发现可执行签到脚本")

    print(f"发现 {len(tasks)} 个签到脚本，将顺序执行：")
    for task in tasks:
        print(f"- {task.name}")
    print("")

    results = [run_task(task, timeout) for task in tasks]
    title, report, fail_count = build_report(results, max_output_limit=max_output_limit)
    print("\n========== 每日汇总 ==========")
    print(report)

    push_enabled = bool_env("DAILY_PUSH", True) if os.getenv("DAILY_PUSH") is not None else bool_env("QL_DAILY_PUSH", True)
    if push_enabled:
        send_telegram(title, report)

    if fail_count:
        sys.exit(1)


if __name__ == "__main__":
    main()
