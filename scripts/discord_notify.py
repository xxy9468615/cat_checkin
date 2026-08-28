#!/usr/bin/env python3
# new Env("Discord Webhook 通知")
"""Discord Webhook 通知模块：执行进度实时轮播 + 汇总总计。

被 daily_orchestrator.py（每个任务完成即推送一条 embed 卡片，全部结束后推总计）
与 unified_report.py（汇总报告总计，替代已注释的邮件通道）调用。
通知内容按 templates/discord_progress.json 与 discord_summary.json 指定模板渲染
（占位符替换；模板文件缺失时回退代码内置默认模板）。

Environment:
  DISCORD_WEBHOOK_URL  Discord Webhook 地址；未设置时使用下方内置默认 URL。
所有推送均为 best-effort：任何异常只打印警告，绝不阻塞/中断主流程。
"""
from __future__ import annotations

import datetime
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# 内置默认 Webhook（env DISCORD_WEBHOOK_URL 优先；更换地址时改 env 或此处）
DEFAULT_WEBHOOK_URL = (
    "https://discord.com/api/webhooks/1542881396656316459/"
    "tUZ1qvAHLHYmUOzakWTmoApidntcJsVYFd4cVhgr-znGwUcTWZbwmqEkaz9tHIqfpRdM"
)

COLOR_OK = 3066993      # 绿
COLOR_FAIL = 15158332   # 红
COLOR_PENDING = 9807270 # 灰
COLOR_INFO = 3447003    # 蓝

# Discord embed 限制：description ≤ 4096、单字段 value ≤ 1024、总 payload ≤ 6000
OUTPUT_MAX_LEN = 1000
SUMMARY_MAX_LEN = 3500


def webhook_url() -> str:
    return (os.getenv("DISCORD_WEBHOOK_URL") or "").strip() or DEFAULT_WEBHOOK_URL


def _load_template(name: str, fallback: Dict[str, Any]) -> Dict[str, Any]:
    """读取指定模板 JSON；缺失/损坏时回退内置模板（与 email 模板同策略）。"""
    try:
        tpl = json.loads((TEMPLATE_DIR / name).read_text(encoding="utf-8"))
        if isinstance(tpl, dict):
            # 剥离模板内的说明性键（如 _comment），Discord API 拒绝未知字段
            return {k: v for k, v in tpl.items() if not k.startswith("_")}
        return fallback
    except Exception:
        return fallback


def _render(obj: Any, replacements: Dict[str, str]) -> Any:
    """递归替换模板中所有字符串值里的 {{PLACEHOLDER}} 占位符。"""
    if isinstance(obj, str):
        for key, value in replacements.items():
            obj = obj.replace(key, value)
        return obj
    if isinstance(obj, dict):
        return {k: _render(v, replacements) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_render(v, replacements) for v in obj]
    return obj


def _coerce_embed_colors(payload: Dict[str, Any]) -> None:
    """模板渲染后 color 为字符串，Discord 要求 embed.color 必须是整数。"""
    for embed in payload.get("embeds", []) or []:
        color = embed.get("color")
        if isinstance(color, str) and color.lstrip("-").isdigit():
            embed["color"] = int(color)


def _post_webhook(payload: Dict[str, Any]) -> bool:
    """POST 到 Discord Webhook。common.Http 自带 429/5xx 指数退避重试。"""
    try:
        _coerce_embed_colors(payload)
        import common as _common
        resp = _common.Http().request(
            "POST",
            webhook_url(),
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            timeout=15,
        )
        if 200 <= resp.code < 300:
            return True
        print(f"⚠️ Discord 推送失败: HTTP {resp.code} {(resp.text or '')[:200]}")
    except Exception as exc:
        print(f"⚠️ Discord 推送异常: {exc}")
    return False


def _clip(text: str, max_len: int) -> str:
    """取输出末尾片段——各脚本的结果摘要与报错都打印在末尾，超长丢弃头部。"""
    text = (text or "").strip()
    if len(text) <= max_len:
        return text or "（无输出）"
    return "…（前文已截断）\n" + text[-max_len:]


def _timestamp_bjt() -> str:
    return datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat()


def _error_excerpt(output: str) -> str:
    """失败任务优先取含错误关键字的末尾有效行，取不到再回退末尾原文。"""
    try:
        from daily_report import _last_meaningful_line
        line = _last_meaningful_line(output or "")
        if line:
            return line[:OUTPUT_MAX_LEN]
    except Exception:
        pass
    return _clip(output, OUTPUT_MAX_LEN)


# === 内置默认模板（templates/ 下同名 JSON 优先） ===

DEFAULT_PROGRESS_TEMPLATE = {
    "username": "cat_checkin",
    "embeds": [{
        "title": "{{STATUS_ICON}} {{TASK_NAME}} — {{STATUS_TEXT}}",
        "color": "{{COLOR}}",
        "fields": [
            {"name": "📊 进度", "value": "{{PROGRESS}}", "inline": True},
            {"name": "⏱️ 耗时", "value": "{{ELAPSED}}", "inline": True},
            {"name": "📜 输出摘要", "value": "{{OUTPUT}}"},
        ],
        "footer": {"text": "cat_checkin 自动推送"},
        "timestamp": "{{TIMESTAMP}}",
    }],
}

DEFAULT_SUMMARY_TEMPLATE = {
    "username": "cat_checkin",
    "embeds": [{
        "title": "{{TITLE}}",
        "description": "{{REPORT}}",
        "color": "{{COLOR}}",
        "footer": {"text": "cat_checkin 自动推送"},
        "timestamp": "{{TIMESTAMP}}",
    }],
}


def notify_task_progress(
    task_id: str,
    name: str,
    script: str,
    ok: bool,
    output: str,
    elapsed: Optional[float] = None,
    progress: str = "",
) -> bool:
    """单任务完成实时推送。progress 形如「3/12 · 成功 2 · 失败 1」。"""
    status_icon = "✅" if ok else "❌"
    status_text = "成功" if ok else "失败"
    elapsed_str = f"{elapsed:.1f}s" if elapsed else "—"
    replacements = {
        "{{STATUS_ICON}}": status_icon,
        "{{STATUS_TEXT}}": status_text,
        "{{COLOR}}": str(COLOR_OK if ok else COLOR_FAIL),
        "{{TASK_NAME}}": f"{name or task_id} (`{script}`)",
        "{{PROGRESS}}": progress or "—",
        "{{ELAPSED}}": elapsed_str,
        "{{OUTPUT}}": _clip(output, OUTPUT_MAX_LEN) if ok else _error_excerpt(output),
        "{{TIMESTAMP}}": _timestamp_bjt(),
    }
    tpl = _load_template("discord_progress.json", DEFAULT_PROGRESS_TEMPLATE)
    return _post_webhook(_render(tpl, replacements))


def notify_summary(title: str, report: str, ok: bool = True) -> bool:
    """汇总总计推送（orchestrator 结束总计 / unified_report 汇总报告共用）。"""
    report = re.sub(r"\n{3,}", "\n\n", (report or "").strip())
    replacements = {
        "{{TITLE}}": title[:256],
        "{{REPORT}}": _clip(report, SUMMARY_MAX_LEN),
        "{{COLOR}}": str(COLOR_OK if ok else COLOR_FAIL),
        "{{TIMESTAMP}}": _timestamp_bjt(),
    }
    tpl = _load_template("discord_summary.json", DEFAULT_SUMMARY_TEMPLATE)
    return _post_webhook(_render(tpl, replacements))


def main() -> None:
    """CLI 自测：python3 discord_notify.py --test 发送一条测试消息。"""
    ok = notify_task_progress(
        task_id="selftest",
        name="Discord 通知自测",
        script="discord_notify.py",
        ok=True,
        output="这是一条测试消息，如果你看到它说明 Webhook 连通正常。",
        elapsed=0.1,
        progress="test",
    )
    print("✅ 测试消息已发送" if ok else "❌ 测试消息发送失败")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
