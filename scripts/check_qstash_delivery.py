#!/usr/bin/env python3
"""QStash 邮件投递状态核查。

读取发送标记（优先 env：SENT_MARKER_JSON 全量 marker JSON / RESEND_MSG_ID 单值；
回退本地 MARKER_PATH 文件——CI 跨 job 不传递，仅本地调试可用），查询 QStash
/v2/logs 获取投递状态，输出到 $GITHUB_OUTPUT（CI 使用）或 stdout（本地调试）。

输出 delivery= 五态之一：
  ok      — QStash 已成功投递到 Resend（DELIVERED）
  pending — QStash 仍在重试中（RETRY / ACTIVE），不动它
  failed  — QStash 重试耗尽，投递失败（FAILED / ERROR），触发重发
  unknown — 查询失败（偏防重复，打印控制台链接供人工排查）
  none    — 无 resend_msg_id（SMTP-only / 直发 / 无 marker），跳过核查
"""
from __future__ import annotations

import json
import os
import sys
from typing import Optional


def _qstash_base_url() -> str:
    """从 QSTASH_URL 推导区域端点（剥 /v2/publish 或尾部路径）。"""
    url = os.getenv("QSTASH_URL") or os.getenv("WORKBUDDY_QSTASH_URL") or ""
    if not url:
        return ""
    # 兼容两种格式: https://qstash.upstash.io 或 https://qstash.upstash.io/v2/publish
    for suffix in ("/v2/publish", "/v2"):
        if url.rstrip("/").endswith(suffix):
            return url.rstrip("/")[: -len(suffix)]
    return url.rstrip("/")


def _load_marker() -> Optional[dict]:
    """标记来源：env 优先（CI：check_sent 步骤从 Redis marker 导出），本地文件兜底。"""
    raw = os.getenv("SENT_MARKER_JSON", "").strip()
    if raw:
        try:
            marker = json.loads(raw)
            if isinstance(marker, dict):
                return marker
        except (json.JSONDecodeError, ValueError):
            print("⚠️ SENT_MARKER_JSON 解析失败，回退本地文件")
    msg_id = os.getenv("RESEND_MSG_ID", "").strip()
    if msg_id:
        return {"resend_msg_id": msg_id}
    marker_path = os.getenv("MARKER_PATH", ".report_sent")
    try:
        raw = open(marker_path, encoding="utf-8").read()
        marker = json.loads(raw)
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    return marker if isinstance(marker, dict) else None


def check_delivery() -> str:
    marker = _load_marker()
    if not marker:
        return "none"

    today = os.getenv("TODAY", "")
    if today and marker.get("date") != today:
        # marker 日期不是今天（不应发生，防御性检查）
        return "none"

    msg_id = marker.get("resend_msg_id", "")
    if not msg_id:
        return "none"

    base = _qstash_base_url()
    token = os.getenv("QSTASH_TOKEN") or os.getenv("WORKBUDDY_QSTASH_TOKEN") or ""
    if not base or not token:
        return "unknown"

    import urllib.request
    import urllib.error

    logs_url = f"{base}/v2/logs?messageId={msg_id}"
    req = urllib.request.Request(
        logs_url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", "replace")
    except Exception as exc:
        print(f"⚠️ QStash logs 查询失败: {exc}")
        # 输出控制台链接供人工排查
        print(f"   控制台: https://console.upstash.com/qstash/logs?messageId={msg_id}")
        return "unknown"

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return "unknown"

    entries = data.get("logs") or data.get("entries") or []
    if not entries:
        return "unknown"

    # 多条日志可能对应不同重试轮次；以最确定性的状态为准
    has_delivered = False
    has_failed = False
    has_retry = False
    for entry in entries:
        state = str(entry.get("state", "")).upper()
        if state == "DELIVERED":
            has_delivered = True
        if state in ("FAILED", "ERROR"):
            has_failed = True
            # 打印 Resend 返回的错误详情（QStash 在 responseBody 中透传）
            resp_body = str(entry.get("responseBody", ""))
            if resp_body:
                print(f"   Resend 错误: {resp_body[:200]}")
        if state in ("RETRY", "ACTIVE"):
            has_retry = True

    if has_delivered:
        return "ok"
    if has_failed:
        return "failed"
    if has_retry:
        return "pending"
    return "unknown"


def main() -> None:
    state = check_delivery()
    labels = {
        "ok": "✅ QStash 邮件投递成功",
        "pending": "⏳ QStash 仍在重试中，等待下次核查",
        "failed": "❌ QStash 投递失败（重试耗尽），需重发",
        "unknown": "⚠️ 投递状态未知（查询失败），偏保守跳过",
        "none": "ℹ️ 无 QStash 消息 ID，跳过投递核查",
    }
    print(labels.get(state, f"状态: {state}"))

    gh_output = os.getenv("GITHUB_OUTPUT")
    if gh_output:
        with open(gh_output, "a", encoding="utf-8") as f:
            f.write(f"delivery={state}\n")
    else:
        print(f"delivery={state}")


if __name__ == "__main__":
    main()
