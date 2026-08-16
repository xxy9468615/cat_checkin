#!/usr/bin/env python3
# cron: 30 10 * * *
# new Env("每日签到统一汇总推送")
"""Run standalone sign-in scripts sequentially and push a daily report (Telegram / SMTP / Resend).

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

  Email (SMTP) 推送，配置齐全时与 Telegram 并行发送：
  MAIL_HOST               SMTP 服务器，如 smtp.qq.com / smtp.gmail.com。
  MAIL_PORT               端口，默认 465（SSL）；587/25 走 STARTTLS。
  MAIL_USER               登录账号（通常是发件邮箱）。
  MAIL_PASS               登录密码 / 授权码。
  MAIL_FROM               发件人地址，默认取 MAIL_USER。
  MAIL_TO                 收件人，多个用逗号/分号/空格分隔，默认取 MAIL_USER。
  MAIL_SSL                true/false，默认 true（端口 465 强制 SSL）。
  MAIL_PORT=587 时自动 STARTTLS。

  Email (Resend API) 推送，配置齐全时与 Telegram / SMTP 并行发送：
  RESEND_API_KEY          Resend API Key（re_ 开头）。
  RESEND_FROM             发件人，如 "cat_checkin <noreply@your-domain>"，
                          需为 Resend 已验证域名；缺省用 onboarding@resend.dev。
  RESEND_TO               收件人，多个用逗号/分号/空格分隔。缺省回退 MAIL_TO。
"""

from __future__ import annotations

import datetime
import email.mime.multipart
import email.mime.text
import html as _html
import os
import re
import smtplib
import subprocess
import sys
import textwrap
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

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


def _last_meaningful_line(text: str) -> str:
    """取输出最后一行非空内容，作为失败任务的错误摘要。"""
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line:
            return line
    return ""


def build_report(results: Iterable[Tuple[bool, Path, str, float]]) -> Tuple[str, str, int]:
    rows = list(results)
    ok_count = sum(1 for ok, *_ in rows if ok)
    fail_count = len(rows) - ok_count
    today_str = datetime.date.today().strftime("%Y-%m-%d")

    if fail_count > 0:
        summary_header = f"📢 每日签到汇总 ({today_str}) [❌ {fail_count}项失败]"
    else:
        summary_header = f"📢 每日签到汇总 ({today_str})"
    stat_line = f"📊 成功 {ok_count} | 失败 {fail_count} | 共 {len(rows)}"

    lines = [summary_header, stat_line, ""]
    for ok, path, output, elapsed in rows:
        status = "✅" if ok else "❌"
        task_title = get_task_title(path)
        # 成功只留一行(站点+耗时), 冗余详情不再进通知;
        # 失败仅附最后一行错误原因, 排障足够又不臃肿。
        lines.append(f"{status} {task_title} ({elapsed:.1f}s)")
        if not ok:
            reason = _last_meaningful_line(output)
            if reason:
                lines.append(f"  {reason}")
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
        elif re.match(r"^[✅❌]\s", line):
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


TEMPLATE_DIR = BASE_DIR / "templates"

DEFAULT_EMAIL_SHELL = (
    '<div style="margin:0;padding:16px;background:#f0f2f5;'
    "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'PingFang SC','Microsoft YaHei',sans-serif;\">"
    '<div style="max-width:680px;margin:0 auto;">'
    '<div style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);border-radius:10px 10px 0 0;padding:24px 24px 18px;">'
    '<div style="font-size:20px;font-weight:700;color:#ffffff;letter-spacing:.3px;">{{SUBJECT}}</div>'
    '<div style="margin-top:8px;font-size:13px;color:#a0aec0;">{{STAT}}</div>'
    '</div>'
    '<div style="background:#fff;border-radius:0 0 10px 10px;padding:20px 20px 8px;">{{CARDS}}</div>'
    '<div style="padding:14px 20px;font-size:12px;color:#9aa4b0;text-align:center;">{{FOOTER}}</div>'
    "</div></div>"
)


def _template(path: Path, fallback: str) -> str:
    """读取模板文件；顶部 HTML 注释会被略过；缺失则回退。"""
    try:
        text = path.read_text(encoding="utf-8")
        return re.sub(r"^\s*<!--.*?-->\s*", "", text, count=1, flags=re.S)
    except Exception:
        return fallback


def _find(pattern: str, text: str, default: str = "") -> str:
    m = re.search(pattern, text, re.S)
    return (m.group(1) if m and m.groups() else (m.group(0) if m else default)).strip()


def _num(text: str, default: int = 0) -> int:
    m = re.search(r"-?\d+(?:\.\d+)?", text)
    try:
        return int(float(m.group())) if m else default
    except Exception:
        return default


def _extract_fields(output: str) -> Dict[str, str]:
    """从签到脚本输出中启发式提取结构化字段。

    支持脚本自行打印「💰 余额 / 积分」、「📅 连续签到 N 天 | 剩余 M 天」、
    「🎁 获得 X」、「今日获得/签到奖励」等；未识别的字段留空。

    基于行的解析，支持多账号输出（[1/2] 或 #1 前缀）。
    不同站点的计量单位（积分、机时、金币、Token余额、PB币、点数等）
    会被识别并聚合到 assets 字段。
    """
    fields: Dict[str, str] = {}
    out = output.strip()

    # --- 剩余天数 / 有效期 ---
    m = re.search(r"(?:剩余天数|剩余|有效期)[^，。\n\d]*?(\d+)\s*天", out)
    if m:
        fields.setdefault("remaining", f"{m.group(1)} 天")

    # --- 连续签到天数 / 累计签到 ---
    m = re.search(r"(?:累计|累计签到|签到累计)[^，。\n\d]*?(\d+)\s*天", out)
    if m:
        fields.setdefault("cumulative", f"{m.group(1)} 天")
    m = re.search(r"(?:连续|连签)[^，。\n\d]*?(\d+)\s*天", out)
    if m:
        fields.setdefault("streak", f"{m.group(1)} 天")

    # --- 资产提取 ---
    # 长标签优先，防止短标签提前截断（如 Token 截断 Token余额）
    asset_labels = [
        "账户余额", "可用余额", "Token余额", "当前积分", "余额", "开发者豆", "PB币",
        "体验币", "金币", "积分", "贝壳贝", "经验", "点数",
        "机时", "流量", "Token", "钻石",
    ]
    assets: list[str] = []
    seen_vals: set[str] = set()

    for line in out.splitlines():
        work = line
        for label in asset_labels:
            lm = re.search(re.escape(label) + r"\s*[:：]\s*(\d+(?:[.,]\d+)?)", work)
            if not lm:
                lm = re.search(re.escape(label) + r"\s+(\d+(?:[.,]\d+)?)", work)
            if lm:
                val = lm.group(1).strip()
                key = f"{label}:{val}"
                if key not in seen_vals:
                    seen_vals.add(key)
                    assets.append(f"{label} {val}")
                # 用空格覆盖已匹配区间，防止短标签复匹配长标签内部
                work = work[: lm.start()] + " " * (lm.end() - lm.start()) + work[lm.end():]

    if assets:
        fields["assets"] = " | ".join(assets)

    # --- 今日获得 / 奖励 ---
    reward_keywords = ["获得", "今日获得", "签到奖励", "新增", "领取", "奖励", "获取"]
    rewards: list[str] = []
    for kw in reward_keywords:
        m = re.search(re.escape(kw) + r"\s*[:：]?\s*([0-9.,]+[^\n，。]*)", out)
        if m:
            val = m.group(1).strip()
            if val and val not in rewards:
                rewards.append(val)
    if rewards:
        fields["reward"] = " | ".join(rewards)

    # --- 兑换进度 / 兑换结果 ---
    m = re.search(r"(?:🎯\s*)?(?:兑换进度|兑换结果|兑换状态)\s*[:：]\s*([^\n]+)", out)
    if not m:
        m = re.search(r"🎁\s*([^\n]+)", out)
    if m:
        val = m.group(1).strip()
        if val and not val.startswith("未开启"):
            fields.setdefault("exchange", val)

    # --- 成功/失败计数 ---
    ok_match = re.findall(r"(?:成功|签到成功|已签到|✅)\s*(\d+)", out)
    fail_match = re.findall(r"(?:失败|失败账号|签到失败|❌)\s*(\d+)", out)
    if ok_match:
        fields.setdefault("summary", f"✅ {ok_match[-1]}")
    if fail_match:
        if "summary" in fields:
            fields["summary"] += f" ❌ {fail_match[-1]}"
        else:
            fields.setdefault("summary", f"❌ {fail_match[-1]}")

    return fields


def _truncate_output(text: str, max_length: int = 1200) -> str:
    """截断输出文本，保留换行符。超长时保留尾部——各脚本的结果摘要与
    报错堆栈都打印在末尾，头部多为过程性日志（如 workbuddy 的轮询心跳）。"""
    text = text.strip()
    if len(text) <= max_length:
        return text
    return "…（前文已截断）\n" + text[-max_length:]


def _build_task_card(ok: bool, path: Path, output: str, elapsed: float) -> str:
    """构造单个任务卡片。"""
    title = get_task_title(path)
    status_color = "#228757" if ok else "#ce2b39"
    status_text = "✅ 成功" if ok else "❌ 失败"
    status_bg = "#e4f5ec" if ok else "#fce8e9"

    fields = _extract_fields(output)

    # 字段徽标
    badges_html = ""
    badge = lambda bg, color, text: (
        f'<span style="display:inline-block;margin:2px 6px 2px 0;padding:2px 8px;'
        f'background:{bg};border-radius:10px;font-size:12px;color:{color};">'
        f'{_html.escape(str(text))}</span>'
    )
    if fields.get("remaining"):
        badges_html += badge("#e0f2fe", "#0369a1", f"剩余 {fields['remaining']}")
    if fields.get("assets"):
        for part in fields["assets"].split(" | "):
            badges_html += badge("#eef2ff", "#3730a3", part)
    if fields.get("streak"):
        badges_html += badge("#e6fefa", "#0d9488", f"连续 {fields['streak']}")
    if fields.get("cumulative"):
        badges_html += badge("#f0fdf4", "#15803d", f"累计 {fields['cumulative']}")
    if fields.get("reward"):
        for part in fields["reward"].split(" | "):
            badges_html += badge("#fce8ff", "#ad1457", f"获得 {part}")
    if fields.get("exchange"):
        badges_html += badge("#f3e8ff", "#6b21a8", fields["exchange"])
    if fields.get("summary"):
        badges_html += badge("#fff7e6", "#b45309", fields["summary"])

    # 截断输出用于卡片正文，保留原始换行符
    body = _truncate_output(output, 1200)
    body_html = _html.escape(body).replace("\n", "<br>")

    return f"""
    <div style="margin:0 0 16px 0;border:1px solid #e3e6ea;border-left:3px solid {status_color};background:#fff;border-radius:6px;overflow:hidden;">
      <div style="padding:12px 16px;background:{status_bg};display:flex;align-items:center;justify-content:space-between;">
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="font-size:14px;font-weight:600;color:#1a1a1a;">{status_text}</span>
          <span style="font-size:14px;font-weight:600;color:#2b2f36;">{ _html.escape(title) }</span>
          <span style="font-size:12px;color:#8a9099;direction:ltr;">{ _html.escape(path.name) }</span>
        </div>
        <span style="font-size:12px;color:#8a9099;">{elapsed:.1f}s</span>
      </div>
      {('<div style="padding:8px 16px;font-size:12px;line-height:1.8;">' + badges_html + '</div>') if badges_html else ''}
      <div style="padding:10px 16px;font-size:12px;line-height:1.6;color:#2b2f36;white-space:pre-wrap;word-break:break-word;">{body_html}</div>
    </div>"""


def build_email_html(results: List[Tuple[bool, Path, str, float]], stat_line: str, title: str) -> str:
    """渲染结构化签到结果为卡片式 HTML。"""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    footer = f"由 cat_checkin 自动生成 · {now}"

    # 按成功/失败排序：失败在前更醒目
    sorted_results = list(results)
    failed = [r for r in sorted_results if not r[0]]
    succeeded = [r for r in sorted_results if r[0]]

    cards_html = ""
    if failed:
        cards_html += '<div style="margin:12px 0 6px 0;font-size:12px;color:#9aa4b0;">--- 失败任务 ---</div>'
        for ok, path, output, elapsed in failed:
            cards_html += _build_task_card(ok, path, output, elapsed)
    if succeeded:
        if failed:
            cards_html += '<div style="margin:12px 0 6px 0;font-size:12px;color:#9aa4b0;">--- 成功任务 ---</div>'
        for ok, path, output, elapsed in succeeded:
            cards_html += _build_task_card(ok, path, output, elapsed)

    tpl = _template(
        TEMPLATE_DIR / "email_report.html",
        DEFAULT_EMAIL_SHELL,
    )
    replacements = {
        "{{SUBJECT}}": _html.escape(title),
        "{{STAT}}": _html.escape(stat_line),
        "{{CARDS}}": cards_html,
        "{{FOOTER}}": _html.escape(footer),
    }
    for key, value in replacements.items():
        tpl = tpl.replace(key, value)
    return tpl


def _split_recipients(raw: str) -> List[str]:
    return [x for x in re.split(r"[,;\s]+", raw.strip()) if x]


def send_email(subject: str, report: str, results: List[Tuple[bool, Path, str, float]]) -> None:
    host = os.getenv("MAIL_HOST", "").strip()
    user = os.getenv("MAIL_USER", "").strip()
    password = os.getenv("MAIL_PASS", "").strip()
    if not host or not user or not password:
        print("未配置 MAIL_HOST + MAIL_USER + MAIL_PASS，跳过邮件推送。")
        return

    sender = os.getenv("MAIL_FROM", "").strip() or user
    recipients = _split_recipients(os.getenv("MAIL_TO", "") or user)
    if not recipients:
        print("未配置有效收件人 MAIL_TO，跳过邮件推送。")
        return

    port = int(os.getenv("MAIL_PORT", "465"))
    use_ssl = bool_env("MAIL_SSL", True) if os.getenv("MAIL_SSL") is not None else (port == 465)

    # subject 首行作为邮件标题、状态行作为副标题
    report_lines = report.split("\n")
    subject_line = next((ln for ln in report_lines if ln.startswith("📢")), subject)
    stat_line = next((ln for ln in report_lines if ln.startswith("📊")), "")

    html_body = build_email_html(results, stat_line, subject_line)

    msg = email.mime.multipart.MIMEMultipart("alternative")
    msg["Subject"] = subject_line or subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.attach(email.mime.text.MIMEText(report, "plain", "utf-8"))
    msg.attach(email.mime.text.MIMEText(html_body, "html", "utf-8"))

    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=60)
        else:
            server = smtplib.SMTP(host, port, timeout=60)
            server.ehlo()
            if port in (587, 25):
                server.starttls()
                server.ehlo()
        with server:
            server.login(user, password)
            server.sendmail(sender, recipients, msg.as_string())
        print(f"✅ 邮件推送完成（{len(recipients)} 位收件人）")
    except Exception as exc:
        print(f"❌ 邮件推送失败: {exc}")


def send_resend(subject: str, report: str, results: List[Tuple[bool, Path, str, float]]) -> None:
    """通过 Resend HTTP API 发送汇总邮件（不依赖 SMTP）。"""
    import json as _json
    import urllib.error

    api_key = os.getenv("RESEND_API_KEY", "").strip()
    if not api_key:
        print("未配置 RESEND_API_KEY，跳过 Resend 推送。")
        return

    sender = os.getenv("RESEND_FROM", "").strip() or "cat_checkin <onboarding@resend.dev>"
    recipients = _split_recipients(os.getenv("RESEND_TO", "") or os.getenv("MAIL_TO", ""))
    if not recipients:
        print("未配置有效收件人 RESEND_TO / MAIL_TO，跳过 Resend 推送。")
        return

    report_lines = report.split("\n")
    subject_line = next((ln for ln in report_lines if ln.startswith("📢")), subject)
    stat_line = next((ln for ln in report_lines if ln.startswith("📊")), "")
    html_body = build_email_html(results, stat_line, subject_line)

    payload = {
        "from": sender,
        "to": recipients,
        "subject": subject_line or subject,
        "html": html_body,
        "text": report,
    }
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=_json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "cat_checkin/1.0 (+https://github.com)",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read().decode("utf-8", "replace")
            mail_id = ""
            try:
                mail_id = _json.loads(body).get("id", "")
            except Exception:
                pass
            print(f"✅ Resend 推送完成（{len(recipients)} 位收件人，id={mail_id}）")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        print(f"❌ Resend 推送失败: HTTP {exc.code} {detail}")
    except Exception as exc:
        print(f"❌ Resend 推送失败: {exc}")


def main() -> None:
    try:
        timeout = int(os.getenv("DAILY_TIMEOUT") or os.getenv("QL_DAILY_TIMEOUT", "180"))
    except ValueError:
        timeout = 180
        print("⚠️ DAILY_TIMEOUT / QL_DAILY_TIMEOUT 格式不正确，已回退为默认值 180 秒。")
    tasks = discover_tasks()
    if not tasks:
        raise SystemExit("未发现可执行签到脚本")

    print(f"发现 {len(tasks)} 个签到脚本，将顺序执行：")
    for task in tasks:
        print(f"- {task.name}")
    print("")

    results = [run_task(task, timeout) for task in tasks]
    title, report, fail_count = build_report(results)
    print("\n========== 每日汇总 ==========")
    print(report)

    # 保存结果 JSON（供 report.yml 统一收集）
    report_file = os.getenv("DAILY_REPORT_FILE", "")
    if report_file:
        import json as _json
        tz = datetime.timezone(datetime.timedelta(hours=8))
        bj_date = datetime.datetime.now(tz).strftime("%Y-%m-%d")
        serialized = [
            {"ok": ok, "script": path.name, "output": output, "elapsed": elapsed, "date": bj_date}
            for ok, path, output, elapsed in results
        ]
        Path(report_file).write_text(
            _json.dumps(serialized, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"📝 签到结果已保存: {report_file}")

    push_enabled = bool_env("DAILY_PUSH", True) if os.getenv("DAILY_PUSH") is not None else bool_env("QL_DAILY_PUSH", True)
    if push_enabled:
        # send_telegram(title, report)  # 已停用 TG
        send_email(title, report, results)
        send_resend(title, report, results)

    if fail_count:
        sys.exit(1)


if __name__ == "__main__":
    main()
