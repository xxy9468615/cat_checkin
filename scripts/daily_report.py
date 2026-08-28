#!/usr/bin/env python3
# cron: 30 10 * * *
# new Env("每日签到统一汇总推送")
"""每日报告函数库：报告文本构建 + HTML 邮件卡片 + SMTP/Resend 双通道发送。

由 unified_report.py（checkin.yml#unified 内联 / #report-fallback 兜底）import 使用；
任务执行与结果落盘由 run_task.py（经 daily_orchestrator 统一调度）完成，本模块不再执行任务。

Environment（邮件通道）：
  SMTP: MAIL_HOST / MAIL_PORT(默认465) / MAIL_USER / MAIL_PASS / MAIL_FROM / MAIL_TO / MAIL_SSL
  Resend: RESEND_API_KEY / RESEND_FROM / RESEND_TO（缺省回退 MAIL_TO）
  send_email 返回 bool；send_resend 返回 Tuple[bool, str]（成功? + msg_id），
  msg_id 为 QStash messageId（持久投递可查）或 Resend email id（直发）。
"""

from __future__ import annotations

import datetime
import email.mime.multipart
import email.mime.text
import html as _html
import json as _json
import os
import re
import smtplib
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

BASE_DIR = Path(__file__).resolve().parent


def bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "y", "on"}


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


def _normalize_status(val: Any) -> str:
    """归一化任务状态为 'ok' | 'fail' | 'pending'。"""
    if isinstance(val, str):
        v = val.lower().strip()
        if v in ("ok", "success", "true"):
            return "ok"
        if v in ("pending", "waiting", "scheduled", "uncollected"):
            return "pending"
        return "fail"
    return "ok" if bool(val) else "fail"


def _last_meaningful_line(text: str) -> str:
    """取失败任务的错误摘要：优先找含错误关键字的行，否则回退到末尾非汇总行。"""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return ""
    error_keywords = ("失败", "Error", "Exception", "失效", "错误", "401", "403", "超时", "无法")
    skip_prefixes = ("成功 ", "失败 ", "签到总结", "========", "--- ", "国内站", "国际站")
    for line in reversed(lines):
        if any(kw in line for kw in error_keywords) and not line.startswith(skip_prefixes):
            return line
    for line in reversed(lines):
        if not line.startswith(skip_prefixes):
            return line
    return lines[-1]


def build_report(results: Iterable[Tuple[Any, Path, str, float]]) -> Tuple[str, str, int]:
    rows: List[Tuple[str, Path, str, float, str]] = []
    for item in results:
        st = _normalize_status(item[0])
        # 第 5 元素为结果 JSON 自带的任务名（同脚本多实例时与脚本 Env 标题不同），可空
        rows.append((st, item[1], item[2], item[3], item[4] if len(item) > 4 else ""))

    ok_count = sum(1 for st, *_ in rows if st == "ok")
    fail_count = sum(1 for st, *_ in rows if st == "fail")
    pending_count = sum(1 for st, *_ in rows if st == "pending")
    total_count = len(rows)
    today_str = datetime.date.today().strftime("%Y-%m-%d")

    if fail_count > 0:
        summary_header = f"📢 每日签到汇总 ({today_str}) [❌ {fail_count}项失败]"
    elif pending_count > 0 and ok_count > 0:
        summary_header = f"📢 每日签到汇总 ({today_str}) [⏳ {pending_count}项待执行]"
    elif pending_count > 0 and ok_count == 0:
        summary_header = f"📢 每日签到汇总 ({today_str}) [⏳ 全部待执行]"
    else:
        summary_header = f"📢 每日签到汇总 ({today_str})"

    if pending_count > 0:
        stat_line = f"📊 成功 {ok_count} | 失败 {fail_count} | 待执行 {pending_count} | 共 {total_count}"
    else:
        stat_line = f"📊 成功 {ok_count} | 失败 {fail_count} | 共 {total_count}"

    lines = [summary_header, stat_line, ""]
    for st, path, output, elapsed, dname in rows:
        task_title = dname or get_task_title(path)
        if st == "ok":
            status_icon = "✅"
            lines.append(f"{status_icon} {task_title} ({elapsed:.1f}s)")
        elif st == "pending":
            status_icon = "⏳"
            lines.append(f"{status_icon} {task_title} (待执行/调度中)")
            if output and output.strip() and output.strip() != "结果未收集到（任务未运行或数据库中未暂存）":
                lines.append(f"  {output.strip()}")
            else:
                lines.append("  任务尚未执行或处于独立调度窗口中")
        else:
            status_icon = "❌"
            lines.append(f"{status_icon} {task_title} ({elapsed:.1f}s)")
            reason = _last_meaningful_line(output)
            if reason:
                lines.append(f"  {reason}")
        lines.append("")
    return summary_header, "\n".join(lines).strip(), fail_count


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
    # 仅匹配多账号汇总「成功 X/Y」(Y>1)，避免「成功N次」内联描述误触发
    ok_match = re.findall(r"成功\s+(\d+)\s*/\s*(\d+)", out)
    fail_match = re.findall(r"失败\s+(\d+)\s*/\s*(\d+)", out)
    if ok_match:
        ok_num, total = ok_match[-1]
        if int(total) > 1:
            fields.setdefault("summary", f"✅ {ok_num}/{total}")
    if fail_match:
        fail_num, total = fail_match[-1]
        if int(total) > 1:
            if "summary" in fields:
                fields["summary"] += f" ❌ {fail_num}/{total}"
            else:
                fields.setdefault("summary", f"❌ {fail_num}/{total}")

    return fields


def _truncate_output(text: str, max_length: int = 1200) -> str:
    """截断输出文本，保留换行符。超长时保留尾部——各脚本的结果摘要与
    报错堆栈都打印在末尾，头部多为过程性日志（如 workbuddy 的轮询心跳）。"""
    text = text.strip()
    if len(text) <= max_length:
        return text
    return "…（前文已截断）\n" + text[-max_length:]


def _sanitize_output(text: str) -> str:
    """清理脚本输出中的 HTML 标签和 Unicode 转义，用于卡片正文渲染前兜底。"""
    text = re.sub(r"<!\[CDATA\[|\]\]>", "", text)
    if "\\u" in text:
        text = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text)
    text = re.sub(r"<img\b[^>]*\balt=[\"']([^\"']*)[\"'][^>]*>", r"\1", text, flags=re.I)
    text = re.sub(r"<[^>]*>", "", text)
    return _html.unescape(text).strip()


def _build_task_card(status: Any, path: Path, output: str, elapsed: float, dname: str = "") -> str:
    """构造单个任务卡片。"""
    title = dname or get_task_title(path)
    st = _normalize_status(status)
    if st == "ok":
        status_color = "#228757"
        status_text = "✅ 成功"
        status_bg = "#e4f5ec"
    elif st == "pending":
        status_color = "#64748b"
        status_text = "⏳ 待执行"
        status_bg = "#f1f5f9"
    else:
        status_color = "#ce2b39"
        status_text = "❌ 失败"
        status_bg = "#fce8e9"

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

    # 截断 + 兜底清洗后渲染卡片正文，保留原始换行符
    body = _sanitize_output(_truncate_output(output, 1200))
    if not body and st == "pending":
        body = "任务尚未执行或处于独立调度窗口中"
    body_html = _html.escape(body).replace("\n", "<br>")

    elapsed_str = f"{elapsed:.1f}s" if st != "pending" else "调度中"

    return f"""
    <div style="margin:0 0 16px 0;border:1px solid #e3e6ea;border-left:3px solid {status_color};background:#fff;border-radius:6px;overflow:hidden;">
      <div style="padding:12px 16px;background:{status_bg};display:flex;align-items:center;justify-content:space-between;">
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="font-size:14px;font-weight:600;color:#1a1a1a;">{status_text}</span>
          <span style="font-size:14px;font-weight:600;color:#2b2f36;">{ _html.escape(title) }</span>
          <span style="font-size:12px;color:#8a9099;direction:ltr;">{ _html.escape(path.name) }</span>
        </div>
        <span style="font-size:12px;color:#8a9099;">{elapsed_str}</span>
      </div>
      {('<div style="padding:8px 16px;font-size:12px;line-height:1.8;">' + badges_html + '</div>') if badges_html else ''}
      <div style="padding:10px 16px;font-size:12px;line-height:1.6;color:#2b2f36;white-space:pre-wrap;word-break:break-word;">{body_html}</div>
    </div>"""


def build_email_html(results: List[Tuple[Any, Path, str, float]], stat_line: str, title: str) -> str:
    """渲染结构化签到结果为卡片式 HTML。"""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    footer = f"由 cat_checkin 自动生成 · {now}"

    # 按 失败 -> 待执行 -> 成功 排序
    rows: List[Tuple[str, Path, str, float, str]] = []
    for item in results:
        st = _normalize_status(item[0])
        rows.append((st, item[1], item[2], item[3], item[4] if len(item) > 4 else ""))

    failed = [r for r in rows if r[0] == "fail"]
    pending = [r for r in rows if r[0] == "pending"]
    succeeded = [r for r in rows if r[0] == "ok"]

    # 今日概览小结（全局统计块，置于所有任务卡片之前）
    today = datetime.date.today()
    overview_html = _build_overview_html(rows, (today - datetime.timedelta(days=1)).strftime("%Y-%m-%d"))

    cards_html = overview_html
    if failed:
        cards_html += '<div style="margin:12px 0 6px 0;font-size:12px;color:#ce2b39;font-weight:600;">⚠️ 失败任务</div>'
        for st, path, output, elapsed, dname in failed:
            cards_html += _build_task_card(st, path, output, elapsed, dname)
    if pending:
        cards_html += '<div style="margin:12px 0 6px 0;font-size:12px;color:#64748b;font-weight:600;">⏳ 待执行 / 独立调度任务</div>'
        for st, path, output, elapsed, dname in pending:
            cards_html += _build_task_card(st, path, output, elapsed, dname)
    if succeeded:
        cards_html += '<div style="margin:12px 0 6px 0;font-size:12px;color:#228757;font-weight:600;">✅ 成功任务</div>'
        for st, path, output, elapsed, dname in succeeded:
            cards_html += _build_task_card(st, path, output, elapsed, dname)

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


# === 今日概览小结（2026-08-29 邮件日报增强：全局统计块，逐任务卡片之上） ===

_REWARD_UNIT_DENY = {"天", "次", "个"}
_REWARD_UNIT_MULT = {"K": 1e3, "M": 1e6, "B": 1e9}


def _fmt_num(v: float) -> str:
    if abs(v - round(v)) < 0.01:
        return f"{int(round(v)):,}"
    return f"{v:,.1f}"


def _parse_asset_pairs(assets: str) -> Dict[str, float]:
    """"积分 2,430 | 魔粒 240" → {"积分": 2430, "魔粒": 240}（best-effort）。"""
    pairs: Dict[str, float] = {}
    for part in (assets or "").split(" | "):
        m = re.match(r"\s*(\S+)\s+([\d,]+(?:\.\d+)?)\s*$", part.strip())
        if m:
            try:
                pairs[m.group(1)] = float(m.group(2).replace(",", ""))
            except ValueError:
                pass
    return pairs


def _streak_days(text: str) -> int:
    m = re.search(r"(\d+)\s*天", text or "")
    return int(m.group(1)) if m else 0


def _collect_overview(rows: List[Tuple[str, Path, str, float, str]], yesterday: str) -> Dict[str, Any]:
    """聚合全局小结：🎁 今日获得(按单位) / 💰 资产变化(vs 昨日归档) / 🔥 连签最高 / ⚠️ 连签将断。

    全部 best-effort：昨日归档缺失/Redis 不可用/字段提取不到时对应项为空，不影响邮件。
    """
    gains: Dict[str, float] = {}
    changes: List[str] = []
    max_streak = ("", 0)
    at_risk: List[str] = []

    y_sites: Dict[str, Any] = {}
    prefix = (os.getenv("CAT_CHECKIN_REDIS_PREFIX") or "cat_checkin:").rstrip(":")
    try:
        from common import upstash_redis_command
        ok, res = upstash_redis_command(["GET", f"{prefix}:daily:{yesterday}"])
        if ok and isinstance(res, dict) and res.get("result"):
            archive = _json.loads(res["result"]) if isinstance(res["result"], str) else res["result"]
            y_sites = archive.get("sites") or {}
    except Exception:
        y_sites = {}

    for st, path, output, _elapsed, dname in rows:
        fields = _extract_fields(output or "")
        task_id = path.stem  # u1s1.py → u1s1（与归档 site_key 命名一致）
        title = dname or get_task_title(path)

        if st == "ok":
            # 今日获得按单位聚合（M/K 简写换算数值；跨单位不求和）
            for part in (fields.get("reward") or "").split(" | "):
                part = part.strip()
                if not part:
                    continue
                val, unit = None, ""
                m = re.search(r"\(([\d.,]+)\s*([KMB]?)\)\s*(\S+)", part)
                if m:
                    unit = m.group(3)
                    try:
                        val = float(m.group(1).replace(",", "")) * _REWARD_UNIT_MULT.get(m.group(2).upper(), 1.0)
                    except ValueError:
                        pass
                else:
                    m2 = re.match(r"([\d,]+(?:\.\d+)?)\s*(\S+)\s*$", part)
                    if m2:
                        unit = m2.group(2).strip("()（）")
                        try:
                            val = float(m2.group(1).replace(",", ""))
                        except ValueError:
                            pass
                if val is not None and unit and unit not in _REWARD_UNIT_DENY:
                    gains[unit] = gains.get(unit, 0.0) + val

            sd = _streak_days(fields.get("streak") or "")
            if sd > max_streak[1]:
                max_streak = (title, sd)

            # 资产变化：与昨日归档同站同标签对比
            t_pairs = _parse_asset_pairs(fields.get("assets") or "")
            y_pairs = _parse_asset_pairs(str((y_sites.get(task_id) or {}).get("assets") or ""))
            diffs = [
                f"{label}{'+' if tv - y_pairs[label] > 0 else ''}{_fmt_num(tv - y_pairs[label])}"
                for label, tv in t_pairs.items()
                if label in y_pairs and abs(tv - y_pairs[label]) >= 0.01
            ]
            if diffs:
                changes.append(f"{title} {' '.join(diffs[:3])}")

        elif st == "fail":
            # 连签将断：昨天还成功、今天失败的脚本（读通知状态 last_ok_date）。
            # pending/调度中不算——latvi 等窗口型任务未到点是正常现象，避免误报。
            # 状态键是 orchestrator 任务 id：经 task_registry 反查（workbuddy.py 有
            # 多个账号实例 state），查不到再回退脚本 stem。
            try:
                from common import load_kv_state
                from task_registry import TASKS as _REG
                state_ids = [k for k, t in _REG.items() if t.get("script") == path.name] or [path.stem]
                for state_id in state_ids:
                    state = load_kv_state(f"{prefix}:state:notify:{state_id}", f".notify_state_{state_id}.json")
                    if str(state.get("last_ok_date") or "") == yesterday:
                        at_risk.append(title)
                        break
            except Exception:
                pass

    return {"gains": gains, "changes": changes[:4], "max_streak": max_streak, "at_risk": at_risk[:4]}


def _build_overview_html(rows: List[Tuple[str, Path, str, float, str]], yesterday: str) -> str:
    """今日概览卡片 HTML（置于逐任务卡片之上）；无任何数据时返回空串。"""
    data = _collect_overview(rows, yesterday)
    gains = data["gains"]
    changes = data["changes"]
    max_streak = data["max_streak"]
    at_risk = data["at_risk"]
    if not (gains or changes or max_streak[1] or at_risk):
        return ""

    def badge(bg: str, color: str, text: str) -> str:
        return (
            f'<span style="display:inline-block;margin:2px 6px 2px 0;padding:2px 8px;'
            f'background:{bg};border-radius:10px;font-size:12px;color:{color};">'
            f'{_html.escape(text)}</span>'
        )

    chips = ""
    if gains:
        def gfmt(v: float) -> str:
            return f"{v / 1e6:.2f}M" if v >= 1e6 else _fmt_num(v)
        chips += "".join(badge("#fce8ff", "#ad1457", f"获得 +{gfmt(v)} {unit}") for unit, v in gains.items())
    if changes:
        chips += "".join(badge("#eef2ff", "#3730a3", f"变化 {c}") for c in changes)
    if max_streak[1]:
        chips += badge("#e6fefa", "#0d9488", f"连签最高 {max_streak[0]} {max_streak[1]} 天")
    if at_risk:
        chips += badge("#fff7e6", "#b45309", f"连签将断 {'、'.join(at_risk)}")

    return (
        '<div style="margin:0 0 16px 0;border:1px solid #e3e6ea;border-left:3px solid #4f46e5;'
        'background:#fff;border-radius:6px;overflow:hidden;">'
        '<div style="padding:10px 16px;background:#eef2ff;font-size:13px;font-weight:600;color:#3730a3;">'
        '📌 今日概览</div>'
        f'<div style="padding:8px 16px;font-size:12px;line-height:1.9;">{chips}</div>'
        '</div>'
    )


def send_email(subject: str, report: str, results: List[Tuple[bool, Path, str, float]]) -> bool:
    """SMTP 邮件推送。返回是否真正发送成功（未配置/无收件人/异常均为 False）。"""
    host = os.getenv("MAIL_HOST", "").strip()
    user = os.getenv("MAIL_USER", "").strip()
    password = os.getenv("MAIL_PASS", "").strip()
    if not host or not user or not password:
        print("未配置 MAIL_HOST + MAIL_USER + MAIL_PASS，跳过邮件推送。")
        return False

    sender = os.getenv("MAIL_FROM", "").strip() or user
    recipients = _split_recipients(os.getenv("MAIL_TO", "") or user)
    if not recipients:
        print("未配置有效收件人 MAIL_TO，跳过邮件推送。")
        return False

    try:
        port = int(os.getenv("MAIL_PORT") or "465")
    except ValueError:
        port = 465
        print("⚠️ MAIL_PORT 格式不正确，已回退为默认端口 465。")
    # MAIL_SSL 未设置（或被 workflow 注入为空串）时按端口推断
    mail_ssl = (os.getenv("MAIL_SSL") or "").strip()
    use_ssl = bool_env("MAIL_SSL", True) if mail_ssl else (port == 465)

    try:
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
        return True
    except Exception as exc:
        print(f"❌ 邮件推送失败: {exc}")
        return False


def send_resend(subject: str, report: str, results: List[Tuple[bool, Path, str, float]]) -> Tuple[bool, str]:
    """通过 Resend HTTP API 发送汇总邮件。

    返回 (成功?, msg_id)。
    - QStash 主路径（配置了 QSTASH_URL + QSTASH_TOKEN 且 payload ≤ 900KB）：
      通过 QStash 持久投递，msg_id 为 QStash messageId（可经 /v2/logs 核查状态）。
    - 直发回退（未配置 QStash / payload 超限 / QStash publish 失败）：
      用 common.Http 直发 Resend（自动获得 @retry），msg_id 为 Resend email id。
    - 未配置 RESEND_API_KEY 或无收件人：返回 (False, "")。
    """
    import common as _common

    api_key = os.getenv("RESEND_API_KEY", "").strip()
    if not api_key:
        print("未配置 RESEND_API_KEY，跳过 Resend 推送。")
        return False, ""

    sender = os.getenv("RESEND_FROM", "").strip() or "cat_checkin <onboarding@resend.dev>"
    recipients = _split_recipients(os.getenv("RESEND_TO", "") or os.getenv("MAIL_TO", ""))
    if not recipients:
        print("未配置有效收件人 RESEND_TO / MAIL_TO，跳过 Resend 推送。")
        return False, ""

    report_lines = report.split("\n")
    subject_line = next((ln for ln in report_lines if ln.startswith("📢")), subject)
    stat_line = next((ln for ln in report_lines if ln.startswith("📊")), "")
    try:
        html_body = build_email_html(results, stat_line, subject_line)
    except Exception as exc:
        print(f"❌ Resend 推送失败（HTML 模板渲染异常）: {exc}")
        return False, ""

    payload = {
        "from": sender,
        "to": recipients,
        "subject": subject_line or subject,
        "html": html_body,
        "text": report,
    }
    body_str = _json.dumps(payload, ensure_ascii=False)

    # --- QStash 主路径 ---
    qstash_url = os.getenv("QSTASH_URL") or os.getenv("WORKBUDDY_QSTASH_URL")
    qstash_token = os.getenv("QSTASH_TOKEN") or os.getenv("WORKBUDDY_QSTASH_TOKEN")
    if qstash_url and qstash_token and len(body_str.encode("utf-8")) <= 900 * 1024:
        ok, msg_id = _common.qstash_publish(
            "https://api.resend.com/emails",
            body_str,
            forward_headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            retries=2,
            content_dedup=True,
        )
        if ok:
            print(f"✅ Resend 推送已入队 QStash（{len(recipients)} 位收件人，msg_id={msg_id}）")
            return True, msg_id
        print(f"⚠️ QStash publish 失败（{msg_id}），回退直发 Resend")

    # --- 直发回退（common.Http 自动获得 @retry） ---
    resp = _common.Http().request(
        "POST",
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        data=body_str.encode("utf-8"),
    )
    if 200 <= resp.code < 300:
        mail_id = ""
        try:
            mail_id = str(resp.json().get("id", "") or "")
        except Exception:
            pass
        print(f"✅ Resend 推送完成（{len(recipients)} 位收件人，id={mail_id}）")
        return True, mail_id
    detail = resp.text[:200] if resp.text else ""
    print(f"❌ Resend 推送失败: HTTP {resp.code}{' ' + detail if detail else ''}")
    return False, ""

