#!/usr/bin/env python3
# cron: 0 0 * * 0
# new Env("签到统计与周期分析")
"""签到统计与周期分析工具：支持周报、月报、近N天及自定义时段的统计查询与推送。

数据源：
  Upstash Redis 中归档的每日签到结果 (cat_checkin:daily:YYYY-MM-DD)。

特性：
  1. 周期灵活：--period week|last_week|month|last_month|7days|30days 或 --start/--end 自定义时段
  2. 额度统计：展示周期起始额度、截止额度、以及净新增额度（积分、机时、余额、Token等）
  3. 输出丰富：CLI 表格、GitHub Actions Markdown Summary、HTML 卡片、结构化 JSON
  4. 按需推送：支持 --push 通过 Resend / SMTP 推送统计邮件
  5. 健壮容错：Redis 免驱动批量 Pipeline，自动处理缺卡/断签/数据缺失

使用示例：
  python3 scripts/stats.py --period week                # 查询本周统计（CLI 输出）
  python3 scripts/stats.py --period last_week --push   # 查询上周并推送邮件
  python3 scripts/stats.py --period month              # 查询本月统计
  python3 scripts/stats.py --days 14                   # 查询近 14 天
  python3 scripts/stats.py --start 2026-08-10 --end 2026-08-13  # 自定义时段与额度增量
  python3 scripts/stats.py --period week --json        # 结构化 JSON 输出
"""
from __future__ import annotations

import argparse
import calendar
import datetime as dt
import html as _html
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from common import upstash_redis_command, upstash_redis_pipeline  # noqa: E402
from daily_report import get_task_title, send_email, send_resend  # noqa: E402
from task_registry import get_expected_results  # noqa: E402

# 期望任务清单：从统一 task_registry 读取
EXPECTED_RESULTS: Dict[str, str] = get_expected_results()

TEMPLATES_DIR = BASE_DIR / "templates"
EMAIL_STATS_TEMPLATE_PATH = TEMPLATES_DIR / "email_stats.html"

BEIJING_TZ = dt.timezone(dt.timedelta(hours=8))


def get_beijing_today() -> dt.date:
    """获取当前北京时间日期。"""
    return dt.datetime.now(BEIJING_TZ).date()


def fetch_cached_stats(cache_name: str) -> Optional[dict]:
    """从 Upstash Redis 获取预计算好的统计视图（秒级响应）。"""
    prefix = os.getenv("CAT_CHECKIN_REDIS_PREFIX", "cat_checkin:").rstrip(":")
    ok, res = upstash_redis_command(["GET", f"{prefix}:stats:{cache_name}"])
    if ok and res:
        try:
            return json.loads(res) if isinstance(res, str) else res
        except Exception:
            return None
    return None


def resolve_date_range(
    period: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    days: Optional[int] = None,
) -> Tuple[List[str], str]:
    """解析并生成目标日期字符串列表（升序 YYYY-MM-DD）及周期描述。"""
    today = get_beijing_today()

    if start_date and end_date:
        d_start = dt.date.fromisoformat(start_date)
        d_end = dt.date.fromisoformat(end_date)
        if d_start > d_end:
            d_start, d_end = d_end, d_start
        desc = f"自定义时段 ({d_start} ~ {d_end})"
    elif days and days > 0:
        d_start = today - dt.timedelta(days=days - 1)
        d_end = today
        desc = f"近 {days} 天 ({d_start} ~ {d_end})"
    elif period == "last_week":
        weekday = today.weekday()  # 0=Monday, 6=Sunday
        last_sunday = today - dt.timedelta(days=weekday + 1)
        d_start = last_sunday - dt.timedelta(days=6)
        d_end = last_sunday
        desc = f"上周 ({d_start} ~ {d_end})"
    elif period == "week":
        weekday = today.weekday()
        d_start = today - dt.timedelta(days=weekday)
        d_end = today
        desc = f"本周 ({d_start} ~ {d_end})"
    elif period == "last_month":
        first_of_this_month = today.replace(day=1)
        last_day_of_prev_month = first_of_this_month - dt.timedelta(days=1)
        d_start = last_day_of_prev_month.replace(day=1)
        d_end = last_day_of_prev_month
        desc = f"上月 ({d_start} ~ {d_end})"
    elif period == "month":
        d_start = today.replace(day=1)
        d_end = today
        desc = f"本月 ({d_start} ~ {d_end})"
    elif period == "30days":
        d_start = today - dt.timedelta(days=29)
        d_end = today
        desc = f"近 30 天 ({d_start} ~ {d_end})"
    elif period == "7days":
        d_start = today - dt.timedelta(days=6)
        d_end = today
        desc = f"近 7 天 ({d_start} ~ {d_end})"
    else:
        d_start = today - dt.timedelta(days=6)
        d_end = today
        desc = f"近 7 天 ({d_start} ~ {d_end})"

    dates: List[str] = []
    curr = d_start
    while curr <= d_end:
        dates.append(curr.strftime("%Y-%m-%d"))
        curr += dt.timedelta(days=1)

    return dates, desc


def fetch_records_from_redis(dates: List[str]) -> Dict[str, Optional[dict]]:
    """从 Upstash Redis 批量获取目标日期的每日归档记录。

    返回字典: { 'YYYY-MM-DD': dict_or_None }
    """
    prefix = os.getenv("CAT_CHECKIN_REDIS_PREFIX", "cat_checkin:").rstrip(":")
    commands = [["GET", f"{prefix}:daily:{d}"] for d in dates]

    ok, res = upstash_redis_pipeline(commands)
    records: Dict[str, Optional[dict]] = {d: None for d in dates}

    if not ok or not isinstance(res, list):
        print(f"⚠️ Redis 归档查询异常: {res}", file=sys.stderr)
        return records

    for d, raw in zip(dates, res):
        if not raw:
            continue
        try:
            val = raw.get("result") if isinstance(raw, dict) and "result" in raw else raw
            if not val:
                continue
            if isinstance(val, str):
                records[d] = json.loads(val)
            elif isinstance(val, dict):
                records[d] = val
        except Exception as e:
            print(f"⚠️ 解析 {d} 归档数据失败: {e}", file=sys.stderr)

    return records


def get_site_display_name(site_key: str) -> str:
    """获取站点友好的中文显示名称。"""
    script_name = EXPECTED_RESULTS.get(site_key) or EXPECTED_RESULTS.get(f"{site_key}.json")
    account_suffix = ""
    if "-account-" in site_key:
        acc_part = site_key.split("-account-")[-1].replace(".json", "")
        account_suffix = f" (账号{acc_part})"

    if not script_name:
        if site_key.endswith(".py"):
            script_name = site_key
        else:
            script_name = f"{site_key}.py"

    script_path = BASE_DIR / script_name
    if script_path.exists():
        return get_task_title(script_path) + account_suffix
    return site_key + account_suffix


def _parse_asset_items(assets_str: str) -> Dict[str, Tuple[float, str]]:
    """解析 '当前积分 1200 | 账户余额 5.20' -> {'当前积分': (1200.0, '1200'), ...}"""
    res: Dict[str, Tuple[float, str]] = {}
    if not assets_str:
        return res
    for part in assets_str.split(" | "):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"^(.+?)\s+([0-9.,]+(?:\s*[a-zA-Z$￥¥%]+)?)$", part)
        if m:
            label, raw_val = m.group(1).strip(), m.group(2).strip()
            num_m = re.search(r"[-+]?[0-9]+(?:,[0-9]{3})*(?:\.[0-9]+)?", raw_val)
            if num_m:
                try:
                    val_num = float(num_m.group(0).replace(",", ""))
                    res[label] = (val_num, raw_val)
                except ValueError:
                    pass
    return res


def aggregate_stats(records: Dict[str, Optional[dict]], dates: List[str], period_desc: str) -> dict:
    """聚合分析多周期签到数据与站点额度增量。"""
    total_days = len(dates)
    active_days = sum(1 for d in dates if records[d] is not None)

    # 收集已知站点列表（优先 EXPECTED_RESULTS 的 key 统一转换）
    known_sites: set[str] = set()
    for exp_k in EXPECTED_RESULTS.keys():
        clean_k = exp_k[:-5] if exp_k.endswith(".json") else exp_k
        known_sites.add(clean_k)

    for rec in records.values():
        if rec and "sites" in rec and isinstance(rec["sites"], dict):
            for sk in rec["sites"].keys():
                clean_k = sk[:-5] if sk.endswith(".json") else sk
                known_sites.add(clean_k)

    sorted_sites = sorted(known_sites)

    # 统计每个站点在各日期的状态与资产
    site_stats: Dict[str, dict] = {}
    for s in sorted_sites:
        site_stats[s] = {
            "name": get_site_display_name(s),
            "key": s,
            "total_runs": 0,
            "success_runs": 0,
            "failed_runs": 0,
            "success_rate": 0.0,
            "history": [],  # list of {"date": d, "status": "ok"|"fail"|"missing", "elapsed": float, "assets": str}
            "failed_dates": [],
            "streak": 0,
            "avg_elapsed": 0.0,
            "start_quota": "-",
            "end_quota": "-",
            "delta_quota": "-",
            "start_date": "",
            "end_date": "",
            "quota_items": [],
        }

    total_executions = 0
    total_successes = 0
    total_failures = 0
    daily_summaries: List[dict] = []

    for d in dates:
        rec = records[d]
        d_summary = {
            "date": d,
            "has_data": rec is not None,
            "total": 0,
            "success": 0,
            "failed": 0,
            "pending": 0,
            "rate": 0.0,
        }
        if rec:
            d_sites = rec.get("sites", {})
            d_total = rec.get("total", len(d_sites))
            d_succ = rec.get("success", sum(1 for v in d_sites.values() if (v.get("ok") or v.get("status") == "ok") and not v.get("is_pending") and v.get("status") != "pending"))
            d_pend = rec.get("pending", sum(1 for v in d_sites.values() if v.get("is_pending") or v.get("status") == "pending"))
            d_fail = rec.get("failed", sum(1 for v in d_sites.values() if not v.get("ok") and not v.get("is_pending") and v.get("status") != "pending"))
            d_executed = d_succ + d_fail
            d_summary["total"] = d_total
            d_summary["success"] = d_succ
            d_summary["failed"] = d_fail
            d_summary["pending"] = d_pend
            d_summary["rate"] = round((d_succ / d_executed * 100) if d_executed > 0 else 0.0, 1)

            total_executions += d_executed
            total_successes += d_succ
            total_failures += d_fail

            for s in sorted_sites:
                st = site_stats[s]
                s_data = d_sites.get(s) or d_sites.get(f"{s}.json")
                if s_data:
                    is_pending = bool(s_data.get("is_pending")) or s_data.get("status") == "pending"
                    is_ok = (bool(s_data.get("ok")) or s_data.get("status") == "ok") and not is_pending
                    elapsed = float(s_data.get("elapsed") or 0.0)
                    assets_str = str(s_data.get("assets") or "")
                    if is_pending:
                        st["history"].append({"date": d, "status": "pending", "elapsed": 0.0, "assets": assets_str})
                    elif is_ok:
                        st["total_runs"] += 1
                        st["success_runs"] += 1
                        st["history"].append({"date": d, "status": "ok", "elapsed": elapsed, "assets": assets_str})
                    else:
                        st["total_runs"] += 1
                        st["failed_runs"] += 1
                        st["failed_dates"].append(d)
                        st["history"].append({"date": d, "status": "fail", "elapsed": elapsed, "assets": assets_str})
                else:
                    st["history"].append({"date": d, "status": "missing", "elapsed": 0.0, "assets": ""})
        else:
            for s in sorted_sites:
                site_stats[s]["history"].append({"date": d, "status": "missing", "elapsed": 0.0, "assets": ""})

        daily_summaries.append(d_summary)

    # 计算各站点综合指标与额度变化
    for s, st in site_stats.items():
        if st["total_runs"] > 0:
            st["success_rate"] = round((st["success_runs"] / st["total_runs"]) * 100, 1)
            total_el = sum(h["elapsed"] for h in st["history"] if h["status"] != "missing")
            st["avg_elapsed"] = round(total_el / st["total_runs"], 1)
        else:
            st["success_rate"] = 0.0
            st["avg_elapsed"] = 0.0

        # 计算连胜天数 (Streak)
        streak = 0
        for h in reversed(st["history"]):
            if h["status"] == "ok":
                streak += 1
            elif h["status"] == "fail":
                break
        st["streak"] = streak

        # 计算起始额度、截止额度与净增量
        valid_assets = [(h["date"], h["assets"]) for h in st["history"] if h.get("assets")]
        if valid_assets:
            s_date, s_assets_str = valid_assets[0]
            e_date, e_assets_str = valid_assets[-1]
            s_dict = _parse_asset_items(s_assets_str)
            e_dict = _parse_asset_items(e_assets_str)

            st["start_date"] = s_date
            st["end_date"] = e_date

            start_strs = []
            end_strs = []
            delta_strs = []
            quota_items = []

            all_labels: List[str] = []
            for lbl in list(s_dict.keys()) + list(e_dict.keys()):
                if lbl not in all_labels:
                    all_labels.append(lbl)

            for lbl in all_labels:
                s_tuple = s_dict.get(lbl)
                e_tuple = e_dict.get(lbl)

                s_val = s_tuple[0] if s_tuple else None
                s_raw = s_tuple[1] if s_tuple else "-"
                e_val = e_tuple[0] if e_tuple else None
                e_raw = e_tuple[1] if e_tuple else "-"

                start_strs.append(f"{lbl} {s_raw}")
                end_strs.append(f"{lbl} {e_raw}")

                if s_val is not None and e_val is not None:
                    diff = e_val - s_val
                    if diff.is_integer():
                        diff_str = f"{int(diff):+d}"
                    else:
                        diff_str = f"{diff:+.2f}"
                    delta_strs.append(f"{lbl} {diff_str}")
                    quota_items.append({
                        "label": lbl,
                        "start": s_val,
                        "end": e_val,
                        "delta": diff,
                        "delta_str": diff_str,
                    })
                else:
                    delta_strs.append(f"{lbl} -")

            st["start_quota"] = " | ".join(start_strs) if start_strs else "-"
            st["end_quota"] = " | ".join(end_strs) if end_strs else "-"
            st["delta_quota"] = " | ".join(delta_strs) if delta_strs else "-"
            st["quota_items"] = quota_items

    # 排序与分类
    ranked_sites = sorted(
        site_stats.values(),
        key=lambda x: (x["success_rate"], x["success_runs"], -x["failed_runs"]),
        reverse=True,
    )

    perfect_sites = [s for s in ranked_sites if s["total_runs"] > 0 and s["failed_runs"] == 0]
    unstable_sites = [s for s in ranked_sites if s["failed_runs"] > 0]
    missing_sites = [s for s in ranked_sites if s["total_runs"] == 0]

    overall_rate = round((total_successes / total_executions * 100) if total_executions > 0 else 0.0, 1)

    return {
        "period_desc": period_desc,
        "dates": dates,
        "total_days": total_days,
        "active_days": active_days,
        "total_executions": total_executions,
        "total_successes": total_successes,
        "total_failures": total_failures,
        "overall_success_rate": overall_rate,
        "sites": ranked_sites,
        "perfect_sites_count": len(perfect_sites),
        "unstable_sites_count": len(unstable_sites),
        "missing_sites_count": len(missing_sites),
        "daily_summaries": daily_summaries,
    }


def render_cli(stats: dict) -> str:
    """渲染终端彩色/字符报表（包含起止额度与增量展示）。"""
    lines: List[str] = []
    lines.append("=" * 96)
    lines.append(f"📊 签到周期统计分析报告 ({stats['period_desc']})")
    lines.append("=" * 96)
    lines.append(
        f"📅 统计周期: {stats['dates'][0]} 至 {stats['dates'][-1]} (共 {stats['total_days']} 天，有记录 {stats['active_days']} 天)"
    )
    lines.append(
        f"📈 整体成功率: {stats['overall_success_rate']}% | "
        f"总运行: {stats['total_executions']} 次 | "
        f"✅ 成功: {stats['total_successes']} | "
        f"❌ 失败: {stats['total_failures']}"
    )
    lines.append(
        f"🏆 全勤站点: {stats['perfect_sites_count']} 个 | "
        f"⚠️ 异常站点: {stats['unstable_sites_count']} 个 | "
        f"⊘ 未运行: {stats['missing_sites_count']} 个"
    )
    lines.append("-" * 96)
    lines.append(f"{'站点名称':<20} | {'成功率':<7} | {'点阵':<10} | {'起始额度':<16} | {'截止额度':<16} | {'周期新增':<16}")
    lines.append("-" * 96)

    for st in stats["sites"]:
        dots = []
        for h in st["history"]:
            if h["status"] == "ok":
                dots.append("●")
            elif h["status"] == "fail":
                dots.append("○")
            else:
                dots.append("-")
        matrix_str = "".join(dots)
        rate_str = f"{st['success_rate']}%"
        start_q = st["start_quota"] if len(st["start_quota"]) <= 16 else st["start_quota"][:14] + "…"
        end_q = st["end_quota"] if len(st["end_quota"]) <= 16 else st["end_quota"][:14] + "…"
        delta_q = st["delta_quota"] if len(st["delta_quota"]) <= 16 else st["delta_quota"][:14] + "…"

        lines.append(f"{st['name']:<20} | {rate_str:<7} | {matrix_str:<10} | {start_q:<16} | {end_q:<16} | {delta_q:<16}")

    lines.append("=" * 96)
    if stats["unstable_sites_count"] > 0:
        lines.append("⚠️ 异常与失败站点明细：")
        for st in stats["sites"]:
            if st["failed_runs"] > 0:
                fail_days = ", ".join(st["failed_dates"])
                lines.append(f"  • {st['name']}: 失败 {st['failed_runs']} 次 (失败日期: {fail_days})")
        lines.append("-" * 96)

    return "\n".join(lines)


def render_markdown(stats: dict) -> str:
    """渲染 GitHub Actions Summary Markdown（增加额度与净增量列）。"""
    md: List[str] = []
    md.append(f"## 📊 签到周期统计分析报告 ({stats['period_desc']})")
    md.append("")
    md.append(f"> 📅 **统计时段**：`{stats['dates'][0]}` ~ `{stats['dates'][-1]}`（共 {stats['total_days']} 天，有效记录 {stats['active_days']} 天）")
    md.append("")

    # 统计卡片指标表格
    md.append("| 整体成功率 | 总执行次数 | 成功次数 | 失败次数 | 🏆 全勤站点 | ⚠️ 异常站点 |")
    md.append("| :---: | :---: | :---: | :---: | :---: | :---: |")
    md.append(
        f"| **`{stats['overall_success_rate']}%`** | {stats['total_executions']} | "
        f"✅ {stats['total_successes']} | ❌ {stats['total_failures']} | "
        f"{stats['perfect_sites_count']} | {stats['unstable_sites_count']} |"
    )
    md.append("")

    # 站点详细矩阵表
    md.append("### 站点运行矩阵与额度增量")
    md.append("")
    md.append("| 站点 | 成功率 | 历史点阵 | 连胜 | 起始额度 | 截止额度 | 周期净增 | 状态 |")
    md.append("| :--- | :---: | :--- | :---: | :--- | :--- | :--- | :---: |")

    for st in stats["sites"]:
        dots = []
        for h in st["history"]:
            if h["status"] == "ok":
                dots.append("🟢")
            elif h["status"] == "fail":
                dots.append("🔴")
            else:
                dots.append("⚪")
        matrix_str = "".join(dots)

        status_tag = "✅ 稳定" if st["failed_runs"] == 0 and st["total_runs"] > 0 else ("❌ 异常" if st["failed_runs"] > 0 else "⚪ 无数据")
        streak_str = f"{st['streak']}d" if st['streak'] > 0 else "-"

        start_str = f"`{st['start_quota']}`" if st['start_quota'] != "-" else "-"
        end_str = f"`{st['end_quota']}`" if st['end_quota'] != "-" else "-"
        delta_str = f"**`{st['delta_quota']}`**" if st['delta_quota'] != "-" else "-"

        md.append(f"| **{st['name']}** | `{st['success_rate']}%` | {matrix_str} | {streak_str} | {start_str} | {end_str} | {delta_str} | {status_tag} |")

    if stats["unstable_sites_count"] > 0:
        md.append("")
        md.append("### ⚠️ 失败站点与断签分析")
        for st in stats["sites"]:
            if st["failed_runs"] > 0:
                f_dates = ", ".join(f"`{d}`" for d in st["failed_dates"])
                md.append(f"- **{st['name']}**：共失败 {st['failed_runs']} 次，异常日期：{f_dates}")

    return "\n".join(md)


def render_html(stats: dict) -> str:
    """根据模板生成精美的 HTML 统计邮件（包含额度变化与增量高亮）。"""
    template = ""
    if EMAIL_STATS_TEMPLATE_PATH.exists():
        try:
            template = EMAIL_STATS_TEMPLATE_PATH.read_text(encoding="utf-8")
        except Exception:
            pass
    if not template:
        template = (
            "<div style='padding:20px;font-family:sans-serif;'>"
            "<h2>{{SUBJECT}}</h2><p>{{STAT}}</p><div>{{OVERVIEW_CARDS}}</div>"
            "<div>{{SITE_ROWS}}</div><p>{{FOOTER}}</p></div>"
        )

    subject = f"📊 签到周期统计报告 ({stats['period_desc']})"
    stat_line = (
        f"📊 整体成功率 <b>{stats['overall_success_rate']}%</b> · "
        f"总运行 {stats['total_executions']} 次 · "
        f"✅ 成功 {stats['total_successes']} · ❌ 失败 {stats['total_failures']}"
    )

    overview_cards = f"""
    <table style="width:100%;border-collapse:separate;border-spacing:8px 0;margin:0 0 4px;">
      <tr>
        <td style="width:33%;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px;text-align:center;">
          <div style="font-size:11px;color:#64748b;font-weight:500;">整体成功率</div>
          <div style="font-size:22px;font-weight:700;color:{'#16a34a' if stats['overall_success_rate'] >= 90 else '#dc2626'};margin-top:4px;">
            {stats['overall_success_rate']}%
          </div>
        </td>
        <td style="width:33%;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px;text-align:center;">
          <div style="font-size:11px;color:#64748b;font-weight:500;">全勤稳定站点</div>
          <div style="font-size:22px;font-weight:700;color:#16a34a;margin-top:4px;">
            {stats['perfect_sites_count']} <span style="font-size:12px;font-weight:normal;color:#94a3b8;">/ {len(stats['sites'])}</span>
          </div>
        </td>
        <td style="width:33%;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px;text-align:center;">
          <div style="font-size:11px;color:#64748b;font-weight:500;">异常/失败站点</div>
          <div style="font-size:22px;font-weight:700;color:{'#dc2626' if stats['unstable_sites_count'] > 0 else '#64748b'};margin-top:4px;">
            {stats['unstable_sites_count']}
          </div>
        </td>
      </tr>
    </table>
    """

    site_rows: List[str] = []
    for st in stats["sites"]:
        is_perfect = st["failed_runs"] == 0 and st["total_runs"] > 0
        border_color = "#16a34a" if is_perfect else ("#dc2626" if st["failed_runs"] > 0 else "#94a3b8")
        rate_color = "#16a34a" if st["success_rate"] >= 90 else ("#dc2626" if st["success_rate"] < 60 else "#d97706")

        pills = []
        for h in st["history"]:
            if h["status"] == "ok":
                pills.append(f'<span title="{h["date"]}: 成功 ({h["elapsed"]}s)" style="display:inline-block;width:12px;height:12px;border-radius:2px;background:#22c55e;margin-right:3px;"></span>')
            elif h["status"] == "fail":
                pills.append(f'<span title="{h["date"]}: 失败" style="display:inline-block;width:12px;height:12px;border-radius:2px;background:#ef4444;margin-right:3px;"></span>')
            else:
                pills.append(f'<span title="{h["date"]}: 无记录" style="display:inline-block;width:12px;height:12px;border-radius:2px;background:#cbd5e1;margin-right:3px;"></span>')
        matrix_html = "".join(pills)

        fail_info = ""
        if st["failed_runs"] > 0:
            fail_dates_str = ", ".join(st["failed_dates"])
            fail_info = f'<div style="margin-top:6px;font-size:11px;color:#dc2626;background:#fef2f2;padding:4px 8px;border-radius:4px;">⚠️ 失败记录 ({st["failed_runs"]}次): {fail_dates_str}</div>'

        streak_badge = ""
        if st["streak"] >= 3:
            streak_badge = f'<span style="background:#dcfce7;color:#15803d;padding:2px 6px;border-radius:4px;font-size:11px;margin-left:6px;font-weight:600;">🔥 连签 {st["streak"]} 天</span>'

        quota_badge = ""
        if st["delta_quota"] != "-":
            has_positive = any("+" in q for q in st["delta_quota"].split(" | "))
            delta_color = "#16a34a" if has_positive else "#475569"
            quota_badge = f"""
            <div style="margin-top:6px;font-size:11px;color:#475569;background:#f1f5f9;padding:4px 8px;border-radius:4px;display:flex;align-items:center;justify-content:space-between;">
              <span>🪙 额度: <b>{_html.escape(st['start_quota'])}</b> → <b>{_html.escape(st['end_quota'])}</b></span>
              <span style="font-weight:700;color:{delta_color};margin-left:8px;">净增: {_html.escape(st['delta_quota'])}</span>
            </div>
            """

        row_html = f"""
        <div style="border-left:3px solid {border_color};background:#f8fafc;border-radius:0 6px 6px 0;padding:10px 14px;margin-bottom:8px;">
          <div style="display:flex;align-items:center;justify-content:space-between;">
            <div>
              <span style="font-size:13px;font-weight:600;color:#1e293b;">{_html.escape(st['name'])}</span>
              {streak_badge}
            </div>
            <div style="text-align:right;">
              <span style="font-size:13px;font-weight:700;color:{rate_color};">{st['success_rate']}%</span>
              <span style="font-size:11px;color:#64748b;margin-left:4px;">({st['success_runs']}/{st['total_runs']})</span>
            </div>
          </div>
          <div style="margin-top:8px;display:flex;align-items:center;justify-content:space-between;">
            <div style="display:flex;align-items:center;line-height:1;">
              {matrix_html}
            </div>
            <div style="font-size:11px;color:#94a3b8;">
              均耗 {st['avg_elapsed']}s
            </div>
          </div>
          {quota_badge}
          {fail_info}
        </div>
        """
        site_rows.append(row_html)

    now_bj = dt.datetime.now(BEIJING_TZ).strftime("%Y-%m-%d %H:%M:%S")
    footer = f"Generated by cat_checkin Stats Engine · {now_bj} (BJT)"

    html_out = template
    html_out = html_out.replace("{{SUBJECT}}", subject)
    html_out = html_out.replace("{{PERIOD_DESC}}", stats["period_desc"])
    html_out = html_out.replace("{{STAT}}", stat_line)
    html_out = html_out.replace("{{OVERVIEW_CARDS}}", overview_cards)
    html_out = html_out.replace("{{SITE_ROWS}}", "\n".join(site_rows))
    html_out = html_out.replace("{{FOOTER}}", footer)

    return html_out


def push_report_email(subject: str, text_content: str, html_content: str) -> bool:
    """通过 Resend / SMTP 推送统计邮件。"""
    resend_ok = False
    smtp_ok = False

    if os.getenv("RESEND_API_KEY"):
        resend_ok, msg_id = send_resend(subject, text_content, html_content)
        if resend_ok:
            print(f"📧 统计周报/月报已通过 Resend 成功投递 (msg_id: {msg_id})")

    if os.getenv("MAIL_HOST") and os.getenv("MAIL_USER") and os.getenv("MAIL_PASS"):
        smtp_ok = send_email(subject, text_content, html_content)
        if smtp_ok:
            print("📧 统计周报/月报已通过 SMTP 成功投递")

    return resend_ok or smtp_ok


def main() -> None:
    parser = argparse.ArgumentParser(description="cat_checkin 签到多周期统计与查询工具")
    parser.add_argument(
        "--period",
        choices=["week", "last_week", "month", "last_month", "7days", "30days", "custom"],
        default="week",
        help="统计周期类型 (默认: week)",
    )
    parser.add_argument("--days", type=int, help="最近天数 (如 --days 14)")
    parser.add_argument("--start", help="自定义起始日期 YYYY-MM-DD")
    parser.add_argument("--end", help="自定义结束日期 YYYY-MM-DD")
    parser.add_argument("--json", action="store_true", help="输出结构化 JSON")
    parser.add_argument("--markdown", action="store_true", help="输出 GitHub Markdown 格式")
    parser.add_argument("--html", help="导出 HTML 文件路径 (如 --html report.html)")
    parser.add_argument("--push", action="store_true", help="发送邮件通知 (Resend / SMTP)")
    parser.add_argument(
        "--cached",
        action="store_true",
        help="优先尝试从 Redis 读取预计算好的统计视图 (latest_7days / current_month / latest_30days)",
    )

    args = parser.parse_args()

    stats = None
    if args.cached and not args.start and not args.end and not args.days:
        cache_map = {
            "7days": "latest_7days",
            "week": "latest_7days",
            "30days": "latest_30days",
            "month": "current_month",
        }
        cache_name = cache_map.get(args.period)
        if cache_name:
            stats = fetch_cached_stats(cache_name)

    if not stats:
        dates, period_desc = resolve_date_range(
            period=args.period,
            start_date=args.start,
            end_date=args.end,
            days=args.days,
        )
        records = fetch_records_from_redis(dates)
        stats = aggregate_stats(records, dates, period_desc)

    if args.json:
        print(json.dumps(stats, ensure_ascii=False, indent=2))
        return

    if args.markdown:
        md = render_markdown(stats)
        print(md)
        return

    html_content = render_html(stats)
    if args.html:
        Path(args.html).write_text(html_content, encoding="utf-8")
        print(f"💾 统计报告 HTML 已保存至: {args.html}")

    cli_text = render_cli(stats)
    print(cli_text)

    gh_summary = os.getenv("GITHUB_STEP_SUMMARY")
    if gh_summary:
        try:
            with open(gh_summary, "a", encoding="utf-8") as f:
                f.write(render_markdown(stats) + "\n")
        except Exception as e:
            print(f"⚠️ 写入 GITHUB_STEP_SUMMARY 失败: {e}", file=sys.stderr)

    if args.push:
        subject = f"📊 签到周期统计报告 ({period_desc})"
        push_report_email(subject, cli_text, html_content)


if __name__ == "__main__":
    main()
