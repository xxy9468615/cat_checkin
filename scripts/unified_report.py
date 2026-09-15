#!/usr/bin/env python3
# new Env("每日统一通知汇总")
"""统一汇总报告：汇聚当日签到结果，经邮件推送（Discord 仅承担失败即时提醒）。

触发与分工（2026-09-13 日报去重改造）：
- unified job（晨间批次/心跳/重跑）：仅 ARCHIVE_ONLY=1 归档 + 输出 failed_matrix，
  不发邮件；
- report-fallback job：每日 20:00 BJT（cron 0 12 * * *）主发汇总日报，
  21:30 BJT（cron 30 13 * * *）失败补发，manual 经 daily_report dispatch；
  幂等由 Redis sent marker + QStash 投递核查保障；
  定时主力改由 QStash Cron（scripts/setup_report_schedule.py）精确派发，
  GitHub cron 仅兜底——其 schedule 实测可延迟 5~6.7 小时到次日凌晨；
  另受 `_daily_report_window_blocks` 时间窗守卫约束（早于 19:00 BJT 拒发），
  晚到的日报只归档、不发信、不写 marker，既不推错日期数据也不压制当日主发。

优先从 Upstash Redis `cat_checkin:raw:<TODAY>`（HGETALL）汇聚，
兜底扫描 `.task_results/` 本地 JSON；Latvi 若今日无结果则回退昨日（24h 冷却跨日）。

2026-08-29 日报回归邮件通道（HTML 卡片 + 今日概览小结，浏览/归档体验优于 Discord），
Discord 保留频道1 失败即时提醒（discord_notify.notify_task_result）。
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from common import env_bool, upstash_redis_command, upstash_redis_pipeline  # noqa: E402
import alert_levels  # noqa: E402  提示/警告分级（归档 level/warns 字段）
import report_fields  # noqa: E402  按任务定制的字段解析（归档结构化字段）
from daily_report import _extract_fields, build_report, send_email, send_resend  # noqa: E402
from task_registry import TASKS, get_expected_results  # noqa: E402

# Latvi 的结果文件名（24h 间隔约束，18:00 运行，报告取昨日结果）
LATVI_RESULT_FILE = "latvi.json"

# 日报发信时间窗（北京时间）：20:00 主发 + 21:30 失败补发。
# 窗口起点，早于此点一律拒发（见 _daily_report_window_blocks）。
DAILY_REPORT_EARLIEST_HOUR = 19

# 是否允许次日 00:00~05:59 的「迟到兜底」发信。默认 False（严格收敛在
# 19:00~23:59 BJT）：凌晨抢发正是用户反馈的故障现象，且会写下 sent marker
# 压制当日 20:00 主发。仅当 20:00 主发被证实会整批丢失、确需兜底时才改 True。
DAILY_REPORT_ALLOW_LATE = False


def _daily_report_window_blocks(now: dt.datetime, report_fallback: bool) -> bool:
    """判定当前时刻是否禁止发送日报主邮件（北京时间语义，now 须为 BJT aware）。

    背景（2026-09-15 排查）：GitHub Actions 的 schedule 在本仓库严重不准时。
    本应 20:00 BJT 送达的 "0 12 * * *" 日报 cron 屡次延迟约 5~6.7 小时，直到
    次日凌晨 00:59 / 01:16 / 02:44 BJT 才落地。而 TODAY 是在运行时才计算的，
    于是这封「昨天的日报」取到新一天几乎无任务的数据，发出「成功 4、待执行 25」
    的空报告，并写下**新一天**的 sent marker，把当天真正的 20:00 主发幂等秒退
    ——用户看到的就是「每天凌晨推邮件」，且当天再无日报。

    规则（仅约束「主发/补发」通道，report_fallback=True）：
      - 19:00 ~ 23:59 BJT：放行（覆盖 20:00 主发与 21:30 补发）；
      - 其余时刻（含 00:00~18:59）：禁止，只归档、绝不写 sent marker；
      - DAILY_REPORT_ALLOW_LATE=True 时额外放行次日 00:00~05:59。

    非 fallback 通道（重跑补充邮件 / 20:00 前大范围 pending 判定）不受时间窗约束。
    """
    if not report_fallback:
        return False
    hour = now.hour
    if hour >= DAILY_REPORT_EARLIEST_HOUR:
        return False
    if DAILY_REPORT_ALLOW_LATE and hour < 6:
        return False
    return True


# 期望任务清单：从统一 task_registry 读取
EXPECTED_RESULTS: Dict[str, str] = get_expected_results()

# 重跑候选脚本列表（单 run 模式下放宽为全部 daily 任务，均幂等安全）
CHECKIN_MATRIX_SCRIPTS = sorted(
    {t["script"] for t in TASKS.values() if "daily" in t.get("tags", [])}
)


def _load_single_result(path: Path, accepted_dates: Set[str]) -> Optional[dict]:
    """读取并校验单个任务结果 JSON（date 须在 accepted_dates 白名单内）。"""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        date_val = data.get("date")
        # date 缺失/为空同样不放行：历史无日期文件不能冒充今日结果
        if not date_val or date_val not in accepted_dates:
            print(f"⚠️ 跳过过期/无日期数据: {path.name} (日期 {date_val}，要求 {sorted(accepted_dates)})")
            return None
        return data
    except Exception as e:
        print(f"⚠️ 读取 {path.name} 失败: {e}")
        return None


def collect_all_results(today: str, yesterday: str) -> Tuple[List[Tuple[bool, Path, str, float]], Dict[str, dict]]:
    """收集所有任务结果。返回 (build_report 所需元组列表, 原始结果字典 key→data)。

    原始字典供归档使用（key 区分 workbuddy-account-1/2 等同名脚本多账号）。
    """
    collected: Dict[str, dict] = {}

    # === 1. 优先从 Upstash Redis 读取当日原始结果（Hash：field=result_name, value=JSON）===
    url = os.getenv("UPSTASH_REDIS_REST_URL", "")
    token = os.getenv("UPSTASH_REDIS_REST_TOKEN", "")
    if url and token:
        try:
            prefix = os.getenv("CAT_CHECKIN_REDIS_PREFIX", "cat_checkin:").rstrip(":")
            raw_key_today = f"{prefix}:raw:{today}"
            ok, res = upstash_redis_command(["HGETALL", raw_key_today])
            if ok and isinstance(res, dict):
                raw_hash = res.get("result")
                field_map = {}
                if isinstance(raw_hash, dict):
                    field_map = raw_hash
                elif isinstance(raw_hash, list):
                    for i in range(0, len(raw_hash), 2):
                        if i + 1 < len(raw_hash):
                            field_map[str(raw_hash[i])] = raw_hash[i + 1]

                for field, value in field_map.items():
                    try:
                        data = json.loads(value) if isinstance(value, str) else value
                        if isinstance(data, dict):
                            date_val = data.get("date")
                            dates = {today, yesterday} if field == LATVI_RESULT_FILE else {today}
                            if date_val in dates:
                                collected[field] = data
                    except Exception:
                        pass

            # Latvi 24h 间隔约束：若今日 Redis 暂存中没有 latvi.json，尝试读取昨日
            if LATVI_RESULT_FILE not in collected:
                raw_key_yesterday = f"{prefix}:raw:{yesterday}"
                ok2, res2 = upstash_redis_command(["HGET", raw_key_yesterday, LATVI_RESULT_FILE])
                if ok2 and isinstance(res2, dict):
                    lv_val = res2.get("result")
                    if lv_val:
                        try:
                            lv_data = json.loads(lv_val) if isinstance(lv_val, str) else lv_val
                            if isinstance(lv_data, dict) and lv_data.get("date") == yesterday:
                                collected[LATVI_RESULT_FILE] = lv_data
                        except Exception:
                            pass
            if collected:
                print(f"📡 已从 Upstash Redis 汇聚 {len(collected)} 个任务结果")
        except Exception as e:
            print(f"⚠️ 从 Upstash Redis 读取任务结果异常（回退本地扫描）: {e}")

    # === 2. 兜底/本地扫描：.task_results/ 目录（确保本地调试与未配置 Redis 时的可用性）===
    task_results_dir = Path(os.getenv("TASK_OUTPUT_DIR", ".task_results"))
    if task_results_dir.exists() and task_results_dir.is_dir():
        for json_file in sorted(task_results_dir.rglob("*.json")):
            if json_file.name not in collected:
                dates = {today, yesterday} if json_file.name == LATVI_RESULT_FILE else {today}
                res = _load_single_result(json_file, dates)
                if res:
                    collected[json_file.name] = res

    # === 3. 期望清单比对：缺席任务标记为待执行（pending），避免误判为失败红卡 ===
    for missing in sorted(set(EXPECTED_RESULTS) - set(collected)):
        print(f"ℹ️ 期望任务尚未收集 (待执行或独立调度中): {missing}")
        collected[missing] = {
            "ok": False,
            "status": "pending",
            "is_pending": True,
            "script": EXPECTED_RESULTS[missing],
            "output": "任务尚未执行（按计划调度中或数据库中未暂存）",
            "elapsed": 0.0,
        }

    # === 4. 转换为元组并按脚本名排序 (status, path, output, elapsed) ===
    out: List[Tuple[str, Path, str, float]] = []
    for _key, data in sorted(collected.items()):
        is_pending = bool(data.get("is_pending")) or data.get("status") == "pending"
        is_suspended = bool(data.get("circuit_broken")) or data.get("status") == "suspended"
        if is_pending:
            st = "pending"
        elif is_suspended:
            st = "suspended"
        else:
            st = "ok" if bool(data.get("ok")) else "fail"

        # 卡片标题以结果内的 script 字段为准（如 workbuddy.py），而非去重的文件名 key
        script_name = data.get("script") or (_key[:-5] if _key.endswith(".json") else _key)
        path = BASE_DIR / script_name if (BASE_DIR / script_name).exists() else Path(script_name)
        # 字段防御：单个坏结果（elapsed 非数字 / output 为 null）只影响自己，不炸整条链
        try:
            elapsed = float(data.get("elapsed") or 0.0)
        except (TypeError, ValueError):
            elapsed = 0.0
        output = str(data.get("output") or "")
        # 第 5 元素：结果 JSON 自带任务名（同脚本多实例时与脚本 Env 标题不同，
        # 如 ModelScope 国内站/国际站），供邮件卡片标题优先使用
        out.append((st, path, output, elapsed, str(data.get("name") or "")))

    return out, collected


def _emit_failed_sites(collected: Dict[str, dict]) -> List[str]:
    """汇总真实失败站点并写入 GITHUB_OUTPUT（供 checkin.yml 自动重跑 step 使用）。

    输出两个 step output：
    - failed_sites  全部真实失败脚本名（含独立 workflow 站点，供日志/排查）
    - failed_matrix 其中属于 checkin.yml 矩阵的脚本（自动重跑仅 dispatch 这些）
    注意：待执行 (pending) 的站点不计入失败，不触发自动重跑；
    凭据未配置（⚪，非故障）的站点同样不计入失败；
    达到 8 次失败上限已熔断停用（🛑）的站点暂停重试，不计入 failed_matrix，等待修复后上线。
    """
    suspended_sites = sorted(
        {
            str(d.get("script"))
            for d in collected.values()
            if (d.get("status") == "suspended" or d.get("circuit_broken"))
        } - {""}
    )
    unconf_sites = sorted(
        {
            str(d.get("script"))
            for d in collected.values()
            if not d.get("ok") and not d.get("is_pending") and d.get("status") not in ("pending", "suspended")
            and not d.get("circuit_broken")
            and alert_levels.detect_unconfigured(str(d.get("output") or ""))
        } - {""}
    )
    failed_scripts = sorted(
        {
            str(d.get("script"))
            for d in collected.values()
            if not d.get("ok") and not d.get("is_pending") and d.get("status") not in ("pending", "suspended")
            and not d.get("circuit_broken")
        } - {""} - set(unconf_sites) - set(suspended_sites)
    )
    failed_matrix = [s for s in CHECKIN_MATRIX_SCRIPTS if s in failed_scripts]
    if suspended_sites:
        print(f"🛑 任务已熔断停用（单日达8次失败上限，暂停自动重跑，等待修复上线）：{', '.join(suspended_sites)}")
    if unconf_sites:
        print(f"⚪ 凭据未配置（按跳过处理，不触发重跑）：{', '.join(unconf_sites)}")
    if failed_scripts:
        print(
            f"🔴 真实失败站点：{', '.join(failed_scripts)}"
            f"（可自动重跑的矩阵站点：{', '.join(failed_matrix) or '无'}）"
        )
    else:
        print("✅ 无真实失败站点（所有已运行任务均成功，待执行任务按计划等待）")
    gh_output = os.getenv("GITHUB_OUTPUT")
    if gh_output:
        with open(gh_output, "a", encoding="utf-8") as fh:
            fh.write(f"failed_sites={','.join(failed_scripts)}\n")
            fh.write(f"failed_matrix={','.join(failed_matrix)}\n")
    return failed_matrix


def archive_daily_summary(collected: Dict[str, dict], today: str) -> None:
    """将当日汇总写入 Upstash Redis（best-effort，绝不阻塞报告链路）。

    Key Schema（前缀可用 CAT_CHECKIN_REDIS_PREFIX 覆盖，默认 cat_checkin:）：
      - cat_checkin:daily:YYYY-MM-DD  String(JSON)  单日完整汇总明细
      - cat_checkin:month:YYYY-MM     Hash          Field=YYYY-MM-DD, Value=站点状态 JSON
      - cat_checkin:dates             ZSet          Score=BJT 日期时间戳, Member=YYYY-MM-DD
      - cat_checkin:latest            String(JSON)  最新一次完整汇总明细
    同日重跑时新结果覆盖旧条目。解锁 30 天成功率 / 断签站点等历史分析
    （此前唯一的历史留存只有邮件）。
    凭据：UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN；未配置时跳过。
    """
    if os.getenv("ARCHIVE_SUMMARY", "true").lower() in {"0", "false", "no"}:
        return
    url = os.getenv("UPSTASH_REDIS_REST_URL", "")
    token = os.getenv("UPSTASH_REDIS_REST_TOKEN", "")
    if not url or not token:
        print("ℹ️ 历史归档跳过：未配置 UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN")
        return

    prefix = os.getenv("CAT_CHECKIN_REDIS_PREFIX", "cat_checkin:").rstrip(":")
    now = dt.datetime.now(dt.timezone(dt.timedelta(hours=8)))
    updated_at = now.isoformat()
    sites = {}
    for key, d in sorted(collected.items()):
        site_key = key[:-5] if key.endswith(".json") else key
        output_str = str(d.get("output") or "")
        # 按任务定制解析：assets/reward 供概览昨日对比，accounts 为每账号摘要行
        info = report_fields.extract_for(str(d.get("script") or ""), output_str)
        extracted = {
            "assets": report_fields.assets_pairs_text(info),
            "reward": " | ".join(txt for grp, txt in info["badges"] if grp == "reward"),
        }
        if not (extracted["assets"] or extracted["reward"]) and output_str:
            # 未注册脚本/解析为空时回退全局启发式，保持归档字段不倒退
            legacy = _extract_fields(output_str)
            extracted.setdefault("assets", legacy.get("assets", ""))
            extracted.setdefault("reward", legacy.get("reward", ""))
        is_pending = bool(d.get("is_pending")) or d.get("status") == "pending"
        is_suspended = bool(d.get("circuit_broken")) or d.get("status") == "suspended"
        if is_pending:
            st = "pending"
        elif is_suspended:
            st = "suspended"
        else:
            st = "ok" if bool(d.get("ok")) else "fail"
        if st == "fail" and alert_levels.detect_unconfigured(output_str):
            st = "unconfigured"  # ⚪ 凭据未配置（非故障）：不计失败、不影响成功率
        # 🟡 黄色预警归档：ok 站点的续期失败/凭据即将过期提示（fail 站点红线已覆盖）
        cls = alert_levels.classify(
            str(d.get("script") or ""), st == "ok" and not is_pending, output_str
        ) if not is_pending else {"level": "ok", "warns": []}
        sites[site_key] = {
            "ok": bool(d.get("ok")),
            "status": st,
            "is_pending": is_pending,
            "level": cls["level"],
            "warns": list(cls["warns"])[:4],
            "elapsed": d.get("elapsed", 0),
            "script": d.get("script", ""),
            "assets": extracted.get("assets", ""),
            "reward": extracted.get("reward", ""),
            "accounts": info["lines"][:8],
        }
    total = len(sites)
    success = sum(1 for s in sites.values() if s["status"] == "ok")
    failed = sum(1 for s in sites.values() if s["status"] == "fail")
    suspended = sum(1 for s in sites.values() if s["status"] == "suspended")
    pending = sum(1 for s in sites.values() if s["status"] == "pending")
    unconfigured = sum(1 for s in sites.values() if s["status"] == "unconfigured")
    warned = sum(1 for s in sites.values() if s.get("level") == "warn")
    summary = {
        "date": today,
        "updated_at": updated_at,
        "total": total,
        "success": success,
        "failed": failed,
        "suspended": suspended,
        "pending": pending,
        "unconfigured": unconfigured,
        "warned": warned,
        "sites": sites,
    }
    body = json.dumps(summary, ensure_ascii=False, separators=(",", ":"))
    month = today[:7]
    # ZADD score 用北京时间当日 UTC 时间戳（跨时区索引稳定；member 唯一）
    score = int(now.timestamp())
    commands = [
        ["SET", f"{prefix}:daily:{today}", body],
        ["HSET", f"{prefix}:month:{month}", today, body],
        ["ZADD", f"{prefix}:dates", score, today],
        ["SET", f"{prefix}:latest", body],
    ]

    try:
        ok, detail = upstash_redis_pipeline(commands)
        if ok:
            print(
                f"🗂️ 当日汇总已归档 → Upstash Redis（{prefix}:daily:{today}，"
                f"{success}/{total} 成功）"
            )
        else:
            print(f"⚠️ 历史归档写入失败: {detail}")
    except Exception as e:
        print(f"⚠️ 历史归档异常（不影响报告发送）: {e}")


def main() -> None:
    tz = dt.timezone(dt.timedelta(hours=8))
    now = dt.datetime.now(tz)
    today = os.getenv("TODAY") or now.strftime("%Y-%m-%d")
    yesterday = (now - dt.timedelta(days=1)).strftime("%Y-%m-%d")

    results, collected = collect_all_results(today, yesterday)

    if not results:
        print("❌ 今日（10:00 前）未收集到任何完成的签到任务结果，跳过推送。")
        sys.exit(1)

    # 尽早输出失败清单（GITHUB_OUTPUT）：即使后续邮件通道全失败（exit 1），
    # checkin.yml 的自动重跑 step（if: always()）也能拿到 failed_matrix。
    # 重跑 run（RETRY_REPORT=1）不发 failed_matrix：防循环守卫之外再设一道闸。
    retry_report = env_bool("RETRY_REPORT")
    if not retry_report:
        _emit_failed_sites(collected)

    title, report, fail_count = build_report(results)
    print("\n========== 每日统一汇总 ==========")
    print(report)

    push_enabled = os.getenv("DAILY_PUSH", "true").lower() not in {"0", "false", "no"}
    archive_only = os.getenv("ARCHIVE_ONLY", "0").lower() in {"1", "true", "yes"}
    retry_report = env_bool("RETRY_REPORT")
    report_fallback = os.getenv("REPORT_FALLBACK", "0").lower() in {"1", "true", "yes"}
    pending_count = sum(1 for d in collected.values() if d.get("is_pending") or d.get("status") == "pending")

    if push_enabled and archive_only:
        print("📡 归档模式（ARCHIVE_ONLY）：跳过邮件推送，仅归档当日汇总")
        archive_daily_summary(collected, today)
        if fail_count:
            sys.exit(1)
        return

    if push_enabled and _daily_report_window_blocks(now, report_fallback):
        # 时间窗守卫：绝不写 sent marker（否则会压制当日 20:00 主发），仅归档。
        print(f"⏰ 当前 {now.strftime('%H:%M')} BJT 不在日报发信窗口"
              f"（仅 {DAILY_REPORT_EARLIEST_HOUR}:00 之后发信），"
              "本次仅归档、不写发送标记，等待 20:00 主发 / 21:30 补发。")
        archive_daily_summary(collected, today)
        return

    if push_enabled and not retry_report and not report_fallback and pending_count > 3:
        print(f"📡 仍有 {pending_count} 个任务待执行，日常邮件推迟至全量批次完成或晚间兜底（本次仅归档）")
        archive_daily_summary(collected, today)
        return
    if push_enabled:
        if retry_report:
            title = f"[重跑] {title}"
        # Resend 主通道（QStash 持久投递，retries=0 防重复投递）+ SMTP 备选；
        # 全失败 → exit 1 等 21:30 补发
        sent_resend, resend_msg_id = send_resend(title, report, results)
        sent_smtp = False
        if not sent_resend:
            print("⚠️ Resend 主通道失败，回退 SMTP 备选通道")
            sent_smtp = send_email(title, report, results)
        if not (sent_smtp or sent_resend):
            print("❌ 所有邮件通道推送失败：不写发送标记并退出非零，等待 21:30 补发")
            sys.exit(1)
        if retry_report:
            # 重跑补充邮件：不写当日 sent marker（不挡 20:00 主发/21:30 补发、不冒充主报告），
            # 只把重跑后的最新结果再归档一次（raw hash 已含全量，覆盖为最新状态）
            print("🔁 重跑补充报告已发送（不写当日发送标记）")
            archive_daily_summary(collected, today)
            return
        # 邮件已送达或已交接 QStash（至少一个通道）才写当日标记：checkin.yml 兜底去重靠它。
        marker = {"date": today, "sent_at": dt.datetime.now(tz).isoformat()}
        if resend_msg_id:
            marker["resend_msg_id"] = resend_msg_id  # QStash msg_id，供 21:30 补发投递核查
        Path(".report_sent").write_text(
            json.dumps(marker, ensure_ascii=False),
            encoding="utf-8",
        )
        print("🔖 已写入今日本地发送标记 .report_sent")

        # 写入 Upstash Redis 发送标记（TTL 7 天，跨 runner 强力去重）
        url = os.getenv("UPSTASH_REDIS_REST_URL", "")
        token = os.getenv("UPSTASH_REDIS_REST_TOKEN", "")
        if url and token:
            try:
                prefix = os.getenv("CAT_CHECKIN_REDIS_PREFIX", "cat_checkin:").rstrip(":")
                sent_key = f"{prefix}:sent:{today}"
                ok_sent, d_sent = upstash_redis_pipeline([
                    ["SET", sent_key, json.dumps(marker, ensure_ascii=False)],
                    ["EXPIRE", sent_key, 604800],
                ])
                if ok_sent:
                    print(f"🔖 已持久化今日发送标记 → Upstash Redis ({sent_key})")
                else:
                    print(f"⚠️ Redis 发送标记写入失败: {d_sent}")
            except Exception as e:
                print(f"⚠️ Redis 发送标记写入异常: {e}")

        # 输出 resend_msg_id 到 GITHUB_OUTPUT（供 report-fallback 的 QStash 投递核查使用）
        if resend_msg_id:
            gh_output = os.getenv("GITHUB_OUTPUT")
            if gh_output:
                try:
                    with open(gh_output, "a", encoding="utf-8") as fh:
                        fh.write(f"resend_msg_id={resend_msg_id}\n")
                except Exception:
                    pass

        # 报告送达后归档当日汇总（best-effort，失败仅警告）
        archive_daily_summary(collected, today)
        # 邮件已送达即视为本次运行成功（任务失败详情已在邮件正文的红卡片里）：
        # exit 0 让 run 结论为 success，checkin.yml 兜底的 API 去重（只认 success run）
        # 才能兜住 marker cache 保存静默失败时的重复发送场景
        return

    # 未启用推送（本地调试）：保留「有任务失败则 exit 1」的 CLI 语义
    if fail_count:
        sys.exit(1)


if __name__ == "__main__":
    main()
