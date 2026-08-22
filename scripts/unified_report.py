#!/usr/bin/env python3
# new Env("每日统一通知汇总")
"""统一汇总报告：汇聚当日签到结果，构建 HTML 邮件并经 Resend/SMTP 推送。

由 checkin.yml 的 unified（内联，orchestrator 结束后）与 report-fallback（20:30 兜底）
两个 job 触发。优先从 Upstash Redis `cat_checkin:raw:<TODAY>`（HGETALL）汇聚，
兜底扫描 `.task_results/` 本地 JSON；Latvi 若今日无结果则回退昨日（24h 冷却跨日）。
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

from common import upstash_redis_command, upstash_redis_pipeline  # noqa: E402
from daily_report import _extract_fields, build_report, send_email, send_resend  # noqa: E402
from task_registry import TASKS, get_expected_results  # noqa: E402

# Latvi 的结果文件名（24h 间隔约束，18:00 运行，报告取昨日结果）
LATVI_RESULT_FILE = "latvi.json"

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
        if is_pending:
            st = "pending"
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
        out.append((st, path, output, elapsed))

    return out, collected


def _emit_failed_sites(collected: Dict[str, dict]) -> List[str]:
    """汇总真实失败站点并写入 GITHUB_OUTPUT（供 checkin.yml 自动重跑 step 使用）。

    输出两个 step output：
    - failed_sites  全部真实失败脚本名（含独立 workflow 站点，供日志/排查）
    - failed_matrix 其中属于 checkin.yml 矩阵的脚本（自动重跑仅 dispatch 这些）
    注意：待执行 (pending) 的站点不计入失败，不触发自动重跑。
    """
    failed_scripts = sorted(
        {
            str(d.get("script"))
            for d in collected.values()
            if not d.get("ok") and not d.get("is_pending") and d.get("status") != "pending"
        } - {""}
    )
    failed_matrix = [s for s in CHECKIN_MATRIX_SCRIPTS if s in failed_scripts]
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
        extracted = _extract_fields(output_str) if output_str else {}
        is_pending = bool(d.get("is_pending")) or d.get("status") == "pending"
        st = "pending" if is_pending else ("ok" if bool(d.get("ok")) else "fail")
        sites[site_key] = {
            "ok": bool(d.get("ok")),
            "status": st,
            "is_pending": is_pending,
            "elapsed": d.get("elapsed", 0),
            "script": d.get("script", ""),
            "assets": extracted.get("assets", ""),
            "reward": extracted.get("reward", ""),
        }
    total = len(sites)
    success = sum(1 for s in sites.values() if s["status"] == "ok")
    failed = sum(1 for s in sites.values() if s["status"] == "fail")
    pending = sum(1 for s in sites.values() if s["status"] == "pending")
    summary = {
        "date": today,
        "updated_at": updated_at,
        "total": total,
        "success": success,
        "failed": failed,
        "pending": pending,
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
    retry_report = os.getenv("RETRY_REPORT", "").lower() in ("1", "true", "yes")
    if not retry_report:
        _emit_failed_sites(collected)

    title, report, fail_count = build_report(results)
    print("\n========== 每日统一汇总 ==========")
    print(report)

    push_enabled = os.getenv("DAILY_PUSH", "true").lower() not in {"0", "false", "no"}
    if push_enabled:
        if retry_report:
            title = f"[重跑] {title}"
        # Resend 为主通道；仅当主通道失败才回退 SMTP（备选语义，双通道同时配置时不再双发）
        sent_resend, resend_msg_id = send_resend(title, report, results)
        sent_smtp = False
        if not sent_resend:
            print("⚠️ Resend 主通道失败，回退 SMTP 备选通道")
            sent_smtp = send_email(title, report, results)
        if not (sent_smtp or sent_resend):
            print("❌ 所有邮件通道推送失败：不写发送标记并退出非零，等待 10:30 兜底重试")
            sys.exit(1)
        if retry_report:
            # 重跑补充邮件：不写当日 sent marker（不挡 20:30 兜底、不冒充主报告），
            # 只把重跑后的最新结果再归档一次（raw hash 已含全量，覆盖为最新状态）
            print("🔁 重跑补充报告已发送（不写当日发送标记）")
            archive_daily_summary(collected, today)
            return
        # 邮件已送达或已交接 QStash（至少一个通道）才写当日标记：checkin.yml 兜底去重靠它。
        # resend_msg_id 可为空（SMTP-only / 直发失败 / QStash publish 失败回退直发但 Resend 未返回 id），
        # 有值时 10:30 兜底 run 可查询 QStash /v2/logs 确认投递状态。
        marker = {"date": today, "sent_at": dt.datetime.now(tz).isoformat()}
        if resend_msg_id:
            marker["resend_msg_id"] = resend_msg_id
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

        # 输出 resend_msg_id 到 GITHUB_OUTPUT（供 GitHub Actions 后续步骤使用）
        gh_output = os.getenv("GITHUB_OUTPUT")
        if gh_output and resend_msg_id:
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
