#!/usr/bin/env python3
"""secret_age 自检：硬寿命凭据年龄预警（compute_warns 纯函数 + build_report 联动）。

用法：python3 scripts/tests/test_secret_age.py
"""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent  # scripts/
sys.path.insert(0, str(BASE))

import secret_age  # noqa: E402

failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if not cond:
        failures.append(f"{name}: {detail}")
    print(f"[{'PASS' if cond else 'FAIL'}] {name}{'' if cond else ' —— ' + detail}")


NOW = datetime(2026, 8, 30, 13, 0, 0, tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# --- compute_warns：新鲜凭据不提示 ---
fresh = secret_age.compute_warns(
    {"WORKBUDDY_COOKIE_1": iso(NOW - timedelta(days=2)), "WORKBUDDY_COOKIE_2": iso(NOW - timedelta(days=3))},
    NOW,
)
check("新鲜凭据(2/3天)无预警", fresh == [], f"got {fresh}")

# --- 剩 ≤1 天 → 非过期预警 ---
near = secret_age.compute_warns({"WORKBUDDY_COOKIE_1": iso(NOW - timedelta(days=6, hours=3))}, NOW)
check("剩 0.9 天产出 1 条预警", len(near) == 1, f"got {near}")
check("非过期标记", near and near[0]["expired"] is False)
check("secret 名正确", near and near[0]["secret"] == "WORKBUDDY_COOKIE_1")
check("预警含账号名与重登指引", near and "WorkBuddy 账号1" in secret_age.format_warn(near[0]) and "重新登录" in secret_age.format_warn(near[0]))

# --- 超过 7 天 → 过期预警 ---
dead = secret_age.compute_warns({"WORKBUDDY_COOKIE_2": iso(NOW - timedelta(days=7, minutes=1))}, NOW)
check("超 7 天标记 expired", dead and dead[0]["expired"] is True, f"got {dead}")
check("过期文案含硬上限", dead and "硬上限" in secret_age.format_warn(dead[0]))

# --- 剩 1.5 天 → 不提示 ---
edge_out = secret_age.compute_warns({"WORKBUDDY_COOKIE_1": iso(NOW - timedelta(days=5, hours=12))}, NOW)
check("剩 1.5 天不提示", edge_out == [], f"got {edge_out}")

# --- 缺失/坏时间戳/naive 时间 ---
mixed = secret_age.compute_warns(
    {"WORKBUDDY_COOKIE_1": "not-a-date", "WORKBUDDY_COOKIE_2": iso(NOW - timedelta(days=6, hours=12))}, NOW
)
check("坏时间戳跳过 + naive 视为 UTC", len(mixed) == 1 and mixed[0]["secret"] == "WORKBUDDY_COOKIE_2", f"got {mixed}")

# --- 排序：最紧急在前 ---
two = secret_age.compute_warns(
    {"WORKBUDDY_COOKIE_1": iso(NOW - timedelta(days=6, hours=2)), "WORKBUDDY_COOKIE_2": iso(NOW - timedelta(days=7, hours=1))},
    NOW,
)
check("过期排在最前", len(two) == 2 and two[0]["expired"] and not two[1]["expired"], f"got {[e['expired'] for e in two]}")

# --- 文案分支：剩不足半天 ---
half = secret_age.format_warn({"title": "WorkBuddy 账号2", "secret": "WORKBUDDY_COOKIE_2", "remaining_days": 0.3, "lifetime_days": 7, "expired": False})
check("剩 <0.5 天文案", "不足半天" in half, half)
chip = secret_age.format_chip({"title": "WorkBuddy 账号2", "secret": "WORKBUDDY_COOKIE_2", "remaining_days": 0.3, "lifetime_days": 7, "expired": False})
check("徽标短文案", "≤半天" in chip and "WorkBuddy 账号2" in chip, chip)

# --- 端到端：build_report 注入凭据预警（头部 🟡 计数 + 独立提醒块） ---
try:
    import daily_report

    orig = daily_report.secret_age.credential_age_warns
    try:
        daily_report.secret_age.credential_age_warns = lambda: [
            {"title": "WorkBuddy 账号1", "secret": "WORKBUDDY_COOKIE_1", "remaining_days": 0.8, "lifetime_days": 7, "expired": False}
        ]
        header, text, fail_n = daily_report.build_report(
            [(True, BASE / "workbuddy.py", "签到成功 +5", 1.0, "WorkBuddy 账号1")]
        )
        check(
            "build_report 端到端：[🟡 1项注意] + 凭据寿命提醒块 + 不计失败",
            "[🟡 1项注意]" in header and "凭据寿命提醒" in text and "重新登录" in text and fail_n == 0,
            f"header={header!r}",
        )
        # 预警为空时不渲染提醒块
        daily_report.secret_age.credential_age_warns = lambda: []
        header2, text2, _ = daily_report.build_report(
            [(True, BASE / "workbuddy.py", "签到成功 +5", 1.0, "WorkBuddy 账号1")]
        )
        check("无预警时不渲染提醒块", "凭据寿命提醒" not in text2 and "[🟡" not in header2, f"header={header2!r}")
        # credential_age_warns 抛异常也不影响报告
        def _boom():
            raise RuntimeError("api down")

        daily_report.secret_age.credential_age_warns = _boom
        header3, _, _ = daily_report.build_report(
            [(True, BASE / "workbuddy.py", "签到成功 +5", 1.0, "WorkBuddy 账号1")]
        )
        check("预警 API 异常不影响报告", "每日签到汇总" in header3, f"header={header3!r}")
    finally:
        daily_report.secret_age.credential_age_warns = orig
except Exception as exc:
    failures.append(f"build_report 联动异常: {exc}")
    print(f"[FAIL] build_report 联动异常: {exc}")

# --- fetch_secret_updated_at 无 token → {}（不联网不报错） ---
import os  # noqa: E402

_saved = {k: os.environ.pop(k) for k in ("GH_PAT", "GH_TOKEN", "GITHUB_TOKEN", "GITHUB_REPO", "GITHUB_REPOSITORY") if k in os.environ}
try:
    check("无 token 时 fetch 返回 {}", secret_age.fetch_secret_updated_at() == {})
finally:
    os.environ.update(_saved)

print(f"\n{'❌ ' + str(len(failures)) + ' 项失败' if failures else '✅ 全部通过'}")
for f in failures:
    print(f"  - {f}")
sys.exit(1 if failures else 0)
