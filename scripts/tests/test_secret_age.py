#!/usr/bin/env python3
"""secret_age 自检：凭据年龄预警（hard/rolling 两型 + build_report 联动）。

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


# --- rolling 型（真实注册表：WORKBUDDY_REFRESH_TOKEN_*，阈值 3 天）---
fresh = secret_age.compute_warns({"WORKBUDDY_REFRESH_TOKEN_1": iso(NOW - timedelta(days=1))}, NOW)
check("rolling 新鲜(1天)无预警", fresh == [], f"got {fresh}")

stale = secret_age.compute_warns(
    {"WORKBUDDY_REFRESH_TOKEN_2": iso(NOW - timedelta(days=3, hours=2))}, NOW
)
check("rolling 超阈值(3天未滚动)预警", len(stale) == 1 and stale[0]["kind"] == "rolling", f"got {stale}")
check("rolling 文案含断链提示", stale and "滚动" in secret_age.format_warn(stale[0]) and "workbuddy" in secret_age.format_warn(stale[0]))
check("rolling 徽标含未滚动天数", stale and "未滚动" in secret_age.format_chip(stale[0]))

edge = secret_age.compute_warns({"WORKBUDDY_REFRESH_TOKEN_1": iso(NOW - timedelta(days=2, hours=20))}, NOW)
check("rolling 阈值内(2.8天)不预警", edge == [], f"got {edge}")

missing = secret_age.compute_warns({"WORKBUDDY_REFRESH_TOKEN_2": ""}, NOW)
check("空 updated_at 跳过", missing == [], f"got {missing}")

# --- hard 型（合成注册表：剩 ≤1 天 / 过期 / 新鲜）---
SAVED = dict(secret_age.CREDENTIAL_LIFETIMES)
try:
    secret_age.CREDENTIAL_LIFETIMES.clear()
    secret_age.CREDENTIAL_LIFETIMES.update({
        "HARD_COOKIE_1": ("合成账号", 7),
    })
    near = secret_age.compute_warns({"HARD_COOKIE_1": iso(NOW - timedelta(days=6, hours=3))}, NOW)
    check("hard 剩 0.9 天预警", len(near) == 1 and near[0]["kind"] == "hard" and near[0]["expired"] is False, f"got {near}")
    check("hard 预警含账号名与重登指引", near and "合成账号" in secret_age.format_warn(near[0]) and "重新登录" in secret_age.format_warn(near[0]))
    dead = secret_age.compute_warns({"HARD_COOKIE_1": iso(NOW - timedelta(days=7, minutes=1))}, NOW)
    check("hard 超 7 天标记 expired", dead and dead[0]["expired"] is True and "硬上限" in secret_age.format_warn(dead[0]))
    edge_out = secret_age.compute_warns({"HARD_COOKIE_1": iso(NOW - timedelta(days=5, hours=12))}, NOW)
    check("hard 剩 1.5 天不提示", edge_out == [], f"got {edge_out}")
    bad = secret_age.compute_warns({"HARD_COOKIE_1": "not-a-date"}, NOW)
    check("坏时间戳跳过", bad == [], f"got {bad}")
    mixed = secret_age.compute_warns({"HARD_COOKIE_1": iso(NOW - timedelta(days=7, minutes=1))}, NOW)
    half = secret_age.format_warn({"title": "合成账号", "secret": "HARD_COOKIE_1", "remaining_days": 0.3, "lifetime_days": 7, "expired": False, "kind": "hard"})
    check("hard 剩 <0.5 天文案", "不足半天" in half, half)
finally:
    secret_age.CREDENTIAL_LIFETIMES.clear()
    secret_age.CREDENTIAL_LIFETIMES.update(SAVED)

chip_hard = secret_age.format_chip({"title": "合成账号", "secret": "HARD_COOKIE_1", "remaining_days": 0.3, "lifetime_days": 7, "expired": False, "kind": "hard"})
check("hard 徽标短文案", "≤半天" in chip_hard and "合成账号" in chip_hard, chip_hard)

# --- 端到端：build_report 注入凭据预警（头部 🟡 计数 + 独立提醒块） ---
try:
    import daily_report

    orig = daily_report.secret_age.credential_age_warns
    try:
        daily_report.secret_age.credential_age_warns = lambda: [
            {"title": "WorkBuddy 账号1", "secret": "WORKBUDDY_REFRESH_TOKEN_1", "remaining_days": -0.1, "lifetime_days": 3, "kind": "rolling", "age_days": 3.1, "expired": False}
        ]
        header, text, fail_n = daily_report.build_report(
            [(True, BASE / "workbuddy.py", "签到成功 +5", 1.0, "WorkBuddy 账号1")]
        )
        check(
            "build_report 端到端：[🟡 1项注意] + 凭据寿命提醒块 + 不计失败",
            "[🟡 1项注意]" in header and "凭据寿命提醒" in text and fail_n == 0,
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

# --- 数据库回写（Redis rotated_at）优先于 Secret updated_at ---
from unittest import mock  # noqa: E402
import common  # noqa: E402


def _redis_result(rotated_at_epoch):
    return (True, {"result": __import__("json").dumps({"refresh_token": "tok", "rotated_at": rotated_at_epoch})})


try:
    fresh_epoch = (NOW - timedelta(days=1)).timestamp()
    stale_epoch = (NOW - timedelta(days=4)).timestamp()
    secret_fresh = {"WORKBUDDY_REFRESH_TOKEN_1": iso(NOW - timedelta(days=1)),
                    "WORKBUDDY_REFRESH_TOKEN_2": iso(NOW - timedelta(days=1))}
    with mock.patch.object(common, "upstash_redis_command", return_value=_redis_result(fresh_epoch)), \
         mock.patch.object(secret_age, "fetch_secret_updated_at", return_value=secret_fresh), \
         mock.patch.dict("os.environ", {"CAT_CHECKIN_REDIS_PREFIX": "cat_checkin:"}):
        rotated = secret_age._redis_rotated_at()
        check("Redis rotated_at 解析为 ISO", set(rotated) == {"WORKBUDDY_REFRESH_TOKEN_1", "WORKBUDDY_REFRESH_TOKEN_2"}
              and all("T" in v for v in rotated.values()), f"got {rotated}")
        check("Redis 新鲜时整体无预警", secret_age.credential_age_warns() == [], "应无预警")

    with mock.patch.object(common, "upstash_redis_command", return_value=_redis_result(stale_epoch)), \
         mock.patch.object(secret_age, "fetch_secret_updated_at", return_value=secret_fresh), \
         mock.patch.dict("os.environ", {"CAT_CHECKIN_REDIS_PREFIX": "cat_checkin:"}):
        warns = secret_age.credential_age_warns()
        check("Redis 超阈值即预警（即使 Secret 新鲜）", len(warns) >= 1 and all(w["kind"] == "rolling" for w in warns), f"got {warns}")

    with mock.patch.object(common, "upstash_redis_command", return_value=(False, "no key")), \
         mock.patch.object(secret_age, "fetch_secret_updated_at", return_value=secret_fresh), \
         mock.patch.dict("os.environ", {"CAT_CHECKIN_REDIS_PREFIX": "cat_checkin:"}):
        _warns_fb = secret_age.credential_age_warns()
        check("Redis 无键时回退 Secret updated_at", _warns_fb == [], f"got {_warns_fb}")

    with mock.patch.object(common, "upstash_redis_command", side_effect=RuntimeError("redis down")), \
         mock.patch.object(secret_age, "fetch_secret_updated_at", return_value=secret_fresh), \
         mock.patch.dict("os.environ", {"CAT_CHECKIN_REDIS_PREFIX": "cat_checkin:"}):
        _warns_ex = secret_age.credential_age_warns()
        check("Redis 异常时静默回退 Secret", _warns_ex == [], f"got {_warns_ex}")
except Exception as exc:
    failures.append(f"Redis rotated_at 联动异常: {exc}")
    print(f"[FAIL] Redis rotated_at 联动异常: {exc}")

print(f"\n{'❌ ' + str(len(failures)) + ' 项失败' if failures else '✅ 全部通过'}")
for f in failures:
    print(f"  - {f}")
sys.exit(1 if failures else 0)
