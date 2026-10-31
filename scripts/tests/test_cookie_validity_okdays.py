#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cookie_validity 成功运行天数反推有效期 + 老化预警测试（2026-10-31）。

背景：无法解析有效期的凭据（无 Set-Cookie/JWT/签发型证据且无兜底窗口）此前
只报「有效期未知（已使用 N 天）」，不预警。现按成功任务执行天数反推寿命：
- mark_ok 按日去重累计成功运行日（KV 数据库持久化，双通道同 update_state）；
- 成功天数 ≥ 老化基线（COOKIE_UNKNOWN_AGING_WARN_DAYS，默认 45）→ ⚠️ 黄卡；
- 超出任务声明估算窗口仍存活 → 同样升级 ⚠️ 建议预防性更新。"""
from __future__ import annotations

import os
import sys
import time
import unittest
from unittest.mock import patch
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import cookie_validity as cv  # noqa: E402


def _day_ts(offset_days: int, hour: int = 10) -> float:
    """以固定基准时刻（2026-10-01 10:00 UTC+8）推 ts，便于确定性断言。"""
    base = cv.datetime(2026, 10, 1, hour, 0, 0, tzinfo=cv.BJT).timestamp()
    return base + offset_days * cv.DAY_SEC


class TestMarkOk(unittest.TestCase):
    def test_first_ok_day(self):
        st = {}
        cv.mark_ok(st, now=_day_ts(0))
        self.assertEqual(st["ok_first_date"], "2026-10-01")
        self.assertEqual(st["ok_last_date"], "2026-10-01")
        self.assertEqual(st["ok_days_total"], 1)
        self.assertEqual(st["ok_dates"], ["2026-10-01"])

    def test_same_day_idempotent(self):
        st = {}
        cv.mark_ok(st, now=_day_ts(0, hour=9))
        cv.mark_ok(st, now=_day_ts(0, hour=21))
        self.assertEqual(st["ok_days_total"], 1)  # 同日多次运行只计 1

    def test_next_day_increments(self):
        st = {}
        cv.mark_ok(st, now=_day_ts(0))
        cv.mark_ok(st, now=_day_ts(1))
        self.assertEqual(st["ok_days_total"], 2)
        self.assertEqual(st["ok_last_date"], "2026-10-02")
        self.assertEqual(st["ok_first_date"], "2026-10-01")

    def test_ok_dates_capped(self):
        st = {}
        for d in range(cv.OK_DATES_KEEP + 30):
            cv.mark_ok(st, now=_day_ts(d))
        self.assertEqual(len(st["ok_dates"]), cv.OK_DATES_KEEP)
        self.assertEqual(st["ok_days_total"], cv.OK_DATES_KEEP + 30)  # 累计不受裁剪影响


class TestOkRunDays(unittest.TestCase):
    def test_prefers_total_counter(self):
        st = {"ok_days_total": 12, "first_seen_ts": _day_ts(-100)}
        self.assertEqual(cv.ok_run_days(st, now=_day_ts(0)), 12)

    def test_no_counter_means_zero(self):
        """评审口径：first_seen 只是凭据存在天数，不得冒充成功运行天数。"""
        st = {"first_seen_ts": _day_ts(-10)}
        self.assertEqual(cv.ok_run_days(st, now=_day_ts(0)), 0)

    def test_legacy_state_uses_used_days_wording(self):
        """无 mark_ok 计数的历史状态：build_tag 沿用「已使用 N 天」且不发老化黄卡。"""
        st = {"first_seen_ts": _day_ts(-60)}
        tag = cv.build_tag(st, now=_day_ts(0))
        self.assertIn("🔑 Cookie 有效期未知（已使用 60 天", tag)
        self.assertNotIn("⚠️", tag)

    def test_empty_state(self):
        self.assertEqual(cv.ok_run_days({}, now=_day_ts(0)), 0)


class TestBuildTagUnknownAging(unittest.TestCase):
    def test_under_baseline_is_blue_key(self):
        st = {"ok_days_total": 3, "first_seen_ts": _day_ts(-3)}
        tag = cv.build_tag(st, now=_day_ts(0))
        self.assertIn("🔑 Cookie 有效期未知（已成功运行 3 天", tag)
        self.assertNotIn("⚠️", tag)

    def test_over_baseline_warns(self):
        st = {"ok_days_total": 50, "first_seen_ts": _day_ts(-50)}
        tag = cv.build_tag(st, now=_day_ts(0))
        self.assertIn("⚠️ Cookie 有效期未知", tag)
        self.assertIn("已成功运行 50 天", tag)
        self.assertIn("建议预防性更新", tag)
        # report_fields 解析锚点不得破坏
        self.assertIn("Cookie 有效期未知", tag)

    def test_aging_baseline_env_override(self):
        old = cv.UNKNOWN_AGING_WARN_DAYS
        try:
            cv.UNKNOWN_AGING_WARN_DAYS = 10
            st = {"ok_days_total": 12, "first_seen_ts": _day_ts(-12)}
            tag = cv.build_tag(st, now=_day_ts(0))
            self.assertIn("达到 10 天老化基线", tag)
        finally:
            cv.UNKNOWN_AGING_WARN_DAYS = old

    def test_fallback_window_exceeded_warns(self):
        st = {"first_seen_ts": _day_ts(-60)}
        tag = cv.build_tag(st, now=_day_ts(0), fallback_lifetime_days=30)
        self.assertIn("⚠️ Cookie 有效期未知", tag)
        self.assertIn("超出 30 天估算窗口", tag)
        self.assertIn("建议预防性更新", tag)

    def test_fallback_window_within_is_blue(self):
        st = {"first_seen_ts": _day_ts(-3)}
        tag = cv.build_tag(st, now=_day_ts(0), fallback_lifetime_days=30)
        self.assertIn("🔑 Cookie 剩余", tag)
        self.assertNotIn("有效期未知", tag)

    def test_expiry_evidence_takes_precedence(self):
        st = {"ok_days_total": 100,
              "cookie_expire_ts": int(_day_ts(30))}
        tag = cv.build_tag(st, now=_day_ts(0))
        self.assertIn("Cookie 剩余 30 天", tag)
        self.assertNotIn("有效期未知", tag)


class TestAlertLevelsUnknownAging(unittest.TestCase):
    def test_aging_unknown_is_yellow(self):
        import alert_levels
        raw = ("👤 用户: 【***abc】 | 签到成功"
               " | ⚠️ Cookie 有效期未知（已成功运行 60 天，达到 45 天老化基线，建议预防性更新）")
        out = alert_levels.classify("dji.py", True, raw)
        self.assertEqual(out["level"], "warn")
        self.assertTrue(any("突然失效风险" in w for w in out["warns"]))

    def test_blue_unknown_is_not_yellow(self):
        import alert_levels
        raw = "👤 用户: 【***abc】 | 签到成功 | 🔑 Cookie 有效期未知（已成功运行 3 天，未观察到期证据）"
        out = alert_levels.classify("dji.py", True, raw)
        self.assertEqual(out["level"], "ok")
        self.assertEqual(out["warns"], [])

    def test_auto_renew_scripts_exempt(self):
        """AUTO_RENEW_SCRIPTS（滚动保活凭据）不适用老化黄卡（与既有 _COOKIE_DAYS_RE 同口径）。"""
        import alert_levels
        raw = ("👤 用户: 【***abc】 | 签到成功"
               " | ⚠️ Cookie 有效期未知（已成功运行 60 天，达到 45 天老化基线，建议预防性更新）")
        out = alert_levels.classify("smzdm.py", True, raw)
        self.assertEqual(out["level"], "ok")


if __name__ == "__main__":
    unittest.main()


class TestUpdateStateOkReset(unittest.TestCase):
    def test_credential_change_resets_ok_tracking(self):
        """cookie 指纹变更 → ok_* 全量重置（ok_days 度量当前凭据服务天数）。"""
        st = {"ok_days_total": 30, "ok_first_date": "2026-08-01",
              "ok_last_date": "2026-10-01", "ok_dates": ["2026-10-01"],
              "cookie_md5": "old"}
        cv.update_state(st, "brand-new-cookie-value")
        self.assertNotIn("ok_days_total", st)
        self.assertNotIn("ok_first_date", st)
        self.assertNotIn("ok_dates", st)
        # 同指纹再入不重置
        fp_now = st["cookie_md5"]
        st["ok_days_total"] = 5
        cv.update_state(st, "brand-new-cookie-value")
        self.assertEqual(st["ok_days_total"], 5)
        self.assertEqual(st["cookie_md5"], fp_now)


class TestEnvThresholdGuard(unittest.TestCase):
    def test_invalid_env_falls_back_to_default(self):
        """COOKIE_UNKNOWN_AGING_WARN_DAYS 非整数：回退默认，不得在导入期炸掉全部任务。"""
        # 隔离外部环境（本机可能设置了该变量）
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(cv._int_env("COOKIE_UNKNOWN_AGING_WARN_DAYS", 45), 45)
        with patch("os.getenv", return_value="30d"):
            self.assertEqual(cv._int_env("X", 45), 45)
        with patch("os.getenv", return_value="30"):
            self.assertEqual(cv._int_env("X", 45), 30)
        with patch("os.getenv", return_value="-5"):
            self.assertEqual(cv._int_env("X", 45), 45)
        with patch("os.getenv", return_value=""):
            self.assertEqual(cv._int_env("X", 45), 45)

    def test_aging_unknown_runtime_wording(self):
        """无计数历史状态超出声明窗口：「已运行」形态同样命中黄卡锚点。"""
        import alert_levels
        raw = ("👤 用户: 【***abc】 | 签到成功"
               " | ⚠️ Cookie 有效期未知（已运行 60 天，超出 45 天估算窗口，建议预防性更新）")
        out = alert_levels.classify("dji.py", True, raw)
        self.assertEqual(out["level"], "warn")
