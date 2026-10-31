#!/usr/bin/env python3
"""secret_age 自检：凭据年龄预警（hard/rolling 两型 + build_report 联动）。

用法：python3 -m unittest scripts/tests/test_secret_age.py
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent  # scripts/
sys.path.insert(0, str(BASE))

import common  # noqa: E402
import secret_age  # noqa: E402


class TestSecretAge(unittest.TestCase):
    """凭据年龄预警测试类。"""

    def setUp(self):
        self.now = datetime.now(timezone.utc)

    def _iso(self, dt: datetime) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def test_rolling_fresh(self):
        """rolling 新鲜(1天)无预警。"""
        fresh = secret_age.compute_warns(
            {"WORKBUDDY_REFRESH_TOKEN_1": self._iso(self.now - timedelta(days=1))},
            self.now,
        )
        self.assertEqual(fresh, [])

    def test_rolling_stale(self):
        """rolling 超阈值(3天未滚动)预警。"""
        stale = secret_age.compute_warns(
            {"WORKBUDDY_REFRESH_TOKEN_2": self._iso(self.now - timedelta(days=3, hours=2))},
            self.now,
        )
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0]["kind"], "rolling")
        warn_msg = secret_age.format_warn(stale[0])
        self.assertIn("滚动", warn_msg)
        self.assertIn("workbuddy", warn_msg.lower())
        self.assertIn("未滚动", secret_age.format_chip(stale[0]))

    def test_rolling_threshold_edge(self):
        """rolling 阈值内(2.8天)不预警。"""
        edge = secret_age.compute_warns(
            {"WORKBUDDY_REFRESH_TOKEN_1": self._iso(self.now - timedelta(days=2, hours=20))},
            self.now,
        )
        self.assertEqual(edge, [])

    def test_empty_updated_at(self):
        """空 updated_at 跳过。"""
        missing = secret_age.compute_warns({"WORKBUDDY_REFRESH_TOKEN_2": ""}, self.now)
        self.assertEqual(missing, [])

    def test_hard_lifetime_scenarios(self):
        """hard 型场景（剩 ≤1 天 / 过期 / 新鲜 / 格式异常）。"""
        saved = dict(secret_age.CREDENTIAL_LIFETIMES)
        try:
            secret_age.CREDENTIAL_LIFETIMES.clear()
            secret_age.CREDENTIAL_LIFETIMES.update({"HARD_COOKIE_1": ("合成账号", 7)})

            # 剩 0.9 天预警
            near = secret_age.compute_warns(
                {"HARD_COOKIE_1": self._iso(self.now - timedelta(days=6, hours=3))},
                self.now,
            )
            self.assertEqual(len(near), 1)
            self.assertEqual(near[0]["kind"], "hard")
            self.assertFalse(near[0]["expired"])
            self.assertIn("合成账号", secret_age.format_warn(near[0]))
            self.assertIn("重新登录", secret_age.format_warn(near[0]))

            # 超 7 天标记 expired
            dead = secret_age.compute_warns(
                {"HARD_COOKIE_1": self._iso(self.now - timedelta(days=7, minutes=1))},
                self.now,
            )
            self.assertTrue(dead and dead[0]["expired"])
            self.assertIn("硬上限", secret_age.format_warn(dead[0]))

            # 剩 1.5 天不提示
            edge_out = secret_age.compute_warns(
                {"HARD_COOKIE_1": self._iso(self.now - timedelta(days=5, hours=12))},
                self.now,
            )
            self.assertEqual(edge_out, [])

            # 坏时间戳跳过
            bad = secret_age.compute_warns({"HARD_COOKIE_1": "not-a-date"}, self.now)
            self.assertEqual(bad, [])

            # 不足半天文案
            half = secret_age.format_warn({
                "title": "合成账号",
                "secret": "HARD_COOKIE_1",
                "remaining_days": 0.3,
                "lifetime_days": 7,
                "expired": False,
                "kind": "hard",
            })
            self.assertIn("不足半天", half)
        finally:
            secret_age.CREDENTIAL_LIFETIMES.clear()
            secret_age.CREDENTIAL_LIFETIMES.update(saved)

    def test_build_report_integration(self):
        """build_report 注入凭据预警。"""
        import daily_report

        orig = daily_report.secret_age.credential_age_warns
        try:
            daily_report.secret_age.credential_age_warns = lambda: [{
                "title": "WorkBuddy 账号1",
                "secret": "WORKBUDDY_REFRESH_TOKEN_1",
                "remaining_days": -0.1,
                "lifetime_days": 3,
                "kind": "rolling",
                "age_days": 3.1,
                "expired": False,
            }]
            header, text, fail_n = daily_report.build_report(
                [(True, BASE / "workbuddy.py", "签到成功 +5", 1.0, "WorkBuddy 账号1")]
            )
            self.assertIn("[🟡 1项注意]", header)
            self.assertIn("凭据寿命提醒", text)
            self.assertEqual(fail_n, 0)

            # 预警为空时不渲染提醒块
            daily_report.secret_age.credential_age_warns = lambda: []
            header2, text2, _ = daily_report.build_report(
                [(True, BASE / "workbuddy.py", "签到成功 +5", 1.0, "WorkBuddy 账号1")]
            )
            self.assertNotIn("凭据寿命提醒", text2)
            self.assertNotIn("[🟡", header2)

            # credential_age_warns 抛异常也不影响报告
            daily_report.secret_age.credential_age_warns = mock.Mock(side_effect=RuntimeError("api down"))
            header3, _, _ = daily_report.build_report(
                [(True, BASE / "workbuddy.py", "签到成功 +5", 1.0, "WorkBuddy 账号1")]
            )
            self.assertIn("每日签到汇总", header3)
        finally:
            daily_report.secret_age.credential_age_warns = orig

    def test_fetch_secret_no_token(self):
        """无 token 时 fetch 返回 {}。"""
        saved = {k: os.environ.pop(k) for k in ("GH_PAT", "GH_TOKEN", "GITHUB_TOKEN", "GITHUB_REPO", "GITHUB_REPOSITORY") if k in os.environ}
        try:
            self.assertEqual(secret_age.fetch_secret_updated_at(), {})
        finally:
            os.environ.update(saved)

    def test_redis_rotated_at(self):
        """数据库回写（Redis rotated_at）优先于 Secret updated_at。"""
        def _redis_result(rotated_at_epoch):
            return (True, {"result": __import__("json").dumps({"refresh_token": "tok", "rotated_at": rotated_at_epoch})})

        fresh_epoch = (self.now - timedelta(days=1)).timestamp()
        stale_epoch = (self.now - timedelta(days=4)).timestamp()
        secret_fresh = {
            "WORKBUDDY_REFRESH_TOKEN_1": self._iso(self.now - timedelta(days=1)),
            "WORKBUDDY_REFRESH_TOKEN_2": self._iso(self.now - timedelta(days=1)),
        }

        with mock.patch.object(common, "upstash_redis_command", return_value=_redis_result(fresh_epoch)), \
             mock.patch.object(secret_age, "fetch_secret_updated_at", return_value=secret_fresh), \
             mock.patch.dict("os.environ", {"CAT_CHECKIN_REDIS_PREFIX": "cat_checkin:"}):
            rotated = secret_age._redis_rotated_at()
            self.assertEqual(set(rotated), {"WORKBUDDY_REFRESH_TOKEN_1", "WORKBUDDY_REFRESH_TOKEN_2"})
            self.assertTrue(all("T" in v for v in rotated.values()))
            self.assertEqual(secret_age.credential_age_warns(), [])

        with mock.patch.object(common, "upstash_redis_command", return_value=_redis_result(stale_epoch)), \
             mock.patch.object(secret_age, "fetch_secret_updated_at", return_value=secret_fresh), \
             mock.patch.dict("os.environ", {"CAT_CHECKIN_REDIS_PREFIX": "cat_checkin:"}):
            warns = secret_age.credential_age_warns()
            self.assertGreaterEqual(len(warns), 1)
            self.assertTrue(all(w["kind"] == "rolling" for w in warns))

        with mock.patch.object(common, "upstash_redis_command", return_value=(False, "no key")), \
             mock.patch.object(secret_age, "fetch_secret_updated_at", return_value=secret_fresh), \
             mock.patch.dict("os.environ", {"CAT_CHECKIN_REDIS_PREFIX": "cat_checkin:"}):
            self.assertEqual(secret_age.credential_age_warns(), [])

        with mock.patch.object(common, "upstash_redis_command", side_effect=RuntimeError("redis down")), \
             mock.patch.object(secret_age, "fetch_secret_updated_at", return_value=secret_fresh), \
             mock.patch.dict("os.environ", {"CAT_CHECKIN_REDIS_PREFIX": "cat_checkin:"}):
            self.assertEqual(secret_age.credential_age_warns(), [])


if __name__ == "__main__":
    unittest.main()
