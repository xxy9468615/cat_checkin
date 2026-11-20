#!/usr/bin/env python3
"""0 点抢兑 QStash 双排程（主力 23:30 + 补发 23:50 BJT）单元测试。

覆盖：
1. 排程常量：双 scheduleId / UTC cron 与 BJT 时刻对齐 / 事件名与 workflow 契约。
2. create_schedules：缺凭据报错；双排程逐条注册（幂等 ID + retries）。
3. workflow 契约：checkin.yml 认 checkin_rights 事件并映射 telecom-exchange。
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import setup_rights_schedule as srs


class TestRightsSchedule(unittest.TestCase):
    def test_schedule_constants(self):
        ids = [sid for sid, _, _ in srs.SCHEDULES]
        self.assertEqual(ids, ["cat-checkin-rights-window", "cat-checkin-rights-catchup"])
        crons = {sid: cron for sid, cron, _ in srs.SCHEDULES}
        # UTC 15:30 = BJT 23:30（0 点场前 30 分钟）；15:50 = BJT 23:50（补发）
        self.assertEqual(crons["cat-checkin-rights-window"], "30 15 * * *")
        self.assertEqual(crons["cat-checkin-rights-catchup"], "50 15 * * *")
        self.assertEqual(srs.EVENT_TYPE, "checkin_rights")

    def test_create_requires_credentials(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch("sys.stdout") as _:
            self.assertEqual(srs.create_schedules(), 1)

    def test_create_registers_both_schedules_idempotently(self):
        calls = []

        def fake_create(destination, cron, body, **kw):
            calls.append((destination, cron, body, kw))
            return True, kw.get("schedule_id", "")

        env = {"GITHUB_REPO": "owner/repo", "GH_PAT": "V1.0FAKEpat",
               "QSTASH_URL": "https://qstash.example/v2/publish", "QSTASH_TOKEN": "V1.0FAKEtok"}
        with mock.patch.dict(os.environ, env, clear=False), \
             mock.patch.object(srs, "create_qstash_schedule", side_effect=fake_create), \
             mock.patch("sys.stdout"):
            rc = srs.create_schedules()
        self.assertEqual(rc, 0)
        self.assertEqual(len(calls), 2)
        for (dest, cron, body, kw), (sid, want_cron, _) in zip(calls, srs.SCHEDULES):
            self.assertEqual(dest, "https://api.github.com/repos/owner/repo/dispatches")
            self.assertEqual(cron, want_cron)
            self.assertIn('"checkin_rights"', body)
            self.assertEqual(kw["schedule_id"], sid)  # 固定 ID 幂等更新
            self.assertEqual(kw["retries"], 3)
            self.assertIn("Authorization", kw["forward_headers"])

    def test_workflow_accepts_checkin_rights_event(self):
        """workflow 契约护栏：事件类型注册 + Precheck 映射 telecom-exchange。"""
        wf = (BASE_DIR.parent / ".github" / "workflows" / "checkin.yml").read_text(encoding="utf-8")
        self.assertIn("- checkin_rights", wf)
        self.assertIn('checkin_rights)', wf)
        # 映射行必须指向 telecom-exchange
        import re
        m = re.search(r'checkin_rights\)\s+CANDIDATES="([^"]+)"', wf)
        self.assertIsNotNone(m, "Precheck case 分支缺少 checkin_rights 映射")
        self.assertEqual(m.group(1), "telecom-exchange")

    def test_workflow_self_heals_rights_schedule(self):
        """自愈护栏：unified job 必须有 Ensure QStash rights schedule 步骤，
        排程被误删时任何非空 run 原地重建。"""
        wf = (BASE_DIR.parent / ".github" / "workflows" / "checkin.yml").read_text(encoding="utf-8")
        self.assertIn("Ensure QStash rights schedule", wf)
        self.assertIn("python3 scripts/setup_rights_schedule.py", wf)


if __name__ == "__main__":
    unittest.main()