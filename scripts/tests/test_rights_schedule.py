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
        ids = [sid for sid, _, _, _ in srs.SCHEDULES]
        self.assertEqual(ids, ["cat-checkin-rights-window", "cat-checkin-rights-catchup"])
        crons = {sid: cron for sid, cron, _, _ in srs.SCHEDULES}
        # UTC 15:30 = BJT 23:30；UTC 16:00 = BJT 00:00（5 字段 cron 无秒）
        # 补发必须在窗口内：旧 23:50 被 workflow 并发锁延后到 00:04 形同虚设
        self.assertEqual(crons["cat-checkin-rights-window"], "30 15 * * *")
        self.assertEqual(crons["cat-checkin-rights-catchup"], "0 16 * * *")
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
        for (dest, cron, body, kw), (sid, want_cron, _, is_catchup) in zip(calls, srs.SCHEDULES):
            self.assertEqual(dest, "https://api.github.com/repos/owner/repo/dispatches")
            self.assertEqual(cron, want_cron)
            self.assertIn('"checkin_rights"', body)
            if is_catchup:
                self.assertIn('"client_payload"', body)
                self.assertIn('"catchup": true', body)
            else:
                self.assertNotIn('"client_payload"', body)
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

    def test_rights_dispatch_has_independent_concurrency_group(self):
        """0 点场派发不得排在主力 unified 并发组之后（PR #40 评审）：
        23:30 主力占用队列到 00:04，补发必须能同时进入窗口。"""
        wf = (BASE_DIR.parent / ".github" / "workflows" / "checkin.yml").read_text(encoding="utf-8")
        self.assertIn("github.event.action == 'checkin_rights'", wf)
        self.assertIn("github.event.client_payload.catchup == true", wf)
        self.assertIn("unified-rights-catchup-", wf)
        self.assertIn("unified-rights-window-", wf)

    def test_workflow_self_heals_rights_schedule(self):
        """自愈护栏：unified job 必须有 Ensure QStash rights schedule 步骤，
        排程被误删时任何非空 run 原地重建。"""
        wf = (BASE_DIR.parent / ".github" / "workflows" / "checkin.yml").read_text(encoding="utf-8")
        self.assertIn("Ensure QStash rights schedule", wf)
        self.assertIn("python3 scripts/setup_rights_schedule.py", wf)

    def test_list_masks_destination_tokens(self):
        """--list 展示 destination 前必须脱敏：其他排程的 webhook query token
        不得完整写进输出（PR #34 第五轮评审）。"""
        import io
        fake_resp = mock.Mock()
        fake_resp.code = 200
        fake_resp.json.return_value = [
            {"scheduleId": "other", "cron": "0 0 * * *",
             "destination": "https://hooks.example/notify?token=V1.0FAKEabc123secret",
             "method": "POST"},
            {"scheduleId": "cat-checkin-rights-window", "cron": "30 15 * * *",
             "destination": "https://api.github.com/repos/owner/repo/dispatches",
             "method": "POST"},
        ]
        buf = io.StringIO()
        env = {"QSTASH_URL": "https://qstash.example/v2/publish", "QSTASH_TOKEN": "V1.0FAKEtok"}
        with mock.patch.dict(os.environ, env, clear=False), \
             mock.patch.object(srs, "Http") as m_http, \
             mock.patch("sys.stdout", buf):
            m_http.return_value.request.return_value = fake_resp
            rc = srs.list_schedules()
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertNotIn("V1.0FAKEabc123secret", out)
        self.assertIn("<masked>", out)
        # 无凭据的 GitHub dispatch 目标不受影响
        self.assertIn("api.github.com/repos/owner/repo/dispatches", out)

    def test_docstring_states_contents_write_permission(self):
        """文档护栏：dispatches API 要求 Contents: write（非 Actions: write），
        说明文字不得误导用户配错令牌权限（PR #34 第五轮评审）。"""
        self.assertIn("Contents: write", srs.__doc__)


if __name__ == "__main__":
    unittest.main()