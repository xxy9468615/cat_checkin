#!/usr/bin/env python3
"""全任务统一时延分段重试与 8 次失败熔断停用机制单元测试套件。

覆盖范围：
1. 阶梯重试时延梯度与 8 次最大上限定义验证。
2. 任务执行状态记录（成功清零、逐次失败时间跨度递增）。
3. 第 8 次失败瞬时熔断触发（status="suspended", circuit_broken=True）。
4. 跨日自动归零与状态隔离。
5. 到期重试任务识别与最小等待延迟计算。
6. 人工修复后单任务与全量任务重新上线恢复。
7. CI 重试候选站点综合评估（check-retry 命令逻辑）。
8. 编排器调度拦截：已熔断任务跳过执行，且退出码不判为失败。
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import circuit_breaker
from common import BJT


class TestCircuitBreaker(unittest.TestCase):
    """统一重试与熔断管理器测试。"""

    def setUp(self):
        self.test_task = "test_target"
        self.mock_state: dict = {}

        # 隔离状态存储，使用内存字典模拟 load/save
        self.load_patch = mock.patch.object(
            circuit_breaker, "load_circuit_state", side_effect=lambda tid: dict(self.mock_state)
        )
        self.save_patch = mock.patch.object(
            circuit_breaker,
            "save_circuit_state",
            side_effect=lambda tid, st: self.mock_state.update(st),
        )
        self.save_record_patch = mock.patch.object(
            circuit_breaker, "save_suspended_result_record", return_value=None
        )
        self.notify_patch = mock.patch(
            "discord_notify.notify_circuit_breaker", return_value=True
        )
        self.print_patch = mock.patch("builtins.print")

        self.load_patch.start()
        self.save_patch.start()
        self.save_record_patch.start()
        self.notify_patch.start()
        self.print_patch.start()

    def tearDown(self):
        self.load_patch.stop()
        self.save_patch.stop()
        self.save_record_patch.stop()
        self.notify_patch.stop()
        self.print_patch.stop()

    def test_constants_and_ladder(self):
        """验证 8 次上限与分段重试梯度（15m -> 30m -> 45m -> 1h -> 1.5h -> 2h -> 3h）。"""
        self.assertEqual(circuit_breaker.MAX_DAILY_ATTEMPTS, 8)
        expected_intervals = [900, 1800, 2700, 3600, 5400, 7200, 10800]
        self.assertEqual(circuit_breaker.RETRY_INTERVALS, expected_intervals)

    def test_record_task_success(self):
        """验证任务执行成功时清除失败重试计数与熔断标记。"""
        today = circuit_breaker._bjt_today()
        self.mock_state = {
            "attempts": 3,
            "attempt_date": today,
            "fail_streak": 3,
            "circuit_broken": True,
            "status": "suspended",
            "next_retry_at": 1234567.0,
        }

        st, tripped = circuit_breaker.record_task_outcome(self.test_task, ok=True)
        self.assertFalse(tripped)
        self.assertFalse(st["circuit_broken"])
        self.assertEqual(st["status"], "active")
        self.assertEqual(st["fail_streak"], 0)
        self.assertIsNone(st["next_retry_at"])
        self.assertEqual(st["last_ok_date"], today)

    def test_progressive_retry_ladder_failures(self):
        """验证第 1~7 次失败时计算梯级递增的下次重试时刻，且不触发熔断。"""
        today = circuit_breaker._bjt_today()
        fixed_now = 1750000000.0

        with mock.patch.object(circuit_breaker, "_bjt_now_ts", return_value=fixed_now):
            for i, expected_delay in enumerate(circuit_breaker.RETRY_INTERVALS, start=1):
                st, tripped = circuit_breaker.record_task_outcome(self.test_task, ok=False)
                self.assertFalse(tripped, f"Attempt {i} should not trip circuit breaker")
                self.assertEqual(st["attempts"], i)
                self.assertFalse(st.get("circuit_broken", False))
                self.assertNotEqual(st.get("status"), "suspended")
                expected_next = fixed_now + expected_delay
                self.assertEqual(st["next_retry_at"], expected_next)

    def test_eighth_failure_trips_circuit_breaker(self):
        """验证单日第 8 次失败瞬间触发熔断停用（8 次为绝对上限）。"""
        today = circuit_breaker._bjt_today()
        # 预置为今日已失败 7 次
        self.mock_state = {
            "attempts": 7,
            "attempt_date": today,
            "status": "active",
            "circuit_broken": False,
        }

        st, tripped = circuit_breaker.record_task_outcome(
            self.test_task, ok=False, output="WAF 403 Forbidden"
        )
        self.assertTrue(tripped)
        self.assertEqual(st["attempts"], 8)
        self.assertTrue(st["circuit_broken"])
        self.assertEqual(st["status"], "suspended")
        self.assertIsNone(st["next_retry_at"])
        self.assertIn("8 次上限", st["suspend_reason"])
        self.assertTrue(circuit_breaker.is_task_suspended(self.test_task))

    def test_cross_day_attempt_reset(self):
        """验证跨日后历史失败次数自动归零。"""
        yesterday = "2026-09-04"
        self.mock_state = {
            "attempts": 5,
            "attempt_date": yesterday,
            "status": "active",
        }

        # 今日查询尝试轮次应为 0
        self.assertEqual(circuit_breaker.get_task_attempts_today(self.test_task), 0)

        # 再次失败时，轮次重新从 1 开始计起
        st, tripped = circuit_breaker.record_task_outcome(self.test_task, ok=False)
        self.assertEqual(st["attempts"], 1)
        self.assertEqual(st["attempt_date"], circuit_breaker._bjt_today())

    def test_resume_task_and_resume_all(self):
        """验证人工修复后重新上线（清除熔断、重置 attempts、状态变为 active）。"""
        today = circuit_breaker._bjt_today()
        self.mock_state = {
            "status": "suspended",
            "circuit_broken": True,
            "attempts": 8,
            "attempt_date": today,
            "suspend_reason": "连续8次失败",
        }

        st = circuit_breaker.resume_task(self.test_task, reason="修复 WAF 绕过规则")
        self.assertEqual(st["status"], "active")
        self.assertFalse(st["circuit_broken"])
        self.assertEqual(st["attempts"], 0)
        self.assertIsNone(st["suspended_at"])
        self.assertIsNone(st["next_retry_at"])
        self.assertFalse(circuit_breaker.is_task_suspended(self.test_task))

        # 批量恢复
        with mock.patch.object(circuit_breaker, "is_task_suspended", side_effect=lambda tid: tid == "agentrouter"):
            with mock.patch.object(circuit_breaker, "resume_task") as mock_resume:
                resumed = circuit_breaker.resume_all_tasks()
                self.assertIn("agentrouter", resumed)
                mock_resume.assert_called_once()

    def test_get_due_retries_and_delay_calculation(self):
        """验证到期重试识别与下次等待秒数计算。"""
        today = circuit_breaker._bjt_today()
        now_ts = 1750000000.0

        tasks_state = {
            "task_ready": {  # 已到期可重试
                "attempt_date": today,
                "attempts": 2,
                "next_retry_at": now_ts - 10,
                "status": "active",
            },
            "task_future": {  # 尚未到期
                "attempt_date": today,
                "attempts": 1,
                "next_retry_at": now_ts + 600,
                "status": "active",
            },
            "task_suspended": {  # 已熔断停用
                "attempt_date": today,
                "attempts": 8,
                "status": "suspended",
                "circuit_broken": True,
            },
            "task_ok": {  # 今日已成功
                "attempt_date": today,
                "last_ok_date": today,
                "status": "active",
            },
        }

        with mock.patch.object(circuit_breaker, "load_circuit_state", side_effect=lambda tid: tasks_state.get(tid, {})):
            with mock.patch.object(circuit_breaker, "_bjt_now_ts", return_value=now_ts):
                pool = ["task_ready", "task_future", "task_suspended", "task_ok"]
                due = circuit_breaker.get_due_retries(pool)
                self.assertEqual(due, ["task_ready"])

                delay = circuit_breaker.get_min_next_retry_delay(pool)
                self.assertEqual(delay, 600)

    def test_evaluate_retry_candidates_workflow(self):
        """验证 CI 步骤调用的 evaluate_retry_candidates 综合评估。"""
        today = circuit_breaker._bjt_today()
        now_ts = 1750000000.0

        tasks_state = {
            "agentrouter": {
                "attempt_date": today,
                "attempts": 2,
                "next_retry_at": now_ts + 900,
                "status": "active",
            },
            "smzdm": {
                "attempt_date": today,
                "attempts": 8,
                "status": "suspended",
                "circuit_broken": True,
            },
            "cloud189": {
                "attempt_date": today,
                "attempts": 1,
                "next_retry_at": now_ts - 30,
                "status": "active",
            },
        }

        with mock.patch.object(circuit_breaker, "load_circuit_state", side_effect=lambda tid: tasks_state.get(tid, {})):
            with mock.patch.object(circuit_breaker, "_bjt_now_ts", return_value=now_ts):
                res = circuit_breaker.evaluate_retry_candidates("agentrouter, smzdm, cloud189")
                self.assertIn("smzdm", res["suspended"])
                self.assertIn("agentrouter", res["retryable"])
                self.assertIn("cloud189", res["retryable"])
                self.assertIn("cloud189", res["due_now"])
                self.assertEqual(res["next_delay_seconds"], 900)

    def test_evaluate_retry_candidates_shared_script_mapping(self):
        """telecom.py 同时服务 telecom 与 telecom-exchange 两个任务：脚本名必须
        映射到全部共用任务，且只评估「今日确有失败」的任务。

        2026-11-05 复盘：旧逻辑只取首个 id 匹配（telecom.py → telecom），把
        QStash 重试接力点到只有陈旧状态的 telecom 上，真正失败的
        telecom-exchange 无人接力，且以 0s 延时回调空转烧 run。"""
        today = circuit_breaker._bjt_today()
        now_ts = 1750000000.0

        tasks_state = {
            # telecom 每日签到：昨日失败留下的陈旧状态（attempt_date 非今日）→ 不参与
            "telecom": {
                "attempt_date": "2020-01-01",
                "attempts": 3,
                "next_retry_at": now_ts - 3600,
                "status": "active",
            },
            # telecom-exchange 抢兑：今日第 2 次失败，下次重试 15 分钟后
            "telecom-exchange": {
                "attempt_date": today,
                "attempts": 2,
                "next_retry_at": now_ts + 900,
                "status": "active",
            },
        }

        with mock.patch.object(circuit_breaker, "load_circuit_state",
                               side_effect=lambda tid: tasks_state.get(tid, {})):
            with mock.patch.object(circuit_breaker, "_bjt_now_ts", return_value=now_ts):
                res = circuit_breaker.evaluate_retry_candidates("telecom.py")
        self.assertEqual(res["retryable"], ["telecom-exchange"])
        self.assertNotIn("telecom", res["retryable"])
        self.assertNotIn("telecom", res["due_now"])
        self.assertEqual(res["next_delay_seconds"], 900)

    def test_evaluate_retry_candidates_ignores_succeeded_today(self):
        """今日失败后已重试成功的任务不再进入重试接力（last_ok_date=today）。"""
        today = circuit_breaker._bjt_today()
        tasks_state = {
            "glados": {
                "attempt_date": today,
                "attempts": 2,
                "next_retry_at": 1750000000.0 - 60,
                "last_ok_date": today,
                "status": "active",
            },
        }
        with mock.patch.object(circuit_breaker, "load_circuit_state",
                               side_effect=lambda tid: tasks_state.get(tid, {})):
            with mock.patch.object(circuit_breaker, "_bjt_now_ts", return_value=1750000000.0):
                res = circuit_breaker.evaluate_retry_candidates("glados.py")
        self.assertEqual(res["retryable"], [])
        self.assertEqual(res["due_now"], [])


class TestCircuitStateKeyIsolation(unittest.TestCase):
    """熔断状态键隔离与旧 notify 键迁移（2026-11-19 复盘）。

    旧实现把熔断状态写进 state:notify:<task>，而 discord_notify 每次运行
    结束用新建字典整键覆盖该键 → status/circuit_broken/next_retry_at 被抹掉，
    resume 失效、status 表格永远「尚未执行」。现改用专属 cb 键。
    """

    def test_state_paths_use_dedicated_cb_key(self):
        with mock.patch.dict(os.environ, {"CAT_CHECKIN_REDIS_PREFIX": "cat_checkin:"}, clear=False):
            redis_key, state_file = circuit_breaker._state_paths("telecom-exchange")
        self.assertEqual(redis_key, "cat_checkin:cb:telecom-exchange")
        self.assertEqual(state_file, ".cb_state_telecom-exchange.json")
        self.assertNotIn("notify", redis_key)

    def test_load_migrates_owned_fields_from_legacy_notify(self):
        """cb 键缺失时一次性认领旧 notify 键中的熔断器字段（含熔断标记，
        防止升级前已停用的任务因换键复活），不带入 notify 展示字段。"""
        legacy = {
            "status": "suspended",
            "circuit_broken": True,
            "suspend_reason": "单日累计失败达 8 次上限",
            "attempts": 8,
            "attempt_date": "2026-11-19",
            "next_retry_at": None,
            "last_ok_date": "2026-11-18",
            "ok_streak": 3,          # notify 展示字段：不得带入
            "warn_texts": ["x"],     # notify 展示字段：不得带入
        }
        with mock.patch.object(circuit_breaker, "_load_cb_state_raw",
                               return_value=({}, True)) as m_load, \
             mock.patch.object(circuit_breaker, "_legacy_notify_state", return_value=legacy):
            st = circuit_breaker.load_circuit_state("smzdm")
        self.assertTrue(st["circuit_broken"])
        self.assertEqual(st["status"], "suspended")
        self.assertEqual(st["attempts"], 8)
        self.assertNotIn("ok_streak", st)
        self.assertNotIn("warn_texts", st)
        # 首个 load 必须读 cb 专属键
        self.assertIn(":cb:smzdm", m_load.call_args[0][0])

    def test_cb_key_authoritative_over_stale_notify_flag(self):
        """cb 键存在即权威：notify 键里 discord_notify 推送熔断卡留下的
        陈旧 circuit_broken 标记不得复活已恢复的任务。"""
        cb = {"status": "active", "circuit_broken": False, "attempts": 0}
        with mock.patch.object(circuit_breaker, "_load_cb_state_raw",
                               return_value=(cb, False)), \
             mock.patch.object(circuit_breaker, "_legacy_notify_state",
                               return_value={"circuit_broken": True}) as m_legacy:
            st = circuit_breaker.load_circuit_state("glados")
        self.assertFalse(st["circuit_broken"])
        m_legacy.assert_not_called()

    def test_resume_survives_notify_overwrite(self):
        """端到端回归：resume 后模拟 discord_notify 整键覆盖 notify 键，
        熔断状态必须不受影响（旧实现在此处复活失败任务/丢失重试排程）。"""
        store: dict = {}

        def fake_raw(redis_key, state_file):
            data = dict(store.get(redis_key, {}))
            return data, (not data)

        def fake_save(redis_key, state_file, state):
            store[redis_key] = dict(state)

        with mock.patch.object(circuit_breaker, "_load_cb_state_raw", side_effect=fake_raw), \
             mock.patch.object(circuit_breaker, "save_kv_state", side_effect=fake_save), \
             mock.patch.object(circuit_breaker, "_legacy_notify_state", return_value={}), \
             mock.patch.object(circuit_breaker, "save_suspended_result_record"), \
             mock.patch("discord_notify.notify_circuit_breaker", return_value=True), \
             mock.patch("builtins.print"):
            circuit_breaker.trip_circuit_breaker("smzdm", reason="测试熔断")
            self.assertTrue(circuit_breaker.is_task_suspended("smzdm"))
            circuit_breaker.resume_task("smzdm", reason="修复后上线")
            # 模拟 notify_task_result 的整键覆盖（只写 notify 键，新建字典）
            store["cat_checkin:state:notify:smzdm"] = {
                "updated_at": "x", "attempt_date": "2026-11-19",
                "attempts": 1, "last_ok_date": "", "fail_streak": 1, "ok_streak": 0,
            }
            self.assertFalse(circuit_breaker.is_task_suspended("smzdm"))
            st = circuit_breaker.load_circuit_state("smzdm")
            self.assertEqual(st["status"], "active")

    def test_cli_status_shows_data_source_and_missing_retry(self):
        """status 表格必须明示数据源；失败但无重试时刻不得显示「到期就绪」。"""
        import io
        st = {"attempt_date": circuit_breaker._bjt_today(), "attempts": 2,
              "status": "active", "next_retry_at": 0}
        buf = io.StringIO()
        with mock.patch.object(circuit_breaker, "load_circuit_state", return_value=st), \
             mock.patch.object(circuit_breaker, "_redis_channel_status",
                               return_value="⚠️ 未配置凭据，仅本地缓存"), \
             mock.patch("sys.stdout", buf):
            circuit_breaker.cli_status("smzdm")
        out = buf.getvalue()
        self.assertIn("数据源", out)
        self.assertIn("未配置凭据", out)
        self.assertIn("未排定", out)
        self.assertNotIn("到期就绪", out)

    def test_no_migration_on_redis_read_failure(self):
        """Redis 读取失败且无本地文件 ≠ 确认缺键：不得回读旧 notify 的陈旧
        熔断标记把已恢复任务重新熔断（PR #34 评审）。"""
        legacy = {"status": "suspended", "circuit_broken": True, "attempts": 8}
        with mock.patch.object(circuit_breaker, "_load_cb_state_raw",
                               return_value=({}, False)), \
             mock.patch.object(circuit_breaker, "_legacy_notify_state",
                               return_value=legacy) as m_legacy:
            st = circuit_breaker.load_circuit_state("smzdm")
        self.assertEqual(st, {})
        m_legacy.assert_not_called()

    def test_migration_when_absence_confirmed(self):
        """确认缺键（纯本地模式文件缺失 / Redis 明确返回 nil）仍正常迁移。"""
        legacy = {"status": "suspended", "circuit_broken": True, "attempts": 8}
        with mock.patch.object(circuit_breaker, "_load_cb_state_raw",
                               return_value=({}, True)), \
             mock.patch.object(circuit_breaker, "_legacy_notify_state", return_value=legacy):
            st = circuit_breaker.load_circuit_state("smzdm")
        self.assertTrue(st["circuit_broken"])

    def test_raw_local_mode_absence_confirmed(self):
        """凭据未配置（纯本地模式）：文件缺失即确认缺键，可迁移。"""
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch("os.path.exists", return_value=False):
            state, absent = circuit_breaker._load_cb_state_raw("cat_checkin:cb:x", ".cb_state_x.json")
        self.assertEqual(state, {})
        self.assertTrue(absent)

    def test_raw_local_file_present_no_redis_probe(self):
        """本地文件可读时直接采用，不探测 Redis（单次读取，无 TOCTOU）。"""
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write('{"status": "active"}')
            path = f.name
        try:
            with mock.patch.dict(os.environ, {}, clear=True):
                state, absent = circuit_breaker._load_cb_state_raw("cat_checkin:cb:x", path)
            self.assertEqual(state["status"], "active")
            self.assertFalse(absent)
        finally:
            os.unlink(path)

    def test_raw_redis_nil_confirms_absence(self):
        """Redis GET 成功但 result 为空（明确 nil）→ 确认缺键。"""
        with mock.patch.dict(os.environ, {"UPSTASH_REDIS_REST_URL": "https://fake",
                                          "UPSTASH_REDIS_REST_TOKEN": "V1.0FAKEtok"}, clear=False), \
             mock.patch("os.path.exists", return_value=False), \
             mock.patch.object(circuit_breaker, "upstash_redis_command",
                               return_value=(True, {"result": None})):
            state, absent = circuit_breaker._load_cb_state_raw("cat_checkin:cb:x", ".cb_state_x.json")
        self.assertEqual(state, {})
        self.assertTrue(absent)

    def test_raw_redis_failure_no_migration(self):
        """Redis GET 失败（ok=False）→ 不确认缺键，不迁移。"""
        with mock.patch.dict(os.environ, {"UPSTASH_REDIS_REST_URL": "https://fake",
                                          "UPSTASH_REDIS_REST_TOKEN": "V1.0FAKEtok"}, clear=False), \
             mock.patch("os.path.exists", return_value=False), \
             mock.patch.object(circuit_breaker, "upstash_redis_command",
                               return_value=(False, "HTTP 500")):
            state, absent = circuit_breaker._load_cb_state_raw("cat_checkin:cb:x", ".cb_state_x.json")
        self.assertEqual(state, {})
        self.assertFalse(absent)

    def test_raw_redis_data_wins_over_local(self):
        """Redis 有数据时远端权威（覆盖本地），不迁移。"""
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write('{"status": "suspended", "attempts": 8}')
            path = f.name
        try:
            with mock.patch.dict(os.environ, {"UPSTASH_REDIS_REST_URL": "https://fake",
                                              "UPSTASH_REDIS_REST_TOKEN": "V1.0FAKEtok"}, clear=False), \
                 mock.patch.object(circuit_breaker, "upstash_redis_command",
                                   return_value=(True, {"result": '{"status": "active", "attempts": 0}'})):
                state, absent = circuit_breaker._load_cb_state_raw("cat_checkin:cb:x", path)
            self.assertEqual(state["status"], "active")
            self.assertFalse(absent)
        finally:
            os.unlink(path)

    def test_raw_redis_non_dict_value_no_migration(self):
        """键存在但值结构不符（如 "[]"）：不是缺键，禁止迁移
        （PR #34 第三轮评审）。"""
        for bad_val in ('[]', '"str"', '123', '{corrupted'):
            with self.subTest(value=bad_val), \
                 mock.patch.dict(os.environ, {"UPSTASH_REDIS_REST_URL": "https://fake",
                                              "UPSTASH_REDIS_REST_TOKEN": "V1.0FAKEtok"}, clear=False), \
                 mock.patch("os.path.exists", return_value=False), \
                 mock.patch.object(circuit_breaker, "upstash_redis_command",
                                   return_value=(True, {"result": bad_val})):
                state, absent = circuit_breaker._load_cb_state_raw("cat_checkin:cb:x", ".cb_state_x.json")
            self.assertEqual(state, {})
            self.assertFalse(absent, f"值 {bad_val!r} 存在但无效，不得确认缺键")


class TestDailyOrchestratorCircuitIntegration(unittest.TestCase):
    """编排器与熔断机制集成测试。"""

    def test_orchestrator_skips_suspended_task_and_returns_zero(self):
        """验证处于熔断停用状态的任务被编排器直接跳过，且不使 orchestrator 返回退出码 1。"""
        import daily_orchestrator

        import time
        orch = daily_orchestrator.Orchestrator()

        # 模拟仅测试 agentrouter，并将其标记为已熔断
        with mock.patch.object(daily_orchestrator, "is_task_suspended", return_value=True):
            with mock.patch.object(daily_orchestrator, "save_suspended_result_record"):
                orch.results.clear()
                # 模拟 event loop 遇到熔断任务
                cfg = {"id": "agentrouter", "script": "agentrouter.py", "name": "AgentRouter"}
                tid = cfg["id"]
                if daily_orchestrator.is_task_suspended(tid):
                    daily_orchestrator.save_suspended_result_record(tid, "已熔断停用，跳过执行")
                    orch.results[tid] = "suspended"

                self.assertEqual(orch.results.get("agentrouter"), "suspended")

                # 验证退出码判定逻辑：suspended 任务不计入 failed，因此退出码为 0
                failed = [k for k, v in orch.results.items() if v is False]
                suspended = [k for k, v in orch.results.items() if v == "suspended"]
                self.assertEqual(len(failed), 0)
                self.assertEqual(len(suspended), 1)

                exit_code = 1 if failed else 0
                self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
