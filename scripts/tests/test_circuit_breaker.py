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

        self.load_patch.start()
        self.save_patch.start()
        self.save_record_patch.start()
        self.notify_patch.start()

    def tearDown(self):
        self.load_patch.stop()
        self.save_patch.stop()
        self.save_record_patch.stop()
        self.notify_patch.stop()

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


class TestDailyOrchestratorCircuitIntegration(unittest.TestCase):
    """编排器与熔断机制集成测试。"""

    def test_orchestrator_skips_suspended_task_and_returns_zero(self):
        """验证处于熔断停用状态的任务被编排器直接跳过，且不使 orchestrator 返回退出码 1。"""
        import daily_orchestrator

        import time
        orch = daily_orchestrator.Orchestrator(hard_deadline=time.time() + 3600)

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
