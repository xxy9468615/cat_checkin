#!/usr/bin/env python3
"""daily_orchestrator 回归测试（unittest discovery 自动收集）。

历史事故 1：显式任务模式 hard_deadline=+24h，猫咪放风回程若在数小时后，
orchestrator 原地 sleep 干等（曾 4h），堵死同一并发组的后续 run。
历史事故 2：失败重试梯子（15m~3h）同样在进程内堆等待，run 挂起数小时。
2026-09-06 运行模型改造：重试与领奖回程全部跨 run 延时接力
（QStash checkin_retry / workbuddy_travel_claim / latvi_next_sign +
30 分钟心跳 get-due-retries 兜底），orchestrator 不再为任何未来事件驻留。
"""
import io
import os
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

import daily_orchestrator as orch_mod
from daily_orchestrator import Orchestrator, plan_due_tasks

CFG = {"id": "workbuddy-account-1", "name": "WorkBuddy 账号1", "script": "workbuddy.py"}


class NoWaitTests(unittest.TestCase):
    """编排器不得为任何未来事件（重试/领奖回程）在进程内排队驻留。"""

    def _run(self, out):
        orch = Orchestrator(hard_deadline=time.time() + 86400)
        try:
            with patch("sys.stdout", new_callable=io.StringIO):
                orch._on_task_done(CFG, True, out)
            return orch
        finally:
            orch.executor.shutdown(wait=False, cancel_futures=True)

    def test_travel_event_not_enqueued(self):
        """TRAVEL_EVENT（回程 2h 后）不得排入进程内堆——由 workbuddy 自接力承载。"""
        orch = self._run(f"TRAVEL_EVENT state=traveling arrive_at={int(time.time() + 2 * 3600)}")
        self.assertEqual(len(orch.heap), 0, f"heap={orch.heap}")

    def test_past_travel_event_not_enqueued(self):
        orch = self._run(f"TRAVEL_EVENT state=traveling arrive_at={int(time.time() - 60)}")
        self.assertEqual(len(orch.heap), 0, f"heap={orch.heap}")

    def test_retry_not_enqueued_after_failure(self):
        """失败任务的 next_retry_at 不得压入进程内堆（交由延时接力）。"""
        orch = Orchestrator(hard_deadline=time.time() + 86400)
        try:
            fake_circuit = {"next_retry_at": time.time() + 15 * 60, "attempts": 1, "status": "watching"}
            with patch.object(orch_mod, "record_task_outcome", return_value=(fake_circuit, False)), \
                 patch.object(orch_mod, "notify_task_result"), \
                 patch.object(orch_mod, "notify_unconfigured"), \
                 patch("sys.stdout", new_callable=io.StringIO):
                orch._on_task_done(CFG, False, "boom")
            self.assertEqual(len(orch.heap), 0, f"heap={orch.heap}")
            self.assertEqual(orch.results[CFG["id"]], False)
        finally:
            orch.executor.shutdown(wait=False, cancel_futures=True)


class PlanModeTests(unittest.TestCase):
    """--plan 到期评估：不执行任何子进程，输出与 run 过滤口径一致。"""

    def test_due_only_filters_cooldown_and_signed_latvi(self):
        env = {"CAT_CHECKIN_REDIS_PREFIX": "cat_checkin:test:"}
        with patch.dict(os.environ, env, clear=False), \
             patch.object(orch_mod, "is_task_suspended", return_value=False), \
             patch.object(orch_mod, "_cooldown_due_at",
                          side_effect=lambda cfg: time.time() + 3600 if cfg["id"] == "modelscope" else None), \
             patch.object(orch_mod, "_latvi_signed_today", return_value=True):
            due = plan_due_tasks("modelscope,tencent_cloudstudio,latvi", due_only=True)
        self.assertNotIn("modelscope", due, "冷却未到期的 rolling 任务不应到期")
        self.assertIn("tencent_cloudstudio", due)
        self.assertNotIn("latvi", due, "今日已签的 latvi 不应到期")

    def test_due_only_includes_due_tasks(self):
        with patch.object(orch_mod, "is_task_suspended", return_value=False), \
             patch.object(orch_mod, "_cooldown_due_at", return_value=None), \
             patch.object(orch_mod, "_latvi_signed_today", return_value=False):
            due = plan_due_tasks("modelscope,tencent_cloudstudio,latvi", due_only=True)
        # resolve_execution_queue 对 "modelscope" 按双站配对展开出 modelscope_ai
        self.assertEqual(due, ["modelscope", "modelscope_ai", "tencent_cloudstudio", "latvi"])

    def test_explicit_mode_ignores_cooldown(self):
        """非 due_only（显式列表/主 cron）口径：候选内全部到期（重试列表已预过滤）。"""
        with patch.object(orch_mod, "is_task_suspended", return_value=False):
            due = plan_due_tasks("modelscope,latvi", due_only=False)
        self.assertEqual(due, ["modelscope", "modelscope_ai", "latvi"])

    def test_suspended_tasks_skipped(self):
        with patch.object(orch_mod, "is_task_suspended",
                          side_effect=lambda tid: tid == "modelscope"):
            due = plan_due_tasks("modelscope,juejin", due_only=False)
        # modelscope 熔断跳过；其配对实例 modelscope_ai 独立判定，仍到期
        self.assertEqual(due, ["modelscope_ai", "juejin"])

    def test_auto_plan_skips_successful_today(self):
        """自动全量巡检模式（raw_tasks=""）：今日已成功的任务自动跳过，未成功的任务判定为到期。"""
        fake_successful = {"glados", "smzdm", "telecom"}
        with patch.object(orch_mod, "_get_today_successful_tasks", return_value=fake_successful), \
             patch.object(orch_mod, "is_task_suspended", return_value=False), \
             patch.object(orch_mod, "_latvi_signed_today", return_value=True), \
             patch.object(orch_mod, "_cooldown_due_at", return_value=None), \
             patch.object(orch_mod, "load_circuit_state", return_value={}):
            due = plan_due_tasks("", due_only=False)
        self.assertNotIn("glados", due)
        self.assertNotIn("smzdm", due)
        self.assertNotIn("telecom", due)
        self.assertNotIn("latvi", due)
        self.assertIn("alipan", due)
        self.assertIn("52pojie", due)

    def test_auto_plan_skips_tasks_in_backoff(self):
        """今日失败但处于退避等待期（next_retry_at > now）的任务跳过，等待下次到期。"""
        now = time.time()
        today = orch_mod.bjt_now().strftime("%Y-%m-%d")
        fake_circuit = {
            "attempt_date": today,
            "attempts": 2,
            "next_retry_at": now + 1800,  # 30 分钟后到期
        }
        with patch.object(orch_mod, "_get_today_successful_tasks", return_value=set()), \
             patch.object(orch_mod, "is_task_suspended", return_value=False), \
             patch.object(orch_mod, "_latvi_signed_today", return_value=True), \
             patch.object(orch_mod, "_cooldown_due_at", return_value=None), \
             patch.object(orch_mod, "load_circuit_state",
                          side_effect=lambda tid: fake_circuit if tid == "52pojie" else {}):
            due = plan_due_tasks("", due_only=False)
        self.assertNotIn("52pojie", due, "处于重试退避冷却期的任务不应立即到期")
        self.assertIn("alipan", due)

    def test_auto_plan_due_only_night_skips_regular_tasks(self):
        """夜间（00:00~06:59 BJT）心跳模式：不偷跑常规单日任务，仅允许 rolling 任务与未签 latvi。"""
        from datetime import datetime
        fake_bjt_night = datetime(2026, 9, 11, 2, 30, 0, tzinfo=orch_mod.BJT)
        with patch.object(orch_mod, "bjt_now", return_value=fake_bjt_night), \
             patch.object(orch_mod, "_get_today_successful_tasks", return_value=set()), \
             patch.object(orch_mod, "is_task_suspended", return_value=False), \
             patch.object(orch_mod, "_latvi_signed_today", return_value=False), \
             patch.object(orch_mod, "_cooldown_due_at", return_value=None), \
             patch.object(orch_mod, "load_circuit_state", return_value={}):
            due = plan_due_tasks("", due_only=True)
        self.assertNotIn("52pojie", due, "夜间心跳不应提前执行常规单日任务")
        self.assertNotIn("smzdm", due, "夜间心跳不应提前执行常规单日任务")
        self.assertNotIn("cloud189", due, "夜间心跳不应提前执行常规单日任务")
        self.assertIn("modelscope", due, "rolling 任务应按冷却评估")
        self.assertIn("latvi", due, "未签到的 latvi 应到期")

    def test_auto_plan_due_only_daytime_includes_missed_tasks(self):
        """白日（>=07:00 BJT）心跳模式：未成功的常规任务视为漏跑自愈，允许补跑。"""
        from datetime import datetime
        fake_bjt_day = datetime(2026, 9, 11, 9, 30, 0, tzinfo=orch_mod.BJT)
        with patch.object(orch_mod, "bjt_now", return_value=fake_bjt_day), \
             patch.object(orch_mod, "_get_today_successful_tasks", return_value={"smzdm"}), \
             patch.object(orch_mod, "is_task_suspended", return_value=False), \
             patch.object(orch_mod, "_latvi_signed_today", return_value=True), \
             patch.object(orch_mod, "_cooldown_due_at", return_value=None), \
             patch.object(orch_mod, "load_circuit_state", return_value={}):
            due = plan_due_tasks("", due_only=True)
        self.assertNotIn("smzdm", due, "今日已成功的任务应跳过")
        self.assertIn("52pojie", due, "白日心跳模式下未成功的常规任务应触发漏跑自愈")


if __name__ == "__main__":
    unittest.main()
