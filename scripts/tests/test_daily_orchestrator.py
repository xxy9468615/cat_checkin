#!/usr/bin/env python3
"""daily_orchestrator 回归测试（unittest discovery 自动收集）。

历史事故 1：显式任务模式 hard_deadline=+24h，猫咪放风回程若在数小时后，
orchestrator 原地 sleep 干等（曾 4h），堵死同一并发组的后续 run。
历史事故 2：失败重试梯子（15m~3h）同样在进程内堆等待，run 挂起数小时。
2026-09-06 运行模型改造：重试与领奖回程全部跨 run 延时接力
（QStash checkin_retry / workbuddy_travel_claim +
30 分钟心跳 get-due-retries 兜底），orchestrator 不再为任何未来事件驻留。
"""
import io
import os
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE = Path(__file__).resolve().parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

import daily_orchestrator as orch_mod
from daily_orchestrator import Orchestrator, plan_due_tasks

CFG = {"id": "workbuddy-account-1", "name": "WorkBuddy 账号1", "script": "workbuddy.py"}


class OutputSecurityTests(unittest.TestCase):
    def test_child_lines_are_attributed_and_controls_escaped(self):
        payload = "签到失败\n[OK] [other] done\r\x1b[2K\x00\x85\u2028\u202e"
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}), \
             patch("sys.stdout", new_callable=io.StringIO) as buf:
            orch_mod._print_task_output("glados", payload)
        self.assertEqual(buf.getvalue(),
                         "[glados] | 签到失败\n"
                         "[glados] | [OK] [other] done\\r\\u001b[2K\\u0000\\u0085\\u2028\\u202e\n")

    def test_actions_commands_are_disabled_around_child_output(self):
        payload = "::error::forged\n::warning::forged\n::guessed-token::\n::add-mask::hidden"
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}), \
             patch("sys.stdout", new_callable=io.StringIO) as buf:
            orch_mod._print_task_output("glados", payload)
            orch_mod._print_task_output("glados", "ordinary output")
        lines = buf.getvalue().splitlines()
        token = lines[0].removeprefix("::stop-commands::")
        self.assertEqual(len(token), 64)
        self.assertEqual(lines[1:5], [f"[glados] | {line}" for line in payload.splitlines()])
        self.assertEqual(lines[5], f"::{token}::")
        self.assertNotEqual(lines[6], lines[0])
        self.assertEqual(lines[8], f"::{lines[6].removeprefix('::stop-commands::')}::")

    def test_completion_keeps_original_output_for_consumers(self):
        out = "签到失败\n::error::forged\r\x1b[2K"
        orch = Orchestrator()
        try:
            with patch.object(orch_mod, "record_task_outcome", return_value=({}, False)) as record, \
                 patch.object(orch_mod, "notify_task_result") as notify, \
                 patch.object(orch_mod, "_print_task_output") as display, \
                 patch("sys.stdout", new_callable=io.StringIO):
                orch._on_task_done(CFG, False, out)
            display.assert_called_once_with(CFG["id"], out)
            self.assertEqual(record.call_args.kwargs["output"], out)
            self.assertEqual(notify.call_args.kwargs["output"], out)
        finally:
            orch.executor.shutdown(wait=False, cancel_futures=True)


class NoWaitTests(unittest.TestCase):
    """编排器不得为任何未来事件（重试/领奖回程）在进程内排队驻留。"""

    def _run(self, out):
        orch = Orchestrator()
        try:
            with patch.object(orch_mod, "record_task_outcome", return_value=({}, False)), \
                 patch.object(orch_mod, "notify_task_result"), \
                 patch.object(orch_mod, "notify_unconfigured"), \
                 patch("sys.stdout", new_callable=io.StringIO):
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
        orch = Orchestrator()
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

    def test_plan_none_or_empty_returns_empty(self):
        """显式传入 none/empty/null 时不抛出 ValueError，安全返回空到期任务列表。"""
        self.assertEqual(plan_due_tasks("none"), [])
        self.assertEqual(plan_due_tasks("NONE"), [])
        self.assertEqual(plan_due_tasks("empty"), [])
        self.assertEqual(plan_due_tasks("null"), [])
        from task_registry import resolve_execution_queue
        self.assertEqual(resolve_execution_queue("none"), [])
        self.assertEqual(resolve_execution_queue("NONE"), [])
        self.assertEqual(resolve_execution_queue(""), [])

    def test_due_only_filters_cooldown(self):
        env = {"CAT_CHECKIN_REDIS_PREFIX": "cat_checkin:test:"}
        # 冷却样例模拟 rolling 元数据（用 juejin 作冷却样例、glados 作到期样例）。
        with patch.dict(os.environ, env, clear=False), \
             patch.object(orch_mod, "is_task_suspended", return_value=False), \
             patch.object(orch_mod, "_cooldown_due_at",
                          side_effect=lambda cfg: time.time() + 3600 if cfg["id"] == "juejin" else None):
            due = plan_due_tasks("juejin,glados", due_only=True)
        self.assertNotIn("juejin", due, "冷却未到期的 rolling 任务不应到期")
        self.assertIn("glados", due)

    def test_cooldown_due_at_reads_dedicated_rolling_key(self):
        """rolling 冷却读取专用 state:rolling: 键——不得复用 notify 状态键。

        notify 键在每次任务结束后被 orchestrator 的 notify 状态同步整键覆盖，
        last_credit_ts 会被抹掉 → rolling 冷却静默失效（2026-11-05 复盘：
        telecom-exchange 的「场次窗口前 30 分钟」自排程因此从未生效）。"""
        captured = {}

        def fake_load(redis_key, state_file, **kw):
            captured["redis_key"] = redis_key
            captured["state_file"] = state_file
            captured["local_authoritative"] = kw.get("local_authoritative", False)
            return {"last_credit_ts": time.time() - 3600}

        cfg = {"id": "telecom-exchange", "sched": {"type": "rolling", "period_h": 24}}
        env = {"CAT_CHECKIN_REDIS_PREFIX": "cat_checkin:"}
        with patch.dict(os.environ, env, clear=False), \
             patch("common.load_kv_state", side_effect=fake_load):
            due_at = orch_mod._cooldown_due_at(cfg)
        self.assertIsNotNone(due_at)
        self.assertEqual(captured["redis_key"], "cat_checkin:state:rolling:telecom-exchange")
        self.assertEqual(captured["state_file"], ".rolling_state_telecom-exchange.json")
        self.assertTrue(captured["local_authoritative"],
                        "rolling 冷却本地新写入不得被远端旧值覆盖（PR #34 终局自审）")

    def test_cooldown_due_at_legacy_notify_key_fallback(self):
        """新 rolling 键无状态时只读回退旧 notify 键的 last_credit_ts。

        一次性兼容（不回写）：旧实现把排程与 notify 状态共键，仅当任务进程在
        「排程写入」与「notify 同步」之间崩溃时旧键才残留有效时间戳。"""
        calls = []
        fixed_ts = 1750000000.0

        def fake_load(redis_key, state_file, **kw):
            calls.append((redis_key, state_file))
            if "state:rolling:" in redis_key:
                return {}
            return {"last_credit_ts": fixed_ts}

        cfg = {"id": "telecom-exchange", "sched": {"type": "rolling", "period_h": 24}}
        with patch.dict(os.environ, {"CAT_CHECKIN_REDIS_PREFIX": "cat_checkin:"}, clear=False), \
             patch("common.load_kv_state", side_effect=fake_load):
            due_at = orch_mod._cooldown_due_at(cfg)
        self.assertEqual(due_at, fixed_ts + 24 * 3600)
        self.assertEqual(calls, [
            ("cat_checkin:state:rolling:telecom-exchange", ".rolling_state_telecom-exchange.json"),
            ("cat_checkin:state:notify:telecom-exchange", ".notify_state_telecom-exchange.json"),
        ])

    def test_cooldown_due_at_non_numeric_fallback(self):
        """rolling 状态中 last_credit_ts 为非数字异常值时，安全回退到 legacy 键，
        避免抛出异常提前返回 None（评审指认）。"""
        calls = []
        fixed_ts = 1750000000.0

        def fake_load(redis_key, state_file, **kw):
            calls.append((redis_key, state_file))
            if "state:rolling:" in redis_key:
                return {"last_credit_ts": "corrupted_timestamp"}
            return {"last_credit_ts": fixed_ts}

        cfg = {"id": "telecom-exchange", "sched": {"type": "rolling", "period_h": 24}}
        with patch.dict(os.environ, {"CAT_CHECKIN_REDIS_PREFIX": "cat_checkin:"}, clear=False), \
             patch("common.load_kv_state", side_effect=fake_load):
            due_at = orch_mod._cooldown_due_at(cfg)
        self.assertEqual(due_at, fixed_ts + 24 * 3600)
        self.assertEqual(calls, [
            ("cat_checkin:state:rolling:telecom-exchange", ".rolling_state_telecom-exchange.json"),
            ("cat_checkin:state:notify:telecom-exchange", ".notify_state_telecom-exchange.json"),
        ])

    def test_cooldown_due_at_non_rolling_and_missing_state(self):
        """非 rolling 任务与无状态场景均返回 None（视为已到期）。"""
        with patch.dict(os.environ, {"CAT_CHECKIN_REDIS_PREFIX": "cat_checkin:"}, clear=False), \
             patch("common.load_kv_state", side_effect=AssertionError("非 rolling 任务不应读取状态")):
            self.assertIsNone(orch_mod._cooldown_due_at({"id": "glados", "sched": {"type": "daily"}}))
            self.assertIsNone(orch_mod._cooldown_due_at({"id": "glados"}))
        with patch.dict(os.environ, {"CAT_CHECKIN_REDIS_PREFIX": "cat_checkin:"}, clear=False), \
             patch("common.load_kv_state", return_value={}):
            self.assertIsNone(orch_mod._cooldown_due_at(
                {"id": "telecom-exchange", "sched": {"type": "rolling", "period_h": 24}}))

    def test_due_only_includes_due_tasks(self):
        with patch.object(orch_mod, "is_task_suspended", return_value=False), \
             patch.object(orch_mod, "_cooldown_due_at", return_value=None):
            due = plan_due_tasks("juejin,glados", due_only=True)
        self.assertEqual(due, ["juejin", "glados"])

    def test_explicit_mode_ignores_cooldown(self):
        """非 due_only（显式列表/主 cron）口径：候选内全部到期（重试列表已预过滤）。

        原 modelscope → modelscope_ai 同脚本双实例展开覆盖已随 2026-10-28 退役移除。
        """
        with patch.object(orch_mod, "is_task_suspended", return_value=False):
            due = plan_due_tasks("juejin,glados", due_only=False)
        self.assertEqual(due, ["juejin", "glados"])

    def test_suspended_tasks_skipped(self):
        with patch.object(orch_mod, "is_task_suspended",
                          side_effect=lambda tid: tid == "juejin"):
            due = plan_due_tasks("juejin,glados", due_only=False)
        # 熔断任务跳过，其余照常到期
        self.assertEqual(due, ["glados"])

    def test_auto_plan_skips_successful_today(self):
        """自动全量巡检模式（raw_tasks=""）：今日已成功的任务自动跳过，未成功的任务判定为到期。"""
        fake_successful = {"glados", "smzdm", "telecom"}
        with patch.object(orch_mod, "_get_today_successful_tasks", return_value=fake_successful), \
             patch.object(orch_mod, "is_task_suspended", return_value=False), \
             patch.object(orch_mod, "_cooldown_due_at", return_value=None), \
             patch.object(orch_mod, "load_circuit_state", return_value={}):
            due = plan_due_tasks("", due_only=False)
        self.assertNotIn("glados", due)
        self.assertNotIn("smzdm", due)
        self.assertNotIn("telecom", due)
        self.assertIn("alipan", due)
        self.assertIn("52pojie", due)

    def test_auto_plan_skips_tasks_in_backoff(self):
        """今日失败但处于退避等待期（next_retry_at > now）的任务跳过，等待下次到期。

        固定时钟：构造 fake_circuit 与 plan_due_tasks 内部取 today/now 必须
        同源，否则跨北京时间午夜时 attempt_date 失配、退避断言假红
        （PR #34 第十三轮评审指认）。"""
        from datetime import datetime, timezone
        fixed_dt = datetime(2026, 11, 19, 14, 0, 0, tzinfo=orch_mod.BJT)
        now = fixed_dt.timestamp()
        today = fixed_dt.strftime("%Y-%m-%d")
        fake_circuit = {
            "attempt_date": today,
            "attempts": 2,
            "next_retry_at": now + 1800,  # 30 分钟后到期
        }
        with patch.object(orch_mod, "bjt_now", return_value=fixed_dt), \
             patch.object(orch_mod.time, "time", return_value=now), \
             patch.object(orch_mod, "_get_today_successful_tasks", return_value=set()), \
             patch.object(orch_mod, "is_task_suspended", return_value=False), \
             patch.object(orch_mod, "_cooldown_due_at", return_value=None), \
             patch.object(orch_mod, "load_circuit_state",
                          side_effect=lambda tid: fake_circuit if tid == "52pojie" else {}):
            due = plan_due_tasks("", due_only=False)
        self.assertNotIn("52pojie", due, "处于重试退避冷却期的任务不应立即到期")
        self.assertIn("alipan", due)

    def test_auto_plan_rolling_success_does_not_block_next_window(self):
        """rolling 任务白天终局（ok=True）不得屏蔽当晚 23:30 的次日 0 点场预检
        （PR #34 评审）：成功日期属于上一场次；冷却到期检查仍然生效。"""
        with patch.object(orch_mod, "_get_today_successful_tasks",
                          return_value={"telecom-exchange", "glados"}), \
             patch.object(orch_mod, "is_task_suspended", return_value=False), \
             patch.object(orch_mod, "_cooldown_due_at", return_value=None), \
             patch.object(orch_mod, "load_circuit_state", return_value={}):
            due = plan_due_tasks("", due_only=False)
        self.assertIn("telecom-exchange", due, "rolling 自排程到期优先于今日成功去重")
        self.assertNotIn("glados", due, "常规任务今日成功仍跳过")

    def test_auto_plan_rolling_cooldown_still_blocks(self):
        """rolling 豁免只针对「今日成功」去重：冷却未到期仍拦截。"""
        with patch.object(orch_mod, "_get_today_successful_tasks",
                          return_value={"telecom-exchange"}), \
             patch.object(orch_mod, "is_task_suspended", return_value=False), \
             patch.object(orch_mod, "_cooldown_due_at",
                          side_effect=lambda cfg: time.time() + 3600
                          if cfg["id"] == "telecom-exchange" else None), \
             patch.object(orch_mod, "load_circuit_state", return_value={}):
            due = plan_due_tasks("", due_only=False)
        self.assertNotIn("telecom-exchange", due)

    def test_auto_plan_rolling_ignores_framework_backoff(self):
        """rolling 任务节奏由自排程 due_at 全权决定：框架退避梯子不得把
        23:30 预检推迟到梯子时刻（PR #34 评审配套）。固定时钟防跨午夜假红。"""
        from datetime import datetime
        fixed_dt = datetime(2026, 11, 19, 14, 0, 0, tzinfo=orch_mod.BJT)
        now = fixed_dt.timestamp()
        today = fixed_dt.strftime("%Y-%m-%d")
        fake_circuit = {"attempt_date": today, "attempts": 2, "next_retry_at": now + 1800}
        with patch.object(orch_mod, "bjt_now", return_value=fixed_dt), \
             patch.object(orch_mod.time, "time", return_value=now), \
             patch.object(orch_mod, "_get_today_successful_tasks", return_value=set()), \
             patch.object(orch_mod, "is_task_suspended", return_value=False), \
             patch.object(orch_mod, "_cooldown_due_at", return_value=None), \
             patch.object(orch_mod, "load_circuit_state",
                          side_effect=lambda tid: fake_circuit
                          if tid in ("telecom-exchange", "52pojie") else {}):
            due = plan_due_tasks("", due_only=False)
        self.assertIn("telecom-exchange", due, "rolling 到期不受框架退避梯子约束")
        self.assertNotIn("52pojie", due, "常规任务退避梯子仍然生效")

    def test_auto_plan_due_only_night_skips_regular_tasks(self):
        """夜间（00:00~06:59 BJT）心跳模式：不偷跑常规单日任务，仅允许 rolling 任务。"""
        from datetime import datetime
        fake_bjt_night = datetime(2026, 9, 11, 2, 30, 0, tzinfo=orch_mod.BJT)
        with patch.object(orch_mod, "bjt_now", return_value=fake_bjt_night), \
             patch.object(orch_mod, "_get_today_successful_tasks", return_value=set()), \
             patch.object(orch_mod, "is_task_suspended", return_value=False), \
             patch.object(orch_mod, "_cooldown_due_at", return_value=None), \
             patch.object(orch_mod, "load_circuit_state", return_value={}):
            due = plan_due_tasks("", due_only=True)
        self.assertNotIn("52pojie", due, "夜间心跳不应提前执行常规单日任务")
        self.assertNotIn("smzdm", due, "夜间心跳不应提前执行常规单日任务")
        self.assertNotIn("cloud189", due, "夜间心跳不应提前执行常规单日任务")
        # telecom-exchange 为 rolling 自排程任务，夜间心跳允许到期
        self.assertIn("telecom-exchange", due, "rolling 任务应被夜间心跳放行")

    def test_auto_plan_due_only_daytime_includes_missed_tasks(self):
        """白日（>=07:00 BJT）心跳模式：未成功的常规任务视为漏跑自愈，允许补跑。"""
        from datetime import datetime
        fake_bjt_day = datetime(2026, 9, 11, 9, 30, 0, tzinfo=orch_mod.BJT)
        with patch.object(orch_mod, "bjt_now", return_value=fake_bjt_day), \
             patch.object(orch_mod, "_get_today_successful_tasks", return_value={"smzdm"}), \
             patch.object(orch_mod, "is_task_suspended", return_value=False), \
             patch.object(orch_mod, "_cooldown_due_at", return_value=None), \
             patch.object(orch_mod, "load_circuit_state", return_value={}):
            due = plan_due_tasks("", due_only=True)
        self.assertNotIn("smzdm", due, "今日已成功的任务应跳过")
        self.assertIn("52pojie", due, "白日心跳模式下未成功的常规任务应触发漏跑自愈")

    def test_default_timeline_enqueues_suspended_task(self):
        """熔断停用任务须入队以写入「已熔断停用」结果记录，避免日报误报「待执行」。"""
        orch = MagicMock()
        with patch.object(orch_mod, "plan_due_tasks", return_value=["juejin"]), \
             patch.object(orch_mod, "_get_today_successful_tasks", return_value=set()), \
             patch.object(orch_mod, "is_task_suspended",
                          side_effect=lambda tid: tid == "aistudio"), \
             patch("sys.stdout", new_callable=io.StringIO) as buf:
            orch_mod.build_default_timeline(orch)

        pushed = [c.args[2]["id"] for c in orch.push.call_args_list]
        self.assertIn("juejin", pushed, "到期任务应入队")
        self.assertIn("aistudio", pushed, "熔断停用任务应入队以留痕")
        self.assertIn("Suspended tasks", buf.getvalue())

    def test_default_timeline_skips_suspended_but_succeeded_today(self):
        """今日已成功、事后才熔断的任务不得被覆盖为熔断记录。"""
        orch = MagicMock()
        with patch.object(orch_mod, "plan_due_tasks", return_value=[]), \
             patch.object(orch_mod, "_get_today_successful_tasks", return_value={"aistudio"}), \
             patch.object(orch_mod, "is_task_suspended",
                          side_effect=lambda tid: tid == "aistudio"), \
             patch("sys.stdout", new_callable=io.StringIO):
            orch_mod.build_default_timeline(orch)

        pushed = [c.args[2]["id"] for c in orch.push.call_args_list]
        self.assertNotIn("aistudio", pushed)


class ResetCircuitOutputTests(unittest.TestCase):
    """--reset-circuit 恢复输出必须检查 resume 结果，未确认不得报「已重置上线」
    （PR #34 第十六轮评审）。"""

    def _run_main(self, argv, resume_ret):
        buf = io.StringIO()
        with patch.object(sys, "argv", argv), \
             patch.object(orch_mod, "resume_task", return_value=resume_ret), \
             patch.object(orch_mod, "plan_due_tasks", return_value=[]), \
             patch.object(orch_mod, "check_daily_report_needed", return_value=False), \
             patch("sys.stdout", buf):
            try:
                orch_mod.main()
            except SystemExit:
                pass
        return buf.getvalue()

    def test_reset_unconfirmed_not_reported_success(self):
        out = self._run_main(
            ["orch", "--reset-circuit-tasks", "smzdm", "--plan"],
            {orch_mod._CB_READ_FAILED: True})
        self.assertNotIn("已重置上线", out)
        self.assertIn("恢复未确认", out)

    def test_reset_confirmed_reports_success(self):
        out = self._run_main(
            ["orch", "--reset-circuit-tasks", "smzdm", "--plan"],
            {"status": "active"})
        self.assertIn("已重置上线", out)
        self.assertNotIn("恢复未确认", out)


if __name__ == "__main__":
    unittest.main()
