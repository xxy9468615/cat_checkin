#!/usr/bin/env python3
"""telecom 日报解析回归：转盘/抢兑故障文案不得被包装成 reward 徽章。

PR #34 终局自审指认：wheel_daily_draws 返回「转盘提交故障(...)」时，旧解析器
把整段 lottery_res 无条件塞进 reward 徽章，故障在日报里彻底消失（假成功）。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from report_fields import extract_for  # noqa: E402


class TelecomWheelReportTests(unittest.TestCase):
    def test_wheel_failure_not_reward_badge(self):
        out = (
            "👤 用户: 【189****5678】\n"
            "• 签到: 【成功】 (+20 金豆)\n"
            "• 抽奖: 【签到大转盘: 转盘提交故障(抽奖请求已超时，请稍后重试)】\n"
            "❌ 签到大转盘: 转盘提交故障(抽奖请求已超时，请稍后重试)\n"
        )
        r = extract_for("telecom.py", out)
        reward_texts = [t for k, t in r["badges"] if k == "reward"]
        self.assertFalse(any("故障" in t or "超时" in t for t in reward_texts),
                         f"故障文案不得进 reward 徽章: {reward_texts}")
        self.assertTrue(r["error_lines"], "❌ 故障行必须进 error_lines")
        self.assertTrue(any("故障" in e for e in r["error_lines"]))

    def test_wheel_prizes_still_reward_badge(self):
        out = (
            "👤 用户: 【189****5678】\n"
            "• 签到: 【成功】 (+20 金豆)\n"
            "• 抽奖: 【签到大转盘: 88金豆、188金豆】\n"
        )
        r = extract_for("telecom.py", out)
        reward_texts = [t for k, t in r["badges"] if k == "reward"]
        self.assertTrue(any("88金豆" in t for t in reward_texts),
                        f"真实奖品仍应进 reward 徽章: {reward_texts}")
        self.assertFalse(r["error_lines"])

    def test_wheel_field_anomaly_not_reward(self):
        out = (
            "👤 用户: 【189****5678】\n"
            "• 签到: 【成功】\n"
            "• 抽奖: 【签到大转盘: 转盘状态字段异常(缺 remainCount)】\n"
            "❌ 签到大转盘: 转盘状态字段异常(缺 remainCount)\n"
        )
        r = extract_for("telecom.py", out)
        reward_texts = [t for k, t in r["badges"] if k == "reward"]
        self.assertFalse(any("字段异常" in t for t in reward_texts))
        self.assertTrue(r["error_lines"])


if __name__ == "__main__":
    unittest.main()