"""Railgun 只签到回归测试：兑换默认关闭、签到链路不受影响；数据均为合成。"""
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

_spec = importlib.util.spec_from_file_location("railgun_under_test", BASE / "railgun.py")
railgun = importlib.util.module_from_spec(_spec)
# dataclass 装饰器在 exec 期间需要按模块名回查 sys.modules
sys.modules[_spec.name] = railgun
_spec.loader.exec_module(railgun)

SYNTHETIC_COOKIE = "koa:sess=V1.0FAKEsynthetic; koa:sess.sig=V1.0FAKEsynthetic-signature"


class TestExchangeDisabledByDefault(unittest.TestCase):
    """2026-11 用户指令：本任务只签到，不再兑换积分。"""

    def test_default_is_off(self):
        with patch.dict("os.environ", {}, clear=False):
            os.environ.pop("RAILGUN_AUTO_EXCHANGE", None)
            self.assertFalse(railgun.Config().auto_exchange)

    def test_env_can_still_opt_in(self):
        with patch.dict("os.environ", {"RAILGUN_AUTO_EXCHANGE": "true"}):
            self.assertTrue(railgun.Config().auto_exchange)

    def test_run_one_never_calls_exchange(self):
        checker = railgun.Checker(Mock(auto_exchange=False, exchange_plan="plan500",
                                       verbose=False))
        api = Mock()
        api.status.return_value = ("10 天", railgun.CHECKIN_SUCCESS)
        api.checkin.return_value = ("签到成功", railgun.CHECKIN_SUCCESS, 5, "ok")
        api.points.return_value = ("100 积分", 100)

        result = checker._run_one(api, SYNTHETIC_COOKIE, 1, "railgun.example")

        api.exchange.assert_not_called()
        self.assertEqual(result.exchange, "未兑换（本任务仅签到）")
        self.assertEqual(result.code, railgun.CHECKIN_SUCCESS)
        self.assertEqual(result.points_total, 100)
        self.assertEqual(result.points, 5)


if __name__ == "__main__":
    unittest.main()