#!/usr/bin/env python3
"""workbuddy 回归测试（在仓库根目录运行：python3 scripts/tests/test_workbuddy.py）。

历史事故 1（bfb5805 实弹）：_get_credit_expiry 的 _first_num(acc=a, *keys)
被位置调用时第一个 key 填进了 acc——'str' object has no attribute 'get'，
每轮必现且异常无堆栈难定位。教训：默认参数绑定循环变量 + 位置调用 = 隐雷。
历史事故 2（#33319485658 实弹）：端点返回 data 为字符串等非 dict 形态时
裸 .get() 崩——全端点已加 _resp_dict/_data_dict 类型守卫。
"""
import sys
from unittest import mock
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

import workbuddy as wb

failures = []


def check(name, cond, detail=""):
    print(f"  {'✅' if cond else '❌'} {name}" + ("" if cond else f" — {detail}"))
    if not cond:
        failures.append(name)


class FakeResp:
    def __init__(self, payload, code=200):
        self._p, self.code = payload, code

    def json(self, default=None):
        return self._p


def _http(payload, code=200):
    h = mock.MagicMock()
    h.request = mock.MagicMock(return_value=FakeResp(payload, code))
    return h


def main() -> int:
    # 1) 算力到期：正常包 + 个人体验版剔除 + 字符串元素容错
    body = {
        "code": 0,
        "data": {"Response": {"Data": {"Accounts": [
            {"PackageName": "个人体验版", "CapacityType": 4, "CycleCapacityRemain": 500},
            {"PackageName": "新手包", "CapacityType": 0, "CapacityRemainPrecise": "1500",
             "DeductionEndTime": "2026-09-02 12:00:00"},
            "纯字符串元素也不该炸",
        ]}}},
    }
    msg = wb._get_credit_expiry(_http(body), "fake-cred")
    check("算力到期解析", "1500 算力" in msg and "09-02" in msg and "用掉否则作废" in msg, repr(msg))

    # 2) 无临期包 → 空串
    far = {
        "code": 0,
        "data": {"Response": {"Data": {"Accounts": [
            {"CapacityType": 0, "CapacityRemainPrecise": "1500", "DeductionEndTime": "2027-09-02 12:00:00"},
        ]}}},
    }
    check("无临期包返回空串", wb._get_credit_expiry(_http(far), "fake") == "")

    # 3) 响应非 JSON 对象 / code 非 0 → 空串不炸
    check("响应非对象不炸", wb._get_credit_expiry(_http("waf page"), "fake") == "")
    check("code 非 0 不炸", wb._get_credit_expiry(_http({"code": 5, "msg": "x"}), "fake") == "")
    check("HTTP 非 200 不炸", wb._get_credit_expiry(_http({}, code=502), "fake") == "")

    # 4) refresh：错误体 data 为字符串（12153 形态）→ 干净的 RuntimeError 而非 AttributeError
    h = _http({"code": 12153, "data": "Session doesn't have required client", "msg": "invalid_grant"})
    try:
        wb._refresh_access_token(h, "bad-token")
        check("refresh 错误体 data 为字符串", False, "未抛异常")
    except RuntimeError as e:
        check("refresh 错误体 data 为字符串", "续期失败" in str(e) and "12153" in str(e), str(e))

    print(f"\n{'ALL GREEN' if not failures else 'FAILED'}: {6 - len(failures)}/6 passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
