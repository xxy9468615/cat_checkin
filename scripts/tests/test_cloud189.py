#!/usr/bin/env python3
"""天翼云盘（cloud189）签到脚本自检与单元测试。

回归覆盖：
1. X.509 SubjectPublicKeyInfo 解析（曾因 body/off 偏移复用导致 IndexError，
   密码盲登因此崩溃 → 恶性回退到 Cookie 模式）
2. RSA PKCS#1 v1.5 加密输出格式（even-length hex，与 platformlogin.js 的
   RSAKey.encrypt 返回 hex 对齐）
3. 待补：loginSubmit 表单字段（epd 等）——依赖外网与真实账号，不在此单测覆盖。
4. 绿色成长体系（m.cloud.189.cn/market/*）：任务上报幂等、等级权益领取边界、
   鉴权降级路径、文案安全（不得含失败关键词 / 不得被当成签到失败行）。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import importlib

cloud189 = importlib.import_module("cloud189")

# 线上 encryptConf.do 返回的真实 RSA 公钥（SubjectPublicKeyInfo base64，1024 位）。
PUBKEY_1024 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCZLyV4gHNDUGJMZoOcYauxmNEsKrc0TlLeBEVVIIQNzG4WqjimceOj5R9ETwDeeSN3yejAKLGHgx83lyy2wBjvnbfm/nLObyWwQD/09CmpZdxoFYCH6rdDjRpwZOZ2nXSZpgkZXoOBkfNXNxnN74aXtho2dqBynTw3NFTWyQl8BQIDAQAB"
)


class TestCloud189(unittest.TestCase):
    def test_parse_x509_pubkey_no_indexerror(self):
        """曾因复用外层 off 当 body 偏移而 IndexError，此处验证不再崩溃且解析正确。"""
        n, e = cloud189._parse_x509_pubkey(PUBKEY_1024)
        self.assertEqual(e, 65537)
        self.assertEqual(n.bit_length(), 1024)

    def test_rsa_encrypt_format(self):
        """产出应为 128 字节（256 hex）的纯十六进制，符合 PKCS#1 v1.5。"""
        out = cloud189._rsa_encrypt_hex(PUBKEY_1024, "13800138000")
        self.assertEqual(len(out), 256)
        self.assertRegex(out, r"^[0-9a-f]{256}$")

    def test_rsa_encrypt_differs_per_call(self):
        """随机填充下相同明文两次加密结果不同（确认 PKCS#1 v1.5 盲化生效）。"""
        a = cloud189._rsa_encrypt_hex(PUBKEY_1024, "13800138000")
        b = cloud189._rsa_encrypt_hex(PUBKEY_1024, "13800138000")
        self.assertNotEqual(a, b)

    def test_cloud189_reuses_cn_proxy(self):
        """天翼云盘复用仓库已有的 SMZDM / 52POJIE 等 CN 出口代理。"""
        import os
        from unittest.mock import patch

        env = {
            "SMZDM_PROXY": "socks5://user:pass@112.64.135.45:1080#自建-上海联通",
        }
        with patch.dict(os.environ, env, clear=True):
            proxies = cloud189._get_candidate_proxies()
            self.assertTrue(len(proxies) >= 1)
            self.assertIn("自建-上海联通", proxies[0].name)
            self.assertEqual(proxies[0].protocol, "socks5")

    def test_login_network_failure_message_not_mistaken_as_credential_error(self):
        """HTTP -1（网络层失败）的报错文案不得含"密码错误/验证码"——
        候选轮换循环按这些子串中止，网络故障曾被误判成凭证错误吞掉后续候选。"""
        from unittest.mock import MagicMock, patch

        pub_key = PUBKEY_1024
        enc_resp = MagicMock(code=200)
        enc_resp.json.return_value = {"data": {"pubKey": pub_key, "pre": "{RSA}"}}
        login_page = MagicMock(
            code=200,
            text='<input name="captchaToken" value="ctk">'
                 "<script>var lt='lt123';paramId='pid9';reqId='rid7';</script>",
        )
        fail_resp = MagicMock(code=-1, text="")
        fail_resp.json.return_value = {}

        def fake_request(method, url, **_kw):
            if "encryptConf.do" in url:
                return enc_resp
            if "unifyLoginForPC" in url:
                return login_page
            return fail_resp  # loginSubmit.do → 网络层 -1

        h = MagicMock()
        h.request.side_effect = fake_request
        with patch.object(cloud189, "_resp_dict", side_effect=lambda r: r.json.return_value):
            with self.assertRaises(RuntimeError) as ctx:
                cloud189._login(h, "13800138000", "pw")
        msg = str(ctx.exception)
        self.assertIn("-1", msg)
        self.assertIn("网络层异常", msg)
        self.assertNotIn("密码错误", msg)
        self.assertNotIn("验证码", msg)

    def test_candidate_queue_continues_after_proxy_network_failure(self):
        """主出口 Errno 101 → 备用出口网络 -1 都应继续轮换到直连，而非中止队列。"""
        from unittest.mock import MagicMock, patch

        ep1 = MagicMock()
        ep1.display_name = "主出口"
        ep1.url = "socks5://127.0.0.1:1081"
        ep2 = MagicMock()
        ep2.display_name = "备用出口"
        ep2.url = "http://127.0.0.1:8888"
        created = []

        def fake_http(follow_redirects=True, proxy="", infer_proxy=True):
            h = MagicMock()
            h.url = proxy
            created.append((proxy, h))
            return h

        def fake_login(h, username, password):
            if h.url == ep1.url:
                raise RuntimeError("获取公钥失败（HTTP -1）：[Errno 101] Network is unreachable")
            if h.url == ep2.url:
                raise RuntimeError("登录失败（-1）：网络层异常，多为代理出口不可用")
            return "session-key"

        with patch.object(cloud189, "_get_candidate_proxies", return_value=[ep1, ep2]), \
             patch.object(cloud189, "Http", side_effect=fake_http), \
             patch.object(cloud189, "_login", side_effect=fake_login), \
             patch.object(cloud189, "_sign", return_value=("签到成功", True)), \
             patch.object(cloud189, "_lotteries", return_value="无"), \
             patch.object(cloud189, "_space", return_value="10G/100G"):
            ok, _summary = cloud189._run_one(1, 1, "13800138000", "pw")

        self.assertTrue(ok)
        # 直连兜底被触达（两个代理都失败后轮换到了 None 候选）
        self.assertIn("", [proxy for proxy, _ in created])

    def test_proxy_isolation_no_socket_pollution(self):
        """验证 SOCKS 代理不会污染全局 socket，直连和 HTTP 代理依然保持原生隔离。"""
        import socket
        from common import Http, _ORIG_SOCKET

        # 实例化 SOCKS 代理 Http
        h_socks = Http(proxy="socks5://user:pass@127.0.0.1:1080#测试")
        self.assertIs(socket.socket, _ORIG_SOCKET)

        # 实例化直连 Http
        h_direct = Http()
        self.assertIs(socket.socket, _ORIG_SOCKET)

        # 实例化 HTTP 代理 Http
        h_http = Http(proxy="http://127.0.0.1:8888#测试HTTP")
        self.assertIs(socket.socket, _ORIG_SOCKET)

    def test_api_url_and_endpoints(self):
        """验证 Open API 鉴权端点与 Web Portal 彻底分离，避免 cookieUserSession 错误。"""
        self.assertEqual(cloud189.API_URL, "https://api.cloud.189.cn")
        self.assertEqual(cloud189.WEB_URL, "https://cloud.189.cn")
        self.assertEqual(cloud189.AUTH_URL, "https://open.e.189.cn")


# ---------- 绿色成长体系（合成夹具，全部 V1.0FAKE 前缀，无任何真实凭据） ----------

SK_FAKE = "V1.0FAKE_SESSION_KEY"

GREEN_TASKS_MIXED = [
    {"taskId": "V1.0FAKE_TASK_AI", "taskName": "使用AI工具", "rewardValue": 20, "status": False},
    {"taskId": "V1.0FAKE_TASK_DONE", "taskName": "已完成任务", "rewardValue": 50, "status": True},
    {"taskId": "V1.0FAKE_TASK_NEWBIE", "taskName": "开启照片自动备份", "rewardValue": 30, "status": False},
]

GREEN_LEVELS = [
    {"levelNo": "LV1", "levelName": "绿色新人", "levelScore": 500, "drawState": True, "levelUrl": ""},
    {"levelNo": "LV2", "levelName": "绿色达人", "levelScore": 1500, "drawState": True, "levelUrl": ""},
    {"levelNo": "LV3", "levelName": "绿色先锋", "levelScore": 3000, "drawState": False, "levelUrl": ""},
]

GREEN_RIGHTS_MIXED = [
    {"prizeId": "V1.0FAKE_P_DRAWABLE", "rightName": "10G空间券", "drawState": False, "rightState": 1, "canDraws": 1, "actionType": 0},
    {"prizeId": "V1.0FAKE_P_DRAWN", "rightName": "已领权益", "drawState": True, "rightState": 3, "canDraws": 0, "actionType": 0},
    {"prizeId": "V1.0FAKE_P_ACTION", "rightName": "去开通会员", "drawState": False, "rightState": 1, "canDraws": 1, "actionType": 3},
]


def _fake_growth_request(routes, calls):
    """按 URL 片段路由的 Http.request 替身，同时记录调用序列供断言。

    common._resp_dict 以 resp.json({}) 取值，故替身的 json 必须接受一个位置参数。
    calls 记录 (method, url, form) 三元组，供断言 POST 的 body 内容。

    routes 的值可以是 dict（固定响应），也可以是 callable（按 query 定制响应）——
    getGreenTaskList 的夹具需要后者，因为服务端是按 taskType 分列表返回的，
    若所有 taskType 都返回同一份混合列表，就等于伪造了一个不存在的服务端行为。
    """
    import urllib.parse as _up
    from types import SimpleNamespace

    def _req(method, url, form=None, **_kw):
        calls.append((method, url, form or {}))
        qs = _up.parse_qs(_up.urlsplit(url).query)
        for key, payload in routes.items():
            if key in url:
                data = payload(qs) if callable(payload) else payload
                return SimpleNamespace(code=200, text=repr(data),
                                      json=lambda *_a, _p=data: _p)
        return SimpleNamespace(code=404, text="{}", json=lambda *_a: {})  # 未注册路径

    return _req


# 服务端按 taskType 分列表：1=新人任务（需 App 操作）、2=AI任务、3=绿动任务、5=气泡任务
GREEN_TASKS_BY_TYPE = {
    "1": [
        {"taskId": "V1.0FAKE_TASK_NEWBIE", "taskName": "开启照片自动备份",
         "rewardValue": 30, "status": False},
    ],
    "2": [
        {"taskId": "V1.0FAKE_TASK_AI", "taskName": "使用AI工具",
         "rewardValue": 20, "status": False},
    ],
    "3": [
        {"taskId": "V1.0FAKE_TASK_GREEN", "taskName": "上传文件",
         "rewardValue": 10, "status": False},
    ],
    "5": [
        {"taskId": "V1.0FAKE_TASK_BUBBLE", "taskName": "成长气泡",
         "rewardValue": 5, "status": False},
    ],
}


def _green_task_routes():
    """构造按 taskType 分发的 getGreenTaskList 夹具。"""

    def _by_type(qs):
        tt = (qs.get("taskType") or [""])[0]
        return {"code": "0", "data": GREEN_TASKS_BY_TYPE.get(tt, []), "message": "ok"}

    return _by_type


class TestCloud189Growth(unittest.TestCase):
    """绿色成长体系：幂等判据、领取边界、鉴权降级、文案安全。"""

    def _resp(self, code="0", data=None):
        return {"code": code, "data": data if data is not None else {}, "message": "ok"}

    # ---- 1. 任务上报：只对 status is False 的项发 doGreenTask ----

    def test_growth_task_only_done_when_status_false(self):
        from unittest.mock import MagicMock
        calls = []
        routes = {
            "getGreenTaskList": _green_task_routes(),
            "doGreenTask": self._resp("0", True),
        }
        h = MagicMock()
        h.request.side_effect = _fake_growth_request(routes, calls)
        text, done, score, manual = cloud189._growth_tasks(h, SK_FAKE)
        posted = [c for c in calls if c[0] == "POST" and "doGreenTask" in c[1]]
        # 三类可自动化任务各 POST 一次；taskType=1 新人任务绝不 POST
        self.assertEqual(len(posted), 3)
        got = sorted(c[2].get("taskId") for c in posted)
        self.assertEqual(got, ["V1.0FAKE_TASK_AI", "V1.0FAKE_TASK_BUBBLE",
                               "V1.0FAKE_TASK_GREEN"])
        for _m, _u, body in posted:
            self.assertNotEqual(body.get("taskId"), "V1.0FAKE_TASK_NEWBIE")
        self.assertEqual(done, 3)
        self.assertEqual(score, 35)              # 20 + 10 + 5
        self.assertEqual(manual, 1)              # 新人任务只进待手动
        self.assertIn("完成 3 项", text)
        self.assertIn("待手动 1 项", text)

    # ---- 2. doGreenTask 成功判据必须是 data is True（规则 9a(1)） ----

    def test_growth_do_task_requires_data_true(self):
        from unittest.mock import MagicMock
        calls = []
        # 返回 "true" 字符串 / null / 空对象均不算成功
        for bad in ("true", None, {}, 1, "1"):
            calls.clear()
            routes = {
                "getGreenTaskList": _green_task_routes(),
                "doGreenTask": self._resp("0", bad),
            }
            h = MagicMock()
            h.request.side_effect = _fake_growth_request(routes, calls)
            _text, done, _s, _m = cloud189._growth_tasks(h, SK_FAKE)
            self.assertEqual(done, 0, f"data={bad!r} 不得计入完成数")

    def test_growth_do_task_accepts_bool_true(self):
        from unittest.mock import MagicMock
        calls = []
        routes = {
            "getGreenTaskList": _green_task_routes(),
            "doGreenTask": self._resp("0", True),
        }
        h = MagicMock()
        h.request.side_effect = _fake_growth_request(routes, calls)
        _text, done, score, _m = cloud189._growth_tasks(h, SK_FAKE)
        self.assertEqual(done, 3)
        self.assertEqual(score, 35)

    def test_growth_do_task_rejects_nonzero_code(self):
        from unittest.mock import MagicMock
        calls = []
        routes = {
            "getGreenTaskList": _green_task_routes(),
            "doGreenTask": self._resp("1002", True),   # code 非 0 → 幂等/拒绝
        }
        h = MagicMock()
        h.request.side_effect = _fake_growth_request(routes, calls)
        _text, done, _s, _m = cloud189._growth_tasks(h, SK_FAKE)
        self.assertEqual(done, 0)

    # ---- 3. 新人任务只报告、不伪造 ----

    def test_growth_newbie_task_reported_not_faked(self):
        from unittest.mock import MagicMock
        calls = []

        def _only_newbie(qs):
            tt = (qs.get("taskType") or [""])[0]
            data = GREEN_TASKS_BY_TYPE["1"] if tt == "1" else []
            return {"code": "0", "data": data, "message": "ok"}

        routes = {
            "getGreenTaskList": _only_newbie,
            "doGreenTask": self._resp("0", True),
        }
        h = MagicMock()
        h.request.side_effect = _fake_growth_request(routes, calls)
        text, done, score, manual = cloud189._growth_tasks(h, SK_FAKE)
        posted = [c for c in calls if c[0] == "POST" and "doGreenTask" in c[1]]
        self.assertEqual(posted, [])
        self.assertEqual((done, score, manual), (0, 0, 1))
        self.assertIn("待手动", text)

    # ---- 4. 等级查询 ----

    def test_growth_level_reports_current_and_next(self):
        from unittest.mock import MagicMock
        calls = []
        routes = {"getGreenLevelList": self._resp("0", {"userScore": 1250, "greenLevelList": GREEN_LEVELS})}
        h = MagicMock()
        h.request.side_effect = _fake_growth_request(routes, calls)
        text, level_no = cloud189._growth_level(h, SK_FAKE)
        self.assertEqual(level_no, "LV2")           # 最后一个 drawState=True
        self.assertIn("绿色达人", text)
        self.assertIn("1250g", text)
        # 「下一级」= 升级到 LV3 所需的门槛，而非 LV2 自己的 levelScore
        self.assertIn("3000g", text)

    def test_growth_level_all_locked_shows_unlocked_text(self):
        from unittest.mock import MagicMock
        calls = []
        levels = [dict(lv, drawState=False) for lv in GREEN_LEVELS]
        routes = {"getGreenLevelList": self._resp("0", {"userScore": 120, "greenLevelList": levels})}
        h = MagicMock()
        h.request.side_effect = _fake_growth_request(routes, calls)
        text, level_no = cloud189._growth_level(h, SK_FAKE)
        self.assertEqual(level_no, "")
        self.assertIn("未解锁", text)
        self.assertIn("500g", text)

    def test_growth_level_network_failure_returns_empty(self):
        from unittest.mock import MagicMock
        calls = []
        # 网络层失败合成响应：code == -1
        from types import SimpleNamespace

        def _req(method, url, **_kw):
            calls.append((method, url))
            return SimpleNamespace(code=-1, text="", json=lambda *_a: {})

        h = MagicMock()
        h.request.side_effect = _req
        text, level_no = cloud189._growth_level(h, SK_FAKE)
        self.assertEqual((text, level_no), ("", ""))

    # ---- 5. 等级权益领取边界 ----

    def _rights_calls(self, rights, level_no="LV2"):
        calls = []
        routes = {
            "getGreenLevelRight": self._resp("0", rights),
            "drawGreenRight": self._resp("0", {"prizeId": "x"}),
        }
        from unittest.mock import MagicMock
        h = MagicMock()
        h.request.side_effect = _fake_growth_request(routes, calls)
        return h, calls

    def test_level_reward_skips_already_drawn(self):
        h, calls = self._rights_calls(GREEN_RIGHTS_MIXED)
        text, claimed, manual = cloud189._level_rewards(h, SK_FAKE, "LV2")
        posted = [c for c in calls if c[0] == "POST" and "drawGreenRight" in c[1]]
        self.assertEqual(len(posted), 1)                     # 仅可领那项
        self.assertEqual(posted[0][2].get("prizeId"), "V1.0FAKE_P_DRAWABLE")
        self.assertEqual(posted[0][2].get("greenLevel"), "LV2")
        self.assertEqual(claimed, 1)
        self.assertEqual(manual, 1)                          # actionType 项计入待手动
        for _m, _u, body in posted:
            self.assertNotEqual(body.get("prizeId"), "V1.0FAKE_P_DRAWN")  # 已领项绝不重复发

    def test_level_reward_skips_right_state_three(self):
        """rightState===3（H5 列表过滤项）与 drawState 等价，同样视为已领。"""
        h, calls = self._rights_calls([
            {"prizeId": "V1.0FAKE_P_RS3", "rightName": "x", "drawState": False,
             "rightState": 3, "actionType": 0},
        ])
        _text, claimed, _manual = cloud189._level_rewards(h, SK_FAKE, "LV2")
        posted = [c for c in calls if c[0] == "POST" and "drawGreenRight" in c[1]]
        self.assertEqual(posted, [])
        self.assertEqual(claimed, 0)

    def test_level_reward_skips_action_type_items(self):
        h, calls = self._rights_calls([
            {"prizeId": "V1.0FAKE_P_A", "rightName": "去使用AI工具", "drawState": False,
             "rightState": 1, "actionType": 2, "jumpKey": "V1.0FAKE_APP"},
        ])
        text, claimed, manual = cloud189._level_rewards(h, SK_FAKE, "LV2")
        posted = [c for c in calls if c[0] == "POST" and "drawGreenRight" in c[1]]
        self.assertEqual(posted, [])
        self.assertEqual((claimed, manual), (0, 1))
        self.assertIn("需前置动作", text)

    def test_level_reward_success_requires_code_zero(self):
        from unittest.mock import MagicMock
        calls = []
        routes = {
            "getGreenLevelRight": self._resp("0", [
                {"prizeId": "V1.0FAKE_P_DRAWABLE", "rightName": "10G", "drawState": False,
                 "rightState": 1, "actionType": 0},
            ]),
            "drawGreenRight": self._resp("9999", None),   # code 非 0 → 不计入
        }
        h = MagicMock()
        h.request.side_effect = _fake_growth_request(routes, calls)
        _text, claimed, _m = cloud189._level_rewards(h, SK_FAKE, "LV2")
        self.assertEqual(claimed, 0)

    def test_level_reward_no_level_returns_degraded(self):
        from unittest.mock import MagicMock
        calls = []
        h = MagicMock()
        h.request.side_effect = _fake_growth_request({}, calls)
        text, claimed, manual = cloud189._level_rewards(h, SK_FAKE, "")
        self.assertEqual((claimed, manual), (0, 0))
        self.assertIn("未开启", text)
        # 不得发起任何请求
        self.assertEqual(calls, [])

    # ---- 6. 文案安全（规则 9a(2) + 防解析器误判账号失败） ----

    _ERROR_KW = ("失败", "失效", "异常", "错误", "401", "403", "超时", "无法", "Traceback")
    _FAIL_SUB = ("签到失败", "处理失败", "登录失败")

    def test_growth_texts_have_no_error_keywords(self):
        """所有成长体系文案既不能含 _ERROR_KW（防误捞 error_lines），
        也不能含「签到失败/处理失败/登录失败」（防 ex_cloud189 清空账号块）。"""
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        scenarios = [
            ({"getGreenLevelList": self._resp("0", {"userScore": 120, "greenLevelList": [
                dict(lv, drawState=False) for lv in GREEN_LEVELS]})}, ""),
            ({"getGreenLevelList": self._resp("0", {"userScore": 1250, "greenLevelList": GREEN_LEVELS})}, "LV2"),
        ]
        for routes, lvl in scenarios:
            h = MagicMock()
            h.request.side_effect = _fake_growth_request(routes, [])
            level_text, _ = cloud189._growth_level(h, SK_FAKE)
            for kw in self._ERROR_KW + self._FAIL_SUB:
                self.assertNotIn(kw, level_text, f"等级文案含禁词 {kw!r}: {level_text}")

        # 鉴权不全的降级文案
        for text in ("未开启（鉴权不全）", "今日无需处理", "待手动 2 项（App 内完成）",
                     "已领 1 项权益", "无可领权益", "待手动 2 项（需前置动作）"):
            for kw in self._ERROR_KW + self._FAIL_SUB:
                self.assertNotIn(kw, text)

    def test_growth_texts_not_parsed_as_signin_failure(self):
        """端到端：成长行经 ex_cloud189 解析后不得进 fail_lines / error_lines。"""
        from report_fields import extract_for
        out = (
            "[1/1] 👤 用户: 【1***4】\n"
            "  • 签到: 【成功】+30M 空间\n"
            "  • 成长任务: 今日无需处理\n"
            "  • 成长任务: 待手动 2 项（App 内完成）\n"
            "  • 绿色等级: LV3 绿色达人 · 绿值 1250g（下一级 1500g）\n"
            "  • 等级奖励: 未开启（鉴权不全）\n"
            "✅ 全部 1 个账号处理完成 (成功 1/1)\n"
        )
        res = extract_for("cloud189.py", out)
        self.assertEqual(res["fail_lines"], [])
        self.assertEqual(res["error_lines"], [])
        self.assertTrue(any("LV3" in ln for ln in res["lines"]))
        # 周期收益进 gains，绝不进 assets（规则 9a(6)）

    def test_growth_gains_not_assets(self):
        from report_fields import extract_for
        out = (
            "[1/1] 👤 用户: 【1***4】\n"
            "  • 成长任务: 完成 2 项 (+40 绿值)\n"
            "  • 绿色等级: LV3 绿色达人 · 绿值 1250g（下一级 1500g）\n"
        )
        res = extract_for("cloud189.py", out)
        self.assertEqual(res["assets"], [])
        self.assertIn(("绿值", 40.0), res["gains"])

    # ---- 7. 成长体系异常不得拖垮账号判定 ----

    def test_growth_failure_does_not_fail_account(self):
        """所有绿色接口 HTTP -1 时账号 ok 仍由 _sign 决定，且输出无禁词。"""
        from unittest.mock import MagicMock, patch
        from types import SimpleNamespace

        def _req(method, url, **_kw):
            return SimpleNamespace(code=-1, text="", json=lambda *_a: {})

        ep = MagicMock()
        ep.display_name = "测试出口"
        ep.url = "socks5://127.0.0.1:1080"

        def fake_http(follow_redirects=True, proxy="", infer_proxy=True):
            h = MagicMock()
            h.url = proxy
            h.request.side_effect = _req
            return h

        with patch.object(cloud189, "_get_candidate_proxies", return_value=[ep]), \
             patch.object(cloud189, "Http", side_effect=fake_http), \
             patch.object(cloud189, "_login", return_value="V1.0FAKE_SESSION_KEY"), \
             patch.object(cloud189, "_sign", return_value=("【成功】+30M 空间", True)), \
             patch.object(cloud189, "_lotteries", return_value="无"), \
             patch.object(cloud189, "_space", return_value="10G/100G"):
            ok, summary = cloud189._run_one(1, 1, "13800138000", "pw")

        self.assertTrue(ok)
        self.assertIn("• 成长任务:", summary)
        self.assertIn("• 绿色等级:", summary)
        self.assertIn("• 等级奖励:", summary)
        for kw in self._ERROR_KW + self._FAIL_SUB:
            self.assertNotIn(kw, summary, f"降级输出含禁词 {kw!r}")


if __name__ == "__main__":
    unittest.main()