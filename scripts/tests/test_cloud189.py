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
        out = cloud189._rsa_encrypt_hex(PUBKEY_1024, "V1.0FAKE_ACCOUNT")
        self.assertEqual(len(out), 256)
        self.assertRegex(out, r"^[0-9a-f]{256}$")

    def test_rsa_encrypt_differs_per_call(self):
        """随机填充下相同明文两次加密结果不同（确认 PKCS#1 v1.5 盲化生效）。"""
        a = cloud189._rsa_encrypt_hex(PUBKEY_1024, "V1.0FAKE_ACCOUNT")
        b = cloud189._rsa_encrypt_hex(PUBKEY_1024, "V1.0FAKE_ACCOUNT")
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
                cloud189._login(h, "V1.0FAKE_ACCOUNT", "V1.0FAKE_PASS")
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
            ok, _summary = cloud189._run_one(1, 1, "V1.0FAKE_ACCOUNT", "V1.0FAKE_PASS")

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
            # 领取成功判据是 data is True（严判，不认任意 truthy 对象）
            "drawGreenRight": self._resp("0", True),
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

    # ---- 5b. 服务端回显必须被拦住（CodeRabbit Major：健康账号被误显示成失败） ----

    def test_growth_sign_never_echoes_server_text(self):
        """signInNew 失败时绝不回显服务端 message / HTTP 码。

        CodeRabbit #14 Major：原实现把 d.get('message') 原样拼进报告行，天翼的
        文案含「失败/错误」或 code 为 401/403 时，会命中 ex_cloud189 的失败子串
        与 _ERROR_KW，把 ok=True 的健康账号显示成失败行。
        """
        from unittest.mock import MagicMock
        from types import SimpleNamespace
        hostile = [
            ({"code": "1", "message": "签到失败，请稍后重试"}, 200),
            ({"code": "1", "errorMsg": "系统异常"}, 200),
            ({"code": "401", "message": "Unauthorized"}, 401),
            ({"code": "403", "message": "Forbidden"}, 403),
            ({}, 500),
        ]
        for payload, http_code in hostile:
            h = MagicMock()
            h.request.side_effect = lambda *_a, _p=payload, _c=http_code, **__k: SimpleNamespace(
                code=_c, text=repr(_p), json=lambda *x: _p)
            text, ok = cloud189._growth_sign(h, SK_FAKE)
            self.assertFalse(ok)
            # 固定文案，且不含任何服务端回显
            self.assertEqual(text, "绿色签到未达成（接口未确认）")
            for kw in self._ERROR_KW + self._FAIL_SUB:
                self.assertNotIn(kw, text, f"payload={payload} 泄出了禁词 {kw!r}")

    def test_growth_sign_failure_line_is_not_parsed_as_failure(self):
        """端到端：该固定文案经 ex_cloud189 解析后不得进 fail_lines / error_lines。"""
        from report_fields import extract_for
        out = (
            "[1/1] 👤 用户: 【1***4】\n"
            "  • 签到: 【成功】+30M 空间\n"
            "  • 成长任务: 绿色签到未达成（接口未确认） · 今日无需处理\n"
            "  • 等级奖励: 已领 1 项权益\n"
            "  • 绿色等级: LV2 绿色达人 · 绿值 620g\n"
            "✅ 全部 1 个账号处理完成 (成功 1/1)\n"
        )
        res = extract_for("cloud189.py", out)
        self.assertEqual(res["fail_lines"], [])
        self.assertEqual(res["error_lines"], [])
        self.assertEqual(len(res["lines"]), 1)   # 账号块未被清空

    def test_report_safe_drops_banned_words(self):
        """_report_safe：服务端字段命中黑名单即整段丢弃（返回空串）。"""
        self.assertEqual(cloud189._report_safe("绿色达人"), "绿色达人")
        self.assertEqual(cloud189._report_safe("  绿色达人  "), "绿色达人")
        for bad in ("签到失败", "系统错误", "Unauthorized 401", "状态异常", "无法领取",
                    "超时", "处理失败", "Traceback", ""):
            self.assertEqual(cloud189._report_safe(bad), "", f"{bad!r} 应被丢弃")

    def test_growth_level_sanitizes_server_level_name(self):
        """levelName 是服务端字段：命中黑名单时不得泄漏进报告行。"""
        from unittest.mock import MagicMock
        hostile_levels = [
            {"levelNo": "LV2", "levelName": "绿色等级签到失败", "levelScore": 1500,
             "drawState": True},
        ]
        routes = {"getGreenLevelList": self._resp("0", {"userScore": 1250,
                                                        "greenLevelList": hostile_levels})}
        h = MagicMock()
        h.request.side_effect = _fake_growth_request(routes, [])
        text, level_no = cloud189._growth_level(h, SK_FAKE)
        for kw in self._ERROR_KW + self._FAIL_SUB:
            self.assertNotIn(kw, text, f"服务端 levelName 泄出了禁词 {kw!r}")
        self.assertIn("LV2", text)          # 等级号仍如实呈现

    # ---- 5c. Cookie 模式（仅配 CLOUD189_COOKIE_*，无密码） ----

    def test_growth_auth_cookie_mode_still_needs_sso(self):
        """Cookie 模式下 _inject_cookie 种下的同名 COOKIE_LOGIN_USER 也无法
        让服务端直接认账（与云盘登录链落下的那张同名同族），故仍需 ssoLoginMerge。
        该路径是「未配密码」时的实际形态。
        """
        import time
        from http.cookiejar import Cookie, CookieJar
        from unittest.mock import MagicMock

        calls = []

        def _req(method, url, **_kw):
            calls.append((method, url))
            from types import SimpleNamespace
            return SimpleNamespace(code=200, text="x", json=lambda *_a: {})

        h = MagicMock()
        h.request.side_effect = _req
        h.jar = CookieJar()
        h.jar.set_cookie(Cookie(
            version=0, name="COOKIE_LOGIN_USER", value="V1.0FAKE_COOKIE_VALUE",
            port=None, port_specified=False, domain=".189.cn", domain_specified=True,
            domain_initial_dot=True, path="/", path_specified=True, secure=False,
            expires=int(time.time()) + 86400, discard=False, comment=None,
            comment_url=None, rest={}, rfc2109=False,
        ))
        ok = cloud189._ensure_growth_auth(h, "V1.0FAKE_SESSION_KEY")
        # ssoLoginMerge 与活性探测都发生了
        self.assertTrue(any("ssoLoginMerge" in u for _, u in calls))
        self.assertTrue(any("signInNewInfo" in u for _, u in calls))

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

        # 对三个函数的**真实返回值**做同样检查（不遍历硬编码字符串——
        #   自证式断言即使生产文案回退成含「失败」也照样通过）。
        # 任务列表 / 权益列表都用全空夹具，逼出各函数的失败分支文案。
        hostile_sign = [
            ({"code": "1", "message": "签到失败，请稍后重试"}, 200),
            ({"code": "403", "message": "Forbidden"}, 403),
        ]
        for payload, http_code in hostile_sign:
            h = MagicMock()
            from types import SimpleNamespace
            h.request.side_effect = lambda *_a, _p=payload, _c=http_code, **__k: SimpleNamespace(
                code=_c, text=repr(_p), json=lambda *x: _p)
            text, _ok = cloud189._growth_sign(h, SK_FAKE)
            for kw in self._ERROR_KW + self._FAIL_SUB:
                self.assertNotIn(kw, text, f"payload={payload} 泄出禁词 {kw!r}")

        # _growth_tasks：列表拉取失败 / 上报失败路径
        for routes in ({}, {"getGreenTaskList": {"code": "9", "data": None}},
                      {"getGreenTaskList": _green_task_routes(),
                       "doGreenTask": self._resp("1002", None)}):
            h = MagicMock()
            h.request.side_effect = _fake_growth_request(routes, [])
            text, _d, _s, _m = cloud189._growth_tasks(h, SK_FAKE)
            for kw in self._ERROR_KW + self._FAIL_SUB:
                self.assertNotIn(kw, text, f"routes={list(routes)} 泄出禁词 {kw!r}")

        # _level_rewards：权益列表拉取失败 / 领取失败路径
        for routes in ({}, {"getGreenLevelRight": {"code": "9", "data": None}},
                      {"getGreenLevelRight": self._resp("0", [
                          {"prizeId": "V1.0FAKE_P", "rightName": "10G空间券",
                           "drawState": False, "rightState": 1, "actionType": 0}]),
                       "drawGreenRight": self._resp("9999", None)}):
            h = MagicMock()
            h.request.side_effect = _fake_growth_request(routes, [])
            text, _c, _m = cloud189._level_rewards(h, SK_FAKE, "LV2")
            for kw in self._ERROR_KW + self._FAIL_SUB:
                self.assertNotIn(kw, text, f"routes={list(routes)} 泄出禁词 {kw!r}")

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
        """auth_ready=False（无 m 域 Cookie）时账号 ok 仍由 _sign 决定，且输出无禁词。

        注意此路径的真实覆盖面：MagicMock 的 h.jar 迭代为空，因此
        _ensure_growth_auth 返回 False，本用例验证的是**鉴权降级分支**，
        _growth_sign / _growth_tasks / _level_rewards 在此不执行——
        它们的直接用例见 test_growth_sign_* 与 test_growth_tasks_*。
        """
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
            ok, summary = cloud189._run_one(1, 1, "V1.0FAKE_ACCOUNT", "V1.0FAKE_PASS")

        self.assertTrue(ok)
        self.assertIn("• 成长任务:", summary)
        self.assertIn("• 绿色等级:", summary)
        self.assertIn("• 等级奖励:", summary)
        for kw in self._ERROR_KW + self._FAIL_SUB:
            self.assertNotIn(kw, summary, f"降级输出含禁词 {kw!r}")

    # ---- 8. auth_ready=True 且后续抛异常：成长行不得重复/矛盾 ----

    def test_growth_lines_not_duplicated_when_rewards_raise(self):
        """_growth_tasks 成功后 _level_rewards 抛异常时，摘要里不得同时出现
        「成长任务已完成」与「成长任务未开启」两行矛盾结论。

        实现用局部列表收集，异常时整体丢弃只留占位行。
        """
        from unittest.mock import MagicMock, patch

        ep = MagicMock()
        ep.display_name = "测试出口"
        ep.url = "socks5://127.0.0.1:1080"

        def fake_http(follow_redirects=True, proxy="", infer_proxy=True):
            h = MagicMock()
            h.url = proxy
            return h

        def boom(*_a, **_kw):
            raise RuntimeError("链接层抖动")

        with patch.object(cloud189, "_get_candidate_proxies", return_value=[ep]), \
             patch.object(cloud189, "Http", side_effect=fake_http), \
             patch.object(cloud189, "_login", return_value="V1.0FAKE_SESSION_KEY"), \
             patch.object(cloud189, "_sign", return_value=("【成功】+30M 空间", True)), \
             patch.object(cloud189, "_lotteries", return_value="无"), \
             patch.object(cloud189, "_space", return_value="10G/100G"), \
             patch.object(cloud189, "_ensure_growth_auth", return_value=True), \
             patch.object(cloud189, "_growth_level", return_value=("LV2 绿色达人", "LV2")), \
             patch.object(cloud189, "_growth_sign", return_value=("今日已签", True)), \
             patch.object(cloud189, "_growth_tasks",
                          return_value=("完成 2 项 (+30 绿值)", 2, 30, 1)), \
             patch.object(cloud189, "_level_rewards", side_effect=boom):
            ok, summary = cloud189._run_one(1, 1, "V1.0FAKE_ACCOUNT", "V1.0FAKE_PASS")

        # 账号判定不受影响
        self.assertTrue(ok)
        # 每个成长行只出现一次（不重复、不矛盾）
        self.assertEqual(summary.count("• 成长任务:"), 1)
        self.assertEqual(summary.count("• 等级奖励:"), 1)
        self.assertEqual(summary.count("• 绿色等级:"), 1)
        # 已确认的成长任务结果必须保留（CodeRabbit Major：后续异常不得抹掉已得的绿值）
        self.assertIn("完成 2 项 (+30 绿值)", summary)
        self.assertIn("今日已签", summary)
        # 仅未完成的步骤得占位行
        self.assertIn("等级奖励: 未开启（鉴权不全）", summary)
        # 等级查询是独立步骤、已成功，异常只发生在权益领取，
        # 故等级行必须保留真实值（步骤隔离后的正确行为）
        self.assertIn("绿色等级: LV2 绿色达人", summary)
        self.assertNotIn("绿色等级: 未开启", summary)


    # ---- 9. _growth_sign 与 _ensure_growth_auth 的直接用例 ----

    def test_growth_sign_success_reports_signed_day(self):
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        def _req(method, url, **_kw):
            if "signInNewInfo" in url:
                return SimpleNamespace(code=200, text="x", json=lambda *_a: {"status": 0, "data": 5})
            return SimpleNamespace(code=200, text="x",
                                  json=lambda *_a: {"status": 0, "result": True})

        h = MagicMock()
        h.request.side_effect = _req
        text, ok = cloud189._growth_sign(h, SK_FAKE)
        self.assertTrue(ok)
        self.assertIn("今日已签", text)
        self.assertIn("第 5 天", text)

    def test_growth_sign_success_without_day_info(self):
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        def _req(method, url, **_kw):
            if "signInNewInfo" in url:
                return SimpleNamespace(code=-1, text="", json=lambda *_a: {})
            return SimpleNamespace(code=200, text="x",
                                  json=lambda *_a: {"status": 0, "result": True})

        h = MagicMock()
        h.request.side_effect = _req
        text, ok = cloud189._growth_sign(h, SK_FAKE)
        self.assertTrue(ok)
        self.assertEqual(text, "今日已签")

    def test_growth_sign_rejected_code_is_reported_fixed_wording(self):
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        h = MagicMock()
        h.request.side_effect = lambda *_a, **__k: SimpleNamespace(
            code=200, text="x", json=lambda *_x: {"code": "1002", "data": None})
        text, ok = cloud189._growth_sign(h, SK_FAKE)
        self.assertFalse(ok)
        self.assertEqual(text, "绿色签到未达成（接口未确认）")

    def _auth_http(self, jar, alive_after_sso=True):
        """构造带真实 CookieJar 的 Http 替身。

        alive_after_sso=True 表示 ssoLoginMerge 之后服务端活性探测会通过
        （即拿到了真能用的 m 域会话）；False 模拟 CI 上实测到的
        `cookieUserSession=null`——Cookie 种了但服务端不认。
        """
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        calls = []

        def _req(method, url, **_kw):
            calls.append((method, url))
            if "signInNewInfo" in url:
                # ssoLoginMerge 之前一律不认（这是CI 实测现场：登录链的同名 Cookie 无效）
                sso_done = any("ssoLoginMerge" in u for _, u in calls[:-1])
                if sso_done and alive_after_sso:
                    return SimpleNamespace(code=200, text="x",
                                          json=lambda *a: {"code": "0", "data": 3})
                payload = {"errorCode": "InvalidSessionKey",
                           "errorMsg": "cookieUserSession is null or invalid, "
                                      "cookieUserSession=null", "success": None}
                return SimpleNamespace(code=400, text=repr(payload), json=lambda *a: payload)
            return SimpleNamespace(code=200, text="x", json=lambda *_a: {})

        h = MagicMock()
        h.jar = jar
        h.request.side_effect = _req
        return h, calls

    def test_ensure_growth_auth_three_states(self):
        """_ensure_growth_auth 三态：ssoLoginMerge 后会话可用 / 仍不可用 / 无 sessionKey。

        注意：判据已从「jar 里有无 .189.cn 域 Cookie」改为**服务端活性探测**
        （CI 实测：登录链落下的同名 Cookie 服务端不认，旧判据会导致
        ssoLoginMerge 被整个跳过）。故不存在「已有 Cookie 就零请求」这一态了。
        """
        from http.cookiejar import CookieJar

        # ① ssoLoginMerge 后服务端认账 → 可用，且 ssoLoginMerge + 活性探测各一次
        h1, c1 = self._auth_http(CookieJar(), alive_after_sso=True)
        self.assertTrue(cloud189._ensure_growth_auth(h1, SK_FAKE))
        urls = [u for _m, u in c1]
        self.assertEqual(len(urls), 2)
        self.assertTrue(any("ssoLoginMerge" in u for u in urls))
        self.assertTrue(any("signInNewInfo" in u for u in urls))

        # ② ssoLoginMerge 后服务端仍不认 → 不可用（降级为仅查等级）
        h2, c2 = self._auth_http(CookieJar(), alive_after_sso=False)
        self.assertFalse(cloud189._ensure_growth_auth(h2, SK_FAKE))

        # ③ 无 sessionKey → 直接不可用，一个请求都不发
        from unittest.mock import MagicMock

        calls = []
        h3 = MagicMock()
        h3.jar = CookieJar()
        h3.request.side_effect = lambda m, u, **k: calls.append((m, u))
        self.assertFalse(cloud189._ensure_growth_auth(h3, ""))
        self.assertEqual(calls, [])

    def test_ensure_growth_auth_probes_server_not_jar(self):
        """CI 真实验证暴露的缺陷：登录链在 cloud.189.cn / api.cloud.189.cn 上也会
        落下同名 COOKIE_LOGIN_USER（.189.cn 家族），与 m 域那张同名同族，光看 jar
        分不出服务端认哪张。判据必须落到服务端活性探测（signInNewInfo）上——
        否则 ssoLoginMerge 被跳过，signInNew / getGreenLevelRight 恒返回
        `cookieUserSession is null or invalid, cookieUserSession=null`。
        """
        from http.cookiejar import Cookie, CookieJar
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        jar = CookieJar()
        import time as _t
        for dom in ("cloud.189.cn", "api.cloud.189.cn", ".189.cn"):
            jar.set_cookie(Cookie(
                version=0, name="COOKIE_LOGIN_USER", value="V1.0FAKE_OTHER_DOMAIN",
                port=None, port_specified=False, domain=dom, domain_specified=True,
                domain_initial_dot=dom.startswith("."), path="/", path_specified=True,
                secure=False, expires=int(_t.time()) + 3600, discard=False,
                comment=None, comment_url=None, rest={}, rfc2109=False,
            ))

        calls = []

        def _req(method, url, **_kw):
            calls.append((method, url))
            # 场景 A：服务端仍不认 → 400 + errorCode
            if "signInNewInfo" in url:
                payload = {"errorCode": "InvalidSessionKey",
                           "errorMsg": "cookieUserSession is null or invalid, "
                                      "cookieUserSession=null", "success": None}
                return SimpleNamespace(code=400, text=repr(payload), json=lambda *a: payload)
            return SimpleNamespace(code=200, text="x", json=lambda *a: {})

        h = MagicMock()
        h.jar = jar
        h.request.side_effect = _req

        # ① 活性探测认得 InvalidSessionKey
        self.assertFalse(cloud189._growth_session_alive(h, SK_FAKE))
        # ② 于是判为未就绪（而不是被 jar 里的同名 Cookie 骗过）
        self.assertFalse(cloud189._ensure_growth_auth(h, SK_FAKE))
        # ③ ssoLoginMerge 与活性探测都确实发生了
        self.assertTrue(any("ssoLoginMerge" in u for _, u in calls))
        self.assertTrue(any("signInNewInfo" in u for _, u in calls))

    def test_growth_session_alive_accepts_valid_session(self):
        """服务端 200 且无 InvalidSessionKey → 判定会话可用。"""
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        h = MagicMock()
        h.request.side_effect = lambda *a, **k: SimpleNamespace(
            code=200, text="x", json=lambda *x: {"code": "0", "data": 3})
        self.assertTrue(cloud189._growth_session_alive(h, SK_FAKE))

    def test_growth_session_alive_rejects_http_error(self):
        """网络层 -1 亦判为不可用（不得误放行）。"""
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        h = MagicMock()
        h.request.side_effect = lambda *a, **k: SimpleNamespace(
            code=-1, text="", json=lambda *x: {})
        self.assertFalse(cloud189._growth_session_alive(h, SK_FAKE))


    # ---- 10. 业务码字段不统一：signInNew 用 status，其余多用 code ----

    def test_biz_code_prefers_status_then_code(self):
        """CI 实测（2026-11-11）暴露：/market/* 一族的成功码字段并不统一。
        signInNew / signInNewInfo 原生返回 `status`，drawGreenRight /
        getGreenLevelRight 用 `code`。只认 code 会把 status:0 的成功响应判成
        失败（CI 上正是如此：绿色签到恒显示「未达成」，而 code 字段根本不存在）。
        """
        self.assertEqual(cloud189._biz_code({"status": 0, "result": True}), "0")
        self.assertEqual(cloud189._biz_code({"status": "0"}), "0")
        self.assertEqual(cloud189._biz_code({"code": "0", "data": {}}), "0")
        # status 优先（H5 拦截器会把 status 归一成 code，本地不假设字段名）
        self.assertEqual(cloud189._biz_code({"status": 5, "code": "0"}), "5")
        # 都没有 → 空串（调用方据此判失败，不会误放行）
        self.assertEqual(cloud189._biz_code({}), "")
        self.assertEqual(cloud189._biz_code({"result": True}), "")

    def test_growth_sign_accepts_status_zero_without_code_field(self):
        """signInNew 返回 status:0 且完全没有 code 字段 → 必须判为签到成功。"""
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        def _req(method, url, **_kw):
            if "signInNewInfo" in url:
                return SimpleNamespace(code=200, text="x",
                                      json=lambda *a: {"status": 0, "data": 3})
            return SimpleNamespace(code=200, text="x",
                                   json=lambda *a: {"status": 0, "result": True})

        h = MagicMock()
        h.request.side_effect = _req
        text, ok = cloud189._growth_sign(h, SK_FAKE)
        self.assertTrue(ok)
        self.assertIn("今日已签", text)
        self.assertIn("第 3 天", text)


    # ---- 11. 诊断行不得泄漏进报告（CodeRabbit #14：缩进 diag 仍可能命中 _ERROR_KW） ----

    def test_diag_lines_are_not_parsed_as_failures(self):
        """ex_cloud189 必须自行跳过 [diag] 行。

        _finalize 的兜底扫描只认「行首即 [diag]」的行，而任务脚本的 diag 是
        「    [diag] ...」带缩进；文案里一旦带 401/403 等字样，_ERROR_KW 依然
        可能命中它，把健康账号显示成失败。专属解析器先排掉是最稳的一道闸。
        """
        from report_fields import extract_for
        out = (
            "    [diag] signInNew 未达成：HTTP 403 code=403 msg=Unauthorized\n"
            "    [diag] m 域会话未就绪（jar: COOKIE_LOGIN_USER@.189.cn=88B）\n"
            "[1/1] 👤 用户: 【1***4】\n"
            "  • 签到: 【成功】+30M 空间\n"
            "  • 成长任务: 今日已签（本周第 1 天） · 今日无需处理\n"
            "  • 绿色等级: LV1 绿色达人 · 绿值 732g（下一级 1000g）\n"
            "✅ 全部 1 个账号处理完成 (成功 1/1)\n"
        )
        res = extract_for("cloud189.py", out)
        self.assertEqual(res["fail_lines"], [])
        self.assertEqual(res["error_lines"], [])
        self.assertEqual(len(res["lines"]), 1)
        self.assertIn("LV1 绿色达人", res["lines"][0])


    # ---- 12. result 判定 / done 标志初始化 / 单项异常 / 诊断脱敏 ----

    def test_growth_sign_requires_result_true(self):
        """业务码为 0 但 result 非 True（已签/未获服务端确认）不得报成功
        ——规则 9a(1) 绝不允许假成功（CodeRabbit Major）。"""
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        for bad in (False, None, {}, "true", 1):
            h = MagicMock()
            h.request.side_effect = lambda *_a, _r=bad, **__k: SimpleNamespace(
                code=200, text="x", json=lambda *x: {"status": 0, "result": _r})
            text, ok = cloud189._growth_sign(h, SK_FAKE)
            self.assertFalse(ok, f"result={bad!r} 不得判为签到成功")
            self.assertEqual(text, "绿色签到未达成（接口未确认）")

    def test_growth_done_flags_initialized_before_try(self):
        """_ensure_growth_auth 抛异常时，except 分支读 done_task 不得触发
        UnboundLocalError —— 否则普通签到已成功的账号会被判失败（CodeRabbit Major，
        直接违反「成长体系绝不得影响账号判定」）。"""
        from unittest.mock import MagicMock, patch

        ep = MagicMock()
        ep.display_name = "测试出口"
        ep.url = "socks5://127.0.0.1:1080"

        def fake_http(follow_redirects=True, proxy="", infer_proxy=True):
            h = MagicMock()
            h.url = proxy
            return h

        def boom(*_a, **_kw):
            raise RuntimeError("鉴权链路抖动")

        with patch.object(cloud189, "_get_candidate_proxies", return_value=[ep]), \
             patch.object(cloud189, "Http", side_effect=fake_http), \
             patch.object(cloud189, "_login", return_value="V1.0FAKE_SESSION_KEY"), \
             patch.object(cloud189, "_sign", return_value=("【成功】+30M 空间", True)), \
             patch.object(cloud189, "_lotteries", return_value="无"), \
             patch.object(cloud189, "_space", return_value="10G/100G"), \
             patch.object(cloud189, "_ensure_growth_auth", side_effect=boom):
            ok, summary = cloud189._run_one(1, 1, "V1.0FAKE_ACCOUNT", "V1.0FAKE_PASS")

        self.assertTrue(ok)
        self.assertIn("• 成长任务: 未开启（鉴权不全）", summary)
        self.assertIn("• 等级奖励: 未开启（鉴权不全）", summary)

    def test_growth_task_midway_exception_keeps_confirmed(self):
        """_do_green_task 中途抛异常（如 IncompleteRead）不得丢掉已确认的
        done/score，且后续任务仍要继续处理。"""
        import urllib.parse as up
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        tasks = [
            {"taskId": "V1.0FAKE_T1", "taskName": "a", "rewardValue": 10, "status": False},
            {"taskId": "V1.0FAKE_T2", "taskName": "b", "rewardValue": 20, "status": False},
            {"taskId": "V1.0FAKE_T3", "taskName": "c", "rewardValue": 30, "status": False},
        ]
        # 服务端按 taskType 分列表：三项任务只挂在 taskType=2 下，其余类型返回空
        by_type = {"2": tasks, "3": [], "5": [], "1": []}
        calls = []

        def _req(method, url, form=None, **_kw):
            calls.append((method, url, form or {}))
            if "doGreenTask" in url:
                n = sum(1 for m, u, _f in calls if "doGreenTask" in u)
                # 只有**第 2 次**上报抛 IncompleteRead；第 1、3 次正常入账，
                # 这样才能验证「异常之后的任务仍能成功计入 done/score」。
                if n == 2:
                    raise OSError("IncompleteRead")
                return SimpleNamespace(code=200, text="x",
                                      json=lambda *_a: {"status": 0, "data": True})
            qs = up.parse_qs(up.urlsplit(url).query)
            tt = (qs.get("taskType") or [""])[0]
            return SimpleNamespace(code=200, text="x",
                                  json=lambda *_a, _d=by_type.get(tt, []):
                                  {"status": 0, "data": _d})

        h = MagicMock()
        h.request.side_effect = _req
        text, done, score, _m = cloud189._growth_tasks(h, SK_FAKE)
        posted = [c for c in calls if "doGreenTask" in c[1]]
        # 三项都尝试了（异常没有中断循环）
        self.assertEqual(len(posted), 3)
        # 第 1、3 项入账（异常之后的任务确实继续成功），第 2 项计入未确认
        self.assertEqual(done, 2)
        self.assertEqual(score, 40)      # 10 + 30
        self.assertIn("完成 2 项", text)
        self.assertIn("上报未确认 1 项", text)

    def test_mask_net_text_redacts_pii_and_credentials(self):
        """诊断文案必须删改凭据与 PII，而非原样落进 CI 日志（CodeRabbit Major）。"""
        f = cloud189._mask_net_text
        self.assertEqual(f("ok"), "ok")
        # sessionKey / accessToken 查询参数（合成值统一 V1.0FAKE 前缀）
        fake_sk = "V1.0FAKE_SESSION_KEY_ABCDEF123456"
        self.assertIn("***", f(f"sessionKey={fake_sk}"))
        self.assertNotIn("ABCDEF123456", f(f"sessionKey={fake_sk}"))
        self.assertIn("***", f("?accessToken=V1.0FAKE_TOKEN_VALUE_XYZ"))
        # 长 hex / base64 凭据（拼接构造合成值，不引入真实形态）
        self.assertIn("***", f("token " + "a" * 40))
        # 手机号 / 邮箱（用拼接构造样例，避免真实手机号形态入库）
        phone = "13" + "8001" + "38000"
        self.assertIn("***", f(f"用户 {phone} 登录失败"))
        self.assertIn("***", f("邮箱 user@example.com 校验失败"))
        # 不产生自由文本回显：一律截断
        self.assertLessEqual(len(f("x" * 500)), 60)

    def test_diag_bool_whitelist(self):
        """诊断里的布尔字段只输出 true/false/other，绝不做自由文本回显。"""
        f = cloud189._diag_bool
        self.assertEqual(f(True), "true")
        self.assertEqual(f(False), "false")
        self.assertEqual(f(None), "other")
        self.assertEqual(f({"secret": "V1.0FAKE"}), "other")
        self.assertEqual(f("V1.0FAKE_LONG_STRING"), "other")


    # ---- 13. 全部上报异常/被拒时不得报「今日无需处理」（假确认） ----

    def test_growth_tasks_all_failed_reports_unconfirmed(self):
        """所有上报都异常或被拒时，文案必须是「上报未确认 N 项」。

        否则 done=manual=0 会落到「今日无需处理」，把未确认的任务说成无事可做
        ——规则 9a(1) 禁止的假确认（CodeRabbit 指出的真实路径）。
        """
        import urllib.parse as up
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        tasks = [
            {"taskId": "V1.0FAKE_T1", "taskName": "a", "rewardValue": 10, "status": False},
            {"taskId": "V1.0FAKE_T2", "taskName": "b", "rewardValue": 20, "status": False},
        ]
        by_type = {"2": tasks, "3": [], "5": [], "1": []}

        for mode in ("raise", "reject"):
            def _req(method, url, form=None, **_kw):
                if "doGreenTask" in url:
                    if mode == "raise":
                        raise OSError("IncompleteRead")
                    return SimpleNamespace(code=200, text="x",
                                          json=lambda *_a: {"status": 1002, "data": None})
                qs = up.parse_qs(up.urlsplit(url).query)
                tt = (qs.get("taskType") or [""])[0]
                return SimpleNamespace(
                    code=200, text="x",
                    json=lambda *_a, _d=by_type.get(tt, []): {"status": 0, "data": _d})

            h = MagicMock()
            h.request.side_effect = _req
            text, done, score, manual = cloud189._growth_tasks(h, SK_FAKE)
            self.assertNotIn("今日无需处理", text, f"mode={mode} 不得报无事可做")
            self.assertIn("上报未确认 2 项", text, f"mode={mode}")
            self.assertEqual((done, score, manual), (0, 0, 0))

    def test_growth_tasks_no_unfinished_reports_nothing_to_do(self):
        """全部 status=True 时才允许报「今日无需处理」。"""
        import urllib.parse as up
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        tasks = [{"taskId": "V1.0FAKE_T1", "taskName": "a",
                  "rewardValue": 10, "status": True}]

        def _req(method, url, form=None, **_kw):
            qs = up.parse_qs(up.urlsplit(url).query)
            tt = (qs.get("taskType") or [""])[0]
            return SimpleNamespace(
                code=200, text="x",
                json=lambda *_a, _d=tasks if tt == "2" else []: {"status": 0, "data": _d})

        h = MagicMock()
        h.request.side_effect = _req
        text, done, score, manual = cloud189._growth_tasks(h, SK_FAKE)
        self.assertEqual(text, "今日无需处理")
        self.assertEqual((done, score, manual), (0, 0, 0))


# ---- 14. 步骤隔离 / Cookie 模式 sessionKey / 领取严判 ----

    def test_growth_level_exception_does_not_block_tasks(self):
        """等级查询抛异常不得阻断绿色签到与任务上报（CodeRabbit Major：步骤隔离）。"""
        from unittest.mock import MagicMock, patch

        ep = MagicMock()
        ep.display_name = "测试出口"
        ep.url = "socks5://127.0.0.1:1080"

        def fake_http(follow_redirects=True, proxy="", infer_proxy=True):
            h = MagicMock()
            h.url = proxy
            return h

        def boom(*_a, **_kw):
            raise RuntimeError("等级接口抖动")

        with patch.object(cloud189, "_get_candidate_proxies", return_value=[ep]), \
             patch.object(cloud189, "Http", side_effect=fake_http), \
             patch.object(cloud189, "_login", return_value="V1.0FAKE_SESSION_KEY"), \
             patch.object(cloud189, "_sign", return_value=("【成功】+30M 空间", True)), \
             patch.object(cloud189, "_lotteries", return_value="无"), \
             patch.object(cloud189, "_space", return_value="10G/100G"), \
             patch.object(cloud189, "_ensure_growth_auth", return_value=True), \
             patch.object(cloud189, "_growth_level", side_effect=boom), \
             patch.object(cloud189, "_growth_sign", return_value=("今日已签", True)), \
             patch.object(cloud189, "_growth_tasks",
                          return_value=("完成 3 项 (+50 绿值)", 3, 50, 0)), \
             patch.object(cloud189, "_level_rewards", return_value=("无可领权益", 0, 0)):
            ok, summary = cloud189._run_one(1, 1, "V1.0FAKE_ACCOUNT", "V1.0FAKE_PASS")

        self.assertTrue(ok)
        # 等级查询失败，但任务照常上报并进摘要
        self.assertIn("完成 3 项", summary)
        self.assertIn("绿色等级: 未开启（鉴权不全）", summary)

    def test_growth_sign_exception_does_not_block_tasks(self):
        """绿色签到抛异常不得阻断任务上报（步骤隔离）。"""
        from unittest.mock import MagicMock, patch

        ep = MagicMock()
        ep.display_name = "测试出口"
        ep.url = "socks5://127.0.0.1:1080"

        def fake_http(follow_redirects=True, proxy="", infer_proxy=True):
            h = MagicMock()
            h.url = proxy
            return h

        def boom(*_a, **_kw):
            raise RuntimeError("签到接口抖动")

        with patch.object(cloud189, "_get_candidate_proxies", return_value=[ep]), \
             patch.object(cloud189, "Http", side_effect=fake_http), \
             patch.object(cloud189, "_login", return_value="V1.0FAKE_SESSION_KEY"), \
             patch.object(cloud189, "_sign", return_value=("【成功】+30M 空间", True)), \
             patch.object(cloud189, "_lotteries", return_value="无"), \
             patch.object(cloud189, "_space", return_value="10G/100G"), \
             patch.object(cloud189, "_ensure_growth_auth", return_value=True), \
             patch.object(cloud189, "_growth_level", return_value=("LV1 绿色达人", "LV1")), \
             patch.object(cloud189, "_growth_sign", side_effect=boom), \
             patch.object(cloud189, "_growth_tasks",
                          return_value=("完成 2 项 (+20 绿值)", 2, 20, 0)), \
             patch.object(cloud189, "_level_rewards", return_value=("无可领权益", 0, 0)):
            ok, summary = cloud189._run_one(1, 1, "V1.0FAKE_ACCOUNT", "V1.0FAKE_PASS")

        self.assertTrue(ok)
        self.assertIn("完成 2 项", summary)
        self.assertNotIn("今日已签", summary)   # 签到抛异常，无签到文案

    def test_cookie_mode_mints_session_key(self):
        """仅配 CLOUD189_COOKIE_* 时也必须换 sessionKey，否则 /market/* 全部降级。"""
        from unittest.mock import MagicMock, patch

        ep = MagicMock()
        ep.display_name = "测试出口"
        ep.url = "socks5://127.0.0.1:1080"

        def fake_http(follow_redirects=True, proxy="", infer_proxy=True):
            h = MagicMock()
            h.url = proxy
            return h

        with patch.object(cloud189, "_get_candidate_proxies", return_value=[ep]), \
             patch.object(cloud189, "Http", side_effect=fake_http), \
             patch.object(cloud189, "_inject_cookie") as inj, \
             patch.object(cloud189, "_mint_session_key",
                          return_value="V1.0FAKE_SESSION_KEY") as mint, \
             patch.object(cloud189, "_sign", return_value=("【成功】+30M 空间", True)), \
             patch.object(cloud189, "_lotteries", return_value="无"), \
             patch.object(cloud189, "_space", return_value="10G/100G"), \
             patch.object(cloud189, "_ensure_growth_auth", return_value=True), \
             patch.object(cloud189, "_growth_level", return_value=("LV1 绿色达人", "LV1")), \
             patch.object(cloud189, "_growth_sign", return_value=("今日已签", True)), \
             patch.object(cloud189, "_growth_tasks",
                          return_value=("完成 1 项 (+10 绿值)", 1, 10, 0)), \
             patch.object(cloud189, "_level_rewards", return_value=("无可领权益", 0, 0)):
            # 只给 cookie，不给账号密码
            ok, _summary = cloud189._run_one(1, 1, "", "",
                                            "V1.0FAKE_COOKIE=1")

        self.assertTrue(ok)
        inj.assert_called_once()
        mint.assert_called_once()

    def test_level_reward_rejects_non_true_data(self):
        """data 为 "false" / {"success": false} 等 truthy 值不得计为已领（假成功）。"""
        from unittest.mock import MagicMock

        for bad in ("false", {"success": False}, 1, "1", {}):
            calls = []
            routes = {
                "getGreenLevelRight": self._resp("0", [
                    {"prizeId": "V1.0FAKE_P", "rightName": "10G", "drawState": False,
                     "rightState": 1, "actionType": 0}]),
                "drawGreenRight": self._resp("0", bad),
            }
            h = MagicMock()
            h.request.side_effect = _fake_growth_request(routes, calls)
            text, claimed, _m = cloud189._level_rewards(h, SK_FAKE, "LV2")
            self.assertEqual(claimed, 0, f"data={bad!r} 不得计为已领")
            self.assertIn("领取未确认 1 项", text, f"data={bad!r} 应计为未确认")

    def test_level_reward_isolates_request_exception(self):
        """单项 drawGreenRight 抛异常不得中断其余权益（逐项隔离）。"""
        from unittest.mock import MagicMock

        routes = {
            "getGreenLevelRight": self._resp("0", [
                {"prizeId": "V1.0FAKE_P1", "rightName": "a", "drawState": False,
                 "rightState": 1, "actionType": 0},
                {"prizeId": "V1.0FAKE_P2", "rightName": "b", "drawState": False,
                 "rightState": 1, "actionType": 0},
            ]),
        }
        calls = []

        def _req(method, url, form=None, **_kw):
            calls.append((method, url, form or {}))
            if "drawGreenRight" in url:
                if (form or {}).get("prizeId") == "V1.0FAKE_P1":
                    raise OSError("connection reset")
                from types import SimpleNamespace
                return SimpleNamespace(code=200, text="x",
                                      json=lambda *_a: {"status": 0, "data": True})
            return _fake_growth_request(routes, [])(method, url, form=form, **_kw)

        h = MagicMock()
        h.request.side_effect = _req
        text, claimed, _m = cloud189._level_rewards(h, SK_FAKE, "LV2")
        posted = [c for c in calls if "drawGreenRight" in c[1]]
        self.assertEqual(len(posted), 2)     # 第二项仍被尝试
        self.assertEqual(claimed, 1)         # 第二项成功
        self.assertIn("领取未确认 1 项", text)


    def test_growth_tasks_non_list_data_is_not_query_failure(self):
            """不同 taskType 返回结构并不一致（如气泡任务走另一接口函数）。

            data 非 list 只表示该类无任务，**不是**查询失败——真实 CI 实测就出现过
            因此误报「列表未确认 1 类」。只有 HTTP 非 200 / 业务码非 0 才算未确认。
            """
            import urllib.parse as up
            from unittest.mock import MagicMock
            from types import SimpleNamespace

            def _req(method, url, form=None, **_kw):
                qs = up.parse_qs(up.urlsplit(url).query)
                tt = (qs.get("taskType") or [""])[0]
                if tt == "5":
                    # 气泡任务返回对象结构（非 list）
                    return SimpleNamespace(code=200, text="x",
                                          json=lambda *_a: {"status": 0, "data": {}})
                return SimpleNamespace(code=200, text="x",
                                      json=lambda *_a: {"status": 0, "data": []})

            h = MagicMock()
            h.request.side_effect = _req
            text, done, score, manual = cloud189._growth_tasks(h, SK_FAKE)
            self.assertNotIn("列表未确认", text)
            self.assertEqual(text, "今日无需处理")

    def test_growth_tasks_list_query_failure_is_reported(self):
        """HTTP 非 200 / 业务码非 0 才计为列表未确认，并禁止报「今日无需处理」。"""
        import urllib.parse as up
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        for mode in ("http500", "bizcode"):
            def _req(method, url, form=None, **_kw):
                if mode == "http500":
                    return SimpleNamespace(code=500, text="", json=lambda *_a: {})
                return SimpleNamespace(code=200, text="x",
                                      json=lambda *_a: {"status": 9, "data": []})

            h = MagicMock()
            h.request.side_effect = _req
            text, _d, _s, _m2 = cloud189._growth_tasks(h, SK_FAKE)
            self.assertNotIn("今日无需处理", text, f"mode={mode}")
            self.assertIn("列表未确认 4 类", text, f"mode={mode}")


if __name__ == "__main__":
    unittest.main()
