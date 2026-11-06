#!/usr/bin/env python3
"""OPPO 商城 (HeyTap) 签到与无感续期单元测试。

测试覆盖：
1. JWT 令牌 Payload 与 exp 过期时间提取
2. Cookie 键值解析、序列化与 memberinfo 用户信息提取
3. HeyTap Web SDK 规范 PKCE 密钥对生成 (codeVerifier, codeChallenge)
4. 基于 acIdAuthSession 根凭据的 SSO 换票与会话更新全流程 Mock
5. 凭证缺失或失效时的降级与异常处理
6. 签到奖励口径解析（响应 data → baseAwards 今日档位 → 无数值）
7. 浏览任务链路（落地页驻留 → 上报 → 领奖 pointsNum 兜底）、userEventStatus 直领、二次补领
8. 多账号循环错峰与任一失败退出码语义
9. report_fields 中 ex_oppo 的报告提取逻辑验证（含实际 +N 积分口径）
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
import unittest
import urllib.parse
from datetime import datetime
from http.cookiejar import CookieJar
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import oppo
from common import BJT
from report_fields import extract_for


def _make_mock_jwt(payload: dict) -> str:
    header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8")).decode("utf-8").rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")
    signature_b64 = base64.urlsafe_b64encode(b"synthetic_mock_sig").decode("utf-8").rstrip("=")
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def _make_fake_tokensid(exp_seconds: int) -> str:
    """App 端 TOKENSID 形态（TOKEN_ 前缀 ECDSA JWT，毫秒级 exp）；合成夹具凭据一律 V1.0FAKE 语义。"""
    header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "ECDSA", "v": "1"}).encode("utf-8")).decode("utf-8").rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps({"exp": exp_seconds * 1000, "id": "1392822015", "idc": "V1.0FAKE"}).encode("utf-8")).decode("utf-8").rstrip("=")
    signature_b64 = base64.urlsafe_b64encode(b"V1.0FAKE_synthetic_ecdsa_sig").decode("utf-8").rstrip("=")
    return f"TOKEN_{header_b64}.{payload_b64}.{signature_b64}"


# 合成签到页 HTML：含 activityInfo（签到场次）与 taskActivityInfo（任务场次）节点，验证动态发现
_SYNTHETIC_PAGE_HTML = (
    '<html><script>window.__PAGE_DATA__={"template":{'
    '"SignIn_82c7796e":{"type":"SignIn","attr":{'
    '"activityInfo":{"activityId":"2116078703745441792","activityName":"11月积分商城签到"}}},'
    '"Task_9f2c1a3e":{"type":"Task","attr":{'
    '"taskActivityInfo":{"activityId":"1919591795180969984","activityName":"【商城积分乐园】一次性成长任务"}}}'
    "}}</script></html>"
)


class TestOppo(unittest.TestCase):
    def test_jwt_payload_and_exp(self):
        exp_time = int(time.time()) + 3600
        mock_payload = {
            "sub": "synthetic_sub_12345",
            "exp": exp_time,
            "refreshToken": "mock_refresh_token_abc",
        }
        token = _make_mock_jwt(mock_payload)

        payload = oppo._decode_jwt_payload(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload.get("sub"), "synthetic_sub_12345")
        self.assertEqual(payload.get("exp"), exp_time)

        exp = oppo._decode_jwt_exp(token)
        self.assertEqual(exp, exp_time)

        # 畸变 Token 返回 None
        self.assertIsNone(oppo._decode_jwt_payload("invalid_token_format"))
        self.assertIsNone(oppo._decode_jwt_exp("invalid_token_format"))

    def test_cookie_parse_and_format(self):
        cookie_raw = "sa_distinct_id=mock_sa_123; webAccessToken=mock_token_xyz; acIdAuthSession=mock_sso_session"
        items = oppo._parse_cookie_items(cookie_raw)
        self.assertEqual(items.get("sa_distinct_id"), "mock_sa_123")
        self.assertEqual(items.get("webAccessToken"), "mock_token_xyz")
        self.assertEqual(items.get("acIdAuthSession"), "mock_sso_session")

        reformatted = oppo._format_cookie_str(items)
        self.assertIn("sa_distinct_id=mock_sa_123", reformatted)
        self.assertIn("webAccessToken=mock_token_xyz", reformatted)
        self.assertIn("acIdAuthSession=mock_sso_session", reformatted)

    def test_extract_user_info(self):
        member_data = {
            "id": "mock_uid_1001",
            "name": "测试用户",
            "oid": "mock_oid_8888",
        }
        member_json_enc = urllib.parse.quote(json.dumps(member_data))
        cookie_items = {
            "memberinfo": member_json_enc,
            "webAccessToken": "mock_token",
        }
        name, uid, oid = oppo._extract_user_info(cookie_items)
        self.assertEqual(name, "测试用户")
        self.assertEqual(uid, "mock_uid_1001")
        self.assertEqual(oid, "mock_oid_8888")

        # 缺少或损坏 memberinfo 时静默降级
        name_empty, uid_empty, oid_empty = oppo._extract_user_info({})
        self.assertEqual(name_empty, "")
        self.assertEqual(uid_empty, "")
        self.assertEqual(oid_empty, "")

    def test_pkce_generation(self):
        verifier, challenge = oppo._generate_pkce_pair()
        # 1. 验证 codeVerifier 长度为 43 位
        self.assertEqual(len(verifier), 43)
        # 2. 验证字符集为字母数字
        self.assertTrue(verifier.isalnum())
        # 3. 验证 codeChallenge 为 SHA-256 哈希十六进制小写
        expected_challenge = hashlib.sha256(verifier.encode("utf-8")).hexdigest()
        self.assertEqual(challenge, expected_challenge)
        self.assertEqual(len(challenge), 64)

    @patch.object(oppo, "Http")
    def test_try_refresh_oppo_token_success(self, mock_http_cls):
        mock_http = MagicMock()
        mock_http.jar = CookieJar()

        # 模拟响应 1: state 网关
        mock_resp_state = MagicMock()
        mock_resp_state.code = 200
        mock_resp_state.json.return_value = {
            "code": 200,
            "data": {"state": "mock_oauth_state_12345"},
        }

        # 模拟响应 2: SSO 换票 302 重定向
        mock_resp_sso = MagicMock()
        mock_resp_sso.code = 302
        mock_resp_sso.headers = {
            "Location": "https://hd.opposhop.cn/?state=mock_oauth_state_12345&code=mock_auth_code_99999"
        }

        # 模拟响应 3: 商城换票登录
        new_jwt = _make_mock_jwt({"sub": "user_refreshed", "exp": int(time.time()) + 86400})
        mock_resp_login = MagicMock()
        mock_resp_login.code = 200
        mock_resp_login.json.return_value = {
            "code": 200,
            "success": True,
            "data": {
                "webAccessToken": new_jwt,
                "oppo_track_id": "new_track_id",
            },
        }

        def mock_request(method, url, **kwargs):
            if "/account/state" in url:
                return mock_resp_state
            if "/identity/web/v1/authn/auth-and-callback" in url:
                return mock_resp_sso
            if "/account/login" in url:
                return mock_resp_login
            return MagicMock(code=404)

        mock_http.request.side_effect = mock_request

        initial_cookies = {
            "acIdAuthSession": "mock_sso_session_valid",
            "webAccessToken": "old_expired_jwt",
        }

        ok, new_cookies, msg = oppo._try_refresh_oppo_token(mock_http, initial_cookies)
        self.assertTrue(ok)
        self.assertEqual(new_cookies.get("webAccessToken"), new_jwt)
        self.assertEqual(new_cookies.get("oppo_track_id"), "new_track_id")
        self.assertEqual(new_cookies.get("acIdAuthSession"), "mock_sso_session_valid")

    def test_try_refresh_oppo_token_missing_sso(self):
        mock_http = MagicMock()
        initial_cookies = {"webAccessToken": "only_jwt"}
        ok, new_cookies, msg = oppo._try_refresh_oppo_token(mock_http, initial_cookies)
        self.assertFalse(ok)
        self.assertIn("缺少 acIdAuthSession", msg)

    @patch.object(oppo, "Http")
    def test_try_refresh_oppo_token_sso_denied(self, mock_http_cls):
        mock_http = MagicMock()
        # 模拟 SSO 网关未重定向且未下发 code (如会话过期)
        mock_resp_state = MagicMock(code=200)
        mock_resp_state.json.return_value = {"code": 200, "data": {"state": "s1"}}

        mock_resp_sso = MagicMock(code=200)
        mock_resp_sso.headers = {}
        mock_resp_sso.json.return_value = {"code": 10001, "message": "SSO session expired"}

        def mock_request(method, url, **kwargs):
            if "/account/state" in url:
                return mock_resp_state
            if "/identity/web/v1/authn/auth-and-callback" in url:
                return mock_resp_sso
            return MagicMock(code=404)

        mock_http.request.side_effect = mock_request
        initial_cookies = {"acIdAuthSession": "expired_sso_token"}
        ok, _, msg = oppo._try_refresh_oppo_token(mock_http, initial_cookies)
        self.assertFalse(ok)
        self.assertIn("未下发授权 code", msg)

    @patch.object(oppo, "save_kv_state")
    @patch.object(oppo, "load_kv_state")
    @patch.object(oppo, "Http")
    def test_run_account_proactive_refresh(self, mock_http_cls, mock_load_state, mock_save_state):
        mock_load_state.return_value = {}
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http
        mock_http.jar = CookieJar()

        # 生成已过期 (exp < now) 的 synthetic JWT
        expired_jwt = _make_mock_jwt({"sub": "uid_123", "exp": int(time.time()) - 3600})
        new_jwt = _make_mock_jwt({"sub": "uid_123", "exp": int(time.time()) + 86400})

        # Mock HTTP requests
        def mock_request(method, url, **kwargs):
            resp = MagicMock()
            resp.code = 200
            if "/account/state" in url:
                resp.json.return_value = {"code": 200, "data": {"state": "st1"}}
            elif "/identity/web/v1/authn/auth-and-callback" in url:
                resp.code = 302
                resp.headers = {"Location": "https://hd.opposhop.cn/?state=st1&code=auth1"}
            elif "/account/login" in url:
                resp.json.return_value = {"code": 200, "success": True, "data": {"webAccessToken": new_jwt}}
            elif "getSignInDetail" in url:
                resp.json.return_value = {"code": 200, "data": {"cumulativeAwardList": []}}
            elif "signIn" in url:
                resp.json.return_value = {"code": 200, "data": {"credits": 10}}
            elif "queryTaskList" in url:
                resp.json.return_value = {"code": 200, "data": {"taskDTOList": []}}
            elif "queryMemberCreditInfo" in url:
                resp.json.return_value = {"code": 200, "data": {"amount": 600, "userLevel": 1}}
            else:
                resp.json.return_value = {}
            return resp

        mock_http.request.side_effect = mock_request

        raw_cookie = f"acIdAuthSession=mock_sso_session; webAccessToken={expired_jwt}"
        ok, desc = oppo._run_account(raw_cookie, 1, 1)
        self.assertTrue(ok)
        self.assertIn("打卡成功", desc)
        # 验证触发了 save_kv_state 且保存了最新凭据
        self.assertTrue(mock_save_state.called)
        saved_args = mock_save_state.call_args[0]
        saved_data = saved_args[2]
        self.assertEqual(saved_data.get("webAccessToken"), new_jwt)
        self.assertEqual(saved_data.get("acIdAuthSession"), "mock_sso_session")

    @patch.object(oppo, "save_kv_state")
    @patch.object(oppo, "load_kv_state")
    @patch.object(oppo, "Http")
    def test_run_account_reactive_refresh_on_auth_failure(self, mock_http_cls, mock_load_state, mock_save_state):
        mock_load_state.return_value = {}
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http
        mock_http.jar = CookieJar()

        # 生成有效 JWT，但接口返回 403 需重新换票
        initial_jwt = _make_mock_jwt({"sub": "uid_456", "exp": int(time.time()) + 7200})
        refreshed_jwt = _make_mock_jwt({"sub": "uid_456", "exp": int(time.time()) + 86400})

        first_sign = True

        def mock_request(method, url, **kwargs):
            nonlocal first_sign
            resp = MagicMock()
            resp.code = 200
            if "/account/state" in url:
                resp.json.return_value = {"code": 200, "data": {"state": "st2"}}
            elif "/identity/web/v1/authn/auth-and-callback" in url:
                resp.code = 302
                resp.headers = {"Location": "https://hd.opposhop.cn/?state=st2&code=auth2"}
            elif "/account/login" in url:
                resp.json.return_value = {"code": 200, "success": True, "data": {"webAccessToken": refreshed_jwt}}
            elif "signIn" in url:
                if first_sign:
                    first_sign = False
                    resp.json.return_value = {"code": 403, "message": "用户未登录或登录态失效"}
                else:
                    resp.json.return_value = {"code": 200, "data": {"credits": 10}}
            elif "getSignInDetail" in url:
                resp.json.return_value = {"code": 200, "data": {"cumulativeAwardList": []}}
            elif "queryTaskList" in url:
                resp.json.return_value = {"code": 200, "data": {"taskDTOList": []}}
            elif "queryMemberCreditInfo" in url:
                resp.json.return_value = {"code": 200, "data": {"amount": 750, "userLevel": 2}}
            else:
                resp.json.return_value = {}
            return resp

        mock_http.request.side_effect = mock_request

        raw_cookie = f"acIdAuthSession=mock_sso_session; webAccessToken={initial_jwt}"
        ok, desc = oppo._run_account(raw_cookie, 1, 1)
        self.assertTrue(ok)
        self.assertIn("打卡成功", desc)
        self.assertTrue(mock_save_state.called)
        saved_args = mock_save_state.call_args[0]
        self.assertEqual(saved_args[2].get("webAccessToken"), refreshed_jwt)

    def test_report_fields_ex_oppo(self):
        synthetic_output = """
==================================================
📱 OPPO商城 每日打卡与赚积分任务
==================================================

[1/1] 👤 用户: 1001***888（张***）
  📋 查询签到状态与连签进度...
  👉 提交每日打卡签到...
  🎉 签到成功！获得 +10 积分
  🎁 发现可领取的连签里程碑: 连签3天礼包，正在领取...
  🚀 获取日常赚积分任务列表...
  📦 发现 2 项活动任务，正在自动处理...
    🎉 领奖成功: 浏览超值好物 (+2 积分)
    🎉 领奖成功: 浏览新品专区 (+2 积分)
  💰 账户积分余额: 580 (Lv.2，抵扣金: 5.80元)
==================================================
🏁 执行完毕: 成功 1/1 个账号
==================================================
"""
        res = extract_for("oppo.py", synthetic_output)
        self.assertTrue(any("1001***888" in line for line in res["lines"]))
        self.assertTrue(any("签到成功 (+10 积分)" in line for line in res["lines"]))
        self.assertTrue(any("积分 580" in line for line in res["lines"]))
        self.assertTrue(any("完成 2 项日常任务 (+4分)" in line for line in res["lines"]))
        self.assertIn(("积分", 580.0), res["assets"])
        self.assertIn(("积分", 10.0), res["gains"])
        self.assertIn(("积分", 4.0), res["gains"])

    # ---------- 签到奖励口径解析 ----------

    def test_resolve_sign_points_prefers_response_data(self):
        sign_res = {"code": 200, "data": {"awardValue": "2"}}
        detail = {"data": {"baseAwards": [{"signTime": "2099-01-01", "awardType": 1, "awardValue": "5"}]}}
        self.assertEqual(oppo._resolve_sign_points(sign_res, detail), 2)

    def test_resolve_sign_points_falls_back_to_today_base_award(self):
        today = datetime.now(BJT).strftime("%Y-%m-%d")
        sign_res = {"code": 200, "data": None}
        detail = {"data": {"baseAwards": [
            {"signTime": "2026-11-01", "awardType": 1, "awardValue": "2"},
            {"signTime": today, "awardType": 1, "awardValue": "2"},
        ]}}
        self.assertEqual(oppo._resolve_sign_points(sign_res, detail), 2)

    def test_resolve_sign_points_ignores_coupon_and_nonpositive(self):
        today = datetime.now(BJT).strftime("%Y-%m-%d")
        # awardType 2 为券类（包邮券），不计积分；非今日档位忽略
        detail = {"data": {"baseAwards": [
            {"signTime": today, "awardType": 2, "awardValue": "包邮券"},
            {"signTime": "2026-01-01", "awardType": 1, "awardValue": "9"},
        ]}}
        self.assertIsNone(oppo._resolve_sign_points({}, detail))

    def test_resolve_sign_points_unknown_shape_returns_none(self):
        self.assertIsNone(oppo._resolve_sign_points({"code": 200, "data": {"unknownField": 1}}, {}))
        self.assertIsNone(oppo._resolve_sign_points({}, {}))

    # ---------- 浏览任务链路 / 动态场次发现 ----------

    @patch.object(oppo, "save_kv_state")
    @patch.object(oppo, "load_kv_state")
    @patch.object(oppo.time, "sleep")
    @patch.object(oppo, "Http")
    def test_run_account_browse_task_full_chain(self, mock_http_cls, mock_sleep, mock_load_state, mock_save_state):
        """App 模式全链路：动态场次发现 → 落地页驻留 → 上报 → 领奖（pointsNum 兜底）。"""
        mock_load_state.return_value = {}
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http
        mock_http.jar = CookieJar()

        tokensid = _make_fake_tokensid(int(time.time()) + 30 * 86400)
        task = {
            "taskId": "1111222233334444",
            "taskName": "逛逛11.11主会场",
            "taskType": 1,
            "taskStatus": 1,
            "userEventStatus": None,
            "attachConfigOne": {"browseTime": 5},
            "attachConfigTwo": {"link": "https://hd.opposhop.cn/bp/fakebrowsepage"},
            "actionUrl": "https://hd.opposhop.cn/bp/fakebrowsepage",
            "awardAttachConfig": {"pointsNum": "2"},
        }
        calls: list = []

        def mock_request(method, url, **kwargs):
            calls.append((method, url))
            resp = MagicMock()
            resp.code = 200
            if "/bp/b371ce270f7509f0" in url:
                resp.text = _SYNTHETIC_PAGE_HTML
            elif "getSignInDetail" in url:
                today = datetime.now(BJT).strftime("%Y-%m-%d")
                resp.json.return_value = {"code": 200, "data": {
                    "baseAwards": [{"signTime": today, "awardType": 1, "awardValue": "2"}],
                    "cumulativeAwards": [],
                }}
            elif "cumulativeSignIn/signIn" in url:
                # 响应不带可解析积分字段 → 回退 baseAwards 今日档位（2 分）
                resp.json.return_value = {"code": 200, "data": {}}
            elif "queryTaskList" in url:
                resp.json.return_value = {"code": 200, "data": {"taskDTOList": [task]}}
            elif "signInOrShareTask" in url:
                resp.json.return_value = {"code": 200, "data": 200}
            elif "receiveAward" in url:
                # 响应无 awardValue → 回退任务配置 pointsNum=2
                resp.json.return_value = {"code": 200, "data": {"receiveStatus": 1}}
            elif "queryMemberCreditInfo" in url:
                resp.json.return_value = {"code": 200, "data": {"amount": 12, "userLevel": 51}}
            else:
                resp.json.return_value = {}
            return resp

        mock_http.request.side_effect = mock_request

        ok, desc = oppo._run_account(f"TOKENSID={tokensid}", 1, 1)
        self.assertTrue(ok)
        self.assertIn("刷完 1 个任务 (+2分)", desc)

        joined = [u for _, u in calls]
        # 场次动态发现：请求均使用页面 taskActivityInfo 中发现的任务场次
        self.assertTrue(any("queryTaskList?activityId=1919591795180969984" in u for u in joined))
        self.assertTrue(any("getSignInDetail?activityId=2116078703745441792" in u for u in joined))
        # 链路顺序：落地页 GET → 上报 → 领奖
        self.assertIn(("GET", "https://hd.opposhop.cn/bp/fakebrowsepage"), calls)
        link_idx = next(i for i, (m, u) in enumerate(calls) if u.endswith("/bp/fakebrowsepage"))
        report_idx = next(i for i, (m, u) in enumerate(calls) if "signInOrShareTask" in u)
        award_idx = next(i for i, (m, u) in enumerate(calls) if "receiveAward" in u)
        self.assertLess(link_idx, report_idx)
        self.assertLess(report_idx, award_idx)

    @patch.object(oppo, "save_kv_state")
    @patch.object(oppo, "load_kv_state")
    @patch.object(oppo.time, "sleep")
    @patch.object(oppo, "Http")
    def test_run_account_user_event_direct_claim(self, mock_http_cls, mock_sleep, mock_load_state, mock_save_state):
        """userEventStatus==1（如打开通知）直领：成功入账 + 失败容错（无 ⚠️ 领奖失败行）。"""
        mock_load_state.return_value = {}
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http
        mock_http.jar = CookieJar()

        tokensid = _make_fake_tokensid(int(time.time()) + 30 * 86400)
        task = {
            "taskId": "9999888877776666",
            "taskName": "打开消息通知",
            "taskType": 23,
            "taskStatus": 1,
            "userEventStatus": 1,
            "awardAttachConfig": {"pointsNum": "20"},
        }

        def make_request(award_json):
            def mock_request(method, url, **kwargs):
                resp = MagicMock()
                resp.code = 200
                if "/bp/b371ce270f7509f0" in url:
                    resp.text = _SYNTHETIC_PAGE_HTML
                elif "getSignInDetail" in url:
                    resp.json.return_value = {"code": 200, "data": {"cumulativeAwards": []}}
                elif "cumulativeSignIn/signIn" in url:
                    resp.json.return_value = {"code": 200, "data": {"awardValue": "2"}}
                elif "queryTaskList" in url:
                    resp.json.return_value = {"code": 200, "data": {"taskDTOList": [task]}}
                elif "receiveAward" in url:
                    resp.json.return_value = award_json
                elif "queryMemberCreditInfo" in url:
                    resp.json.return_value = {"code": 200, "data": {"amount": 20, "userLevel": 51}}
                else:
                    resp.json.return_value = {}
                return resp
            return mock_request

        # 成功分支：直领入账 20 分，且未走 signInOrShareTask 上报
        mock_http.request.side_effect = make_request({"code": 200, "data": {"receiveStatus": 1}})
        ok, desc = oppo._run_account(f"TOKENSID={tokensid}", 1, 1)
        self.assertTrue(ok)
        self.assertIn("刷完 1 个任务 (+20分)", desc)
        urls = [c.args[1] for c in mock_http.request.call_args_list]
        self.assertFalse(any("signInOrShareTask" in u for u in urls))

        # 失败分支：容错降级为 info（不得出现 ⚠️ 领奖失败，避免污染 error_lines）
        mock_http.request.side_effect = make_request({"code": 500, "message": "系统繁忙"})
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ok2, desc2 = oppo._run_account(f"TOKENSID={tokensid}", 1, 1)
        self.assertTrue(ok2)
        self.assertIn("刷完 0 个任务 (+0分)", desc2)
        self.assertNotIn("领奖失败", buf.getvalue())
        self.assertIn("暂不可领", buf.getvalue())

    @patch.object(oppo, "save_kv_state")
    @patch.object(oppo, "load_kv_state")
    @patch.object(oppo.time, "sleep")
    @patch.object(oppo, "Http")
    def test_run_account_second_pass_claim(self, mock_http_cls, mock_sleep, mock_load_state, mock_save_state):
        """二次补领：首轮上报失败跳过的任务，收尾重查后状态流转到 2 时补领成功。"""
        mock_load_state.return_value = {}
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http
        mock_http.jar = CookieJar()

        tokensid = _make_fake_tokensid(int(time.time()) + 30 * 86400)
        task_first = {
            "taskId": "5555666677778888",
            "taskName": "浏览活动中心",
            "taskType": 1,
            "taskStatus": 1,
            "attachConfigOne": {"browseTime": 0},
            "attachConfigTwo": {},
            "awardAttachConfig": {"pointsNum": "1"},
        }
        query_calls = {"n": 0}

        def mock_request(method, url, **kwargs):
            resp = MagicMock()
            resp.code = 200
            if "/bp/b371ce270f7509f0" in url:
                resp.text = _SYNTHETIC_PAGE_HTML
            elif "getSignInDetail" in url:
                resp.json.return_value = {"code": 200, "data": {"cumulativeAwards": []}}
            elif "cumulativeSignIn/signIn" in url:
                resp.json.return_value = {"code": 200, "data": {"awardValue": "2"}}
            elif "queryTaskList" in url:
                query_calls["n"] += 1
                dto = dict(task_first)
                if query_calls["n"] >= 2:
                    dto["taskStatus"] = 2  # 收尾重查时已流转到待领奖
                resp.json.return_value = {"code": 200, "data": {"taskDTOList": [dto]}}
            elif "signInOrShareTask" in url:
                resp.json.return_value = {"code": 200, "data": 500, "message": "请先浏览页面后再上报"}
            elif "receiveAward" in url:
                resp.json.return_value = {"code": 200, "data": {"receiveStatus": 1}}
            elif "queryMemberCreditInfo" in url:
                resp.json.return_value = {"code": 200, "data": {"amount": 33, "userLevel": 51}}
            else:
                resp.json.return_value = {}
            return resp

        mock_http.request.side_effect = mock_request

        ok, desc = oppo._run_account(f"TOKENSID={tokensid}", 1, 1)
        self.assertTrue(ok)
        self.assertIn("刷完 1 个任务 (+1分)", desc)
        self.assertEqual(query_calls["n"], 2)

    @patch.object(oppo, "save_kv_state")
    @patch.object(oppo, "load_kv_state")
    @patch.object(oppo.time, "sleep")
    @patch.object(oppo, "Http")
    def test_run_account_second_pass_skips_attempted_tasks(self, mock_http_cls, mock_sleep, mock_load_state, mock_save_state):
        """首轮已尝试领奖的失败任务，二次补领不得在脚本内重试（交框架重试梯子）。"""
        mock_load_state.return_value = {}
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http
        mock_http.jar = CookieJar()

        tokensid = _make_fake_tokensid(int(time.time()) + 30 * 86400)
        task = {
            "taskId": "2222333344445555",
            "taskName": "浏览教育优惠",
            "taskType": 1,
            "taskStatus": 2,  # 直接处于待领奖状态
            "attachConfigOne": {"browseTime": 0},
            "attachConfigTwo": {},
            "awardAttachConfig": {"pointsNum": "2"},
        }
        award_calls = {"n": 0}

        def mock_request(method, url, **kwargs):
            resp = MagicMock()
            resp.code = 200
            if "/bp/b371ce270f7509f0" in url:
                resp.text = _SYNTHETIC_PAGE_HTML
            elif "getSignInDetail" in url:
                resp.json.return_value = {"code": 200, "data": {"cumulativeAwards": []}}
            elif "cumulativeSignIn/signIn" in url:
                resp.json.return_value = {"code": 200, "data": {"awardValue": "2"}}
            elif "queryTaskList" in url:
                resp.json.return_value = {"code": 200, "data": {"taskDTOList": [dict(task)]}}
            elif "receiveAward" in url:
                award_calls["n"] += 1
                resp.json.return_value = {"code": 500, "message": "系统繁忙"}
            elif "queryMemberCreditInfo" in url:
                resp.json.return_value = {"code": 200, "data": {"amount": 4, "userLevel": 51}}
            else:
                resp.json.return_value = {}
            return resp

        mock_http.request.side_effect = mock_request

        ok, desc = oppo._run_account(f"TOKENSID={tokensid}", 1, 1)
        self.assertTrue(ok)
        self.assertIn("刷完 0 个任务 (+0分)", desc)
        self.assertEqual(award_calls["n"], 1)  # 首轮 1 次，二次补领不再重试

    # ---------- 多账号循环 / 退出码语义 ----------

    @patch.dict(os.environ, {"OPPO_COOKIE_1": "TOKENSID=V1.0FAKE_cookie_one", "OPPO_COOKIE_2": "TOKENSID=V1.0FAKE_cookie_two"})
    @patch.object(oppo.time, "sleep")
    def test_main_any_account_failure_exits_nonzero(self, mock_sleep):
        """任一账号失败即整体失败（对齐 ima 先例），且两账号均被处理、账号间错峰生效。"""
        with patch.object(oppo, "_run_account", side_effect=[(True, "ok1"), (False, "bad")]) as m_run:
            with self.assertRaises(SystemExit) as cm:
                oppo.main()
        self.assertEqual(cm.exception.code, 1)
        self.assertEqual(m_run.call_count, 2)
        self.assertTrue(mock_sleep.called)  # 账号 2 前有随机错峰等待

    @patch.dict(os.environ, {"OPPO_COOKIE_1": "TOKENSID=V1.0FAKE_cookie_one", "OPPO_COOKIE_2": "TOKENSID=V1.0FAKE_cookie_two"})
    @patch.object(oppo.time, "sleep")
    def test_main_all_success_exits_zero(self, mock_sleep):
        with patch.object(oppo, "_run_account", side_effect=[(True, "ok1"), (True, "ok2")]):
            oppo.main()  # 不抛 SystemExit 即成功

    # ---------- 报告提取：实际积分口径 ----------

    def test_report_fields_ex_oppo_actual_points(self):
        output = """
[1/1] 👤 用户: 139***2015
  🎉 签到成功！获得 +2 积分
  💰 账户积分余额: 12 (Lv.51)
"""
        res = extract_for("oppo.py", output)
        self.assertTrue(any("签到成功 (+2 积分)" in line for line in res["lines"]))
        self.assertIn(("积分", 2.0), res["gains"])
        self.assertIn(("reward", "签到 +2 积分"), res["badges"])
        self.assertIn(("积分", 12.0), res["assets"])

    def test_report_fields_ex_oppo_multi_account_task_isolation(self):
        """多账号：任务完成数/积分按账号块独立归集（回归：不得把账号1的量累计到账号2行）。"""
        output = """
[1/2] 👤 用户: 100***434（张***）
  🎉 签到成功！获得 +20 积分
    🎉 领奖成功: 逛逛11.11主会场 (+1 积分)
    🎉 领奖成功: 浏览活动中心 (+2 积分)
  💰 账户积分余额: 552 (Lv.54)

⏳ 账号间随机错峰 21s ...

[2/2] 👤 用户: 139***2015
  🎉 签到成功！获得 +2 积分
    🎉 领奖成功: 浏览新品平板 (+1 积分)
  💰 账户积分余额: 14 (Lv.51)
==================================================
🏁 执行完毕: 成功 2/2 个账号
==================================================
"""
        res = extract_for("oppo.py", output)
        self.assertTrue(any("完成 2 项日常任务 (+3分)" in line for line in res["lines"]))
        self.assertTrue(any("完成 1 项日常任务 (+1分)" in line for line in res["lines"]))
        self.assertEqual(
            [g for g in res["gains"] if g[0] == "积分"],
            [("积分", 20.0), ("积分", 3.0), ("积分", 2.0), ("积分", 1.0)],
        )

    def test_report_fields_ex_oppo_sign_without_points_number(self):
        output = """
[1/1] 👤 用户: 139***2015
  🎉 签到成功！
  💰 账户积分余额: 5 (Lv.51)
"""
        res = extract_for("oppo.py", output)
        self.assertTrue(any("签到成功" in line and "+2" not in line and "+10" not in line for line in res["lines"]))
        point_gains = [g for g in res["gains"] if g[0] == "积分" and g[1] not in (5.0,)]
        self.assertEqual(point_gains, [])


if __name__ == "__main__":
    unittest.main()
