#!/usr/bin/env python3
"""OPPO 商城 (HeyTap) 签到与无感续期单元测试。

测试覆盖：
1. JWT 令牌 Payload 与 exp 过期时间提取
2. Cookie 键值解析、序列化与 memberinfo 用户信息提取
3. HeyTap Web SDK 规范 PKCE 密钥对生成 (codeVerifier, codeChallenge)
4. 基于 acIdAuthSession 根凭据的 SSO 换票与会话更新全流程 Mock
5. 凭证缺失或失效时的降级与异常处理
6. report_fields 中 ex_oppo 的报告提取逻辑验证
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
import unittest
import urllib.parse
from http.cookiejar import CookieJar
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import oppo
from report_fields import extract_for


def _make_mock_jwt(payload: dict) -> str:
    header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8")).decode("utf-8").rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")
    signature_b64 = base64.urlsafe_b64encode(b"synthetic_mock_sig").decode("utf-8").rstrip("=")
    return f"{header_b64}.{payload_b64}.{signature_b64}"


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


if __name__ == "__main__":
    unittest.main()
