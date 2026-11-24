#!/usr/bin/env python3
"""中国电信签到脚本单元测试。"""
from __future__ import annotations

import io
import http.client
import json
import os
import subprocess
import sys
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import telecom
from report_fields import extract_for


class TestTelecom(unittest.TestCase):
    def test_request_exception_does_not_expose_credentials(self):
        secret = "synthetic-private-ticket"
        url = f"https://user:synthetic-password@wappark.189.cn/jt-sign/ssoHomLogin?ticket={secret}#private-fragment"
        for debug in ("", "1"):
            with self.subTest(debug=debug):
                transport = MagicMock()
                transport.request.side_effect = ValueError(f"failed {url} Cookie: private-cookie")
                client = telecom.TelecomClient(telecom.TelecomAccount(index=1), transport)
                with patch.dict(os.environ, {"DEBUG": debug}), patch("sys.stdout", new_callable=io.StringIO) as out:
                    result = client._req("GET", url)
                self.assertEqual(result, {"code": -1, "msg": "ValueError", "_http_error": True})
                if debug:
                    self.assertIn("https://wappark.189.cn/jt-sign/ssoHomLogin: ValueError", out.getvalue())
                else:
                    self.assertEqual(out.getvalue(), "")
                for value in (secret, "synthetic-password", "private-fragment", "private-cookie"):
                    self.assertNotIn(value, out.getvalue() + json.dumps(result))

    def test_exchange_ticket_urllib_read_failure_is_safe(self):
        # IncompleteRead escapes Http's OSError handling in the urllib backend.
        secret = "synthetic-private-ticket"
        transport = telecom.Http()
        transport.impersonate = None
        response = transport.opener.open = MagicMock()
        response.return_value.__enter__.return_value.read.side_effect = http.client.IncompleteRead(b"partial", 10)
        client = telecom.TelecomClient(telecom.TelecomAccount(index=1, ticket=secret), transport)
        for debug in ("", "1"):
            with self.subTest(debug=debug), patch.dict(os.environ, {"DEBUG": debug}), patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertFalse(client.exchange_ticket())
                self.assertNotIn(secret, out.getvalue())
                self.assertIn("IncompleteRead", out.getvalue())
        self.assertIn(f"ticket={secret}", response.call_args.args[0].full_url)

    def test_parse_account_key_value(self):
        """键值格式抓包串解析。"""
        raw = "phone=18912345678; sign=a1b2c3d4e5f67890a1b2c3d4e5f67890; authorization=Bearer test_jwt_token"
        acc = telecom._parse_account_config(raw, 1)
        self.assertEqual(acc.index, 1)
        self.assertEqual(acc.phone, "18912345678")
        self.assertEqual(acc.sign, "a1b2c3d4e5f67890a1b2c3d4e5f67890")
        self.assertEqual(acc.authorization, "Bearer test_jwt_token")
        self.assertTrue(acc.has_credentials())
        # 2026-10-31 脱敏增强：手机号只保留末 4 位（不再露出前 3 位号段）
        self.assertIn("*******5678", acc.display_name)

    def test_parse_account_json(self):
        """JSON 格式抓包串解析。"""
        raw = json.dumps({
            "phone": "13398765432",
            "sign": "f0e1d2c3b4a59687f0e1d2c3b4a59687",
            "authorization": "Bearer sample_token",
        })
        acc = telecom._parse_account_config(raw, 2)
        self.assertEqual(acc.index, 2)
        self.assertEqual(acc.phone, "13398765432")
        self.assertEqual(acc.sign, "f0e1d2c3b4a59687f0e1d2c3b4a59687")
        self.assertEqual(acc.authorization, "Bearer sample_token")
        self.assertTrue(acc.has_credentials())

    def test_parse_account_multiline_headers(self):
        """多行 Header 抓包文本解析。"""
        raw = (
            "Host: wappark.189.cn\n"
            "sign: 99887766554433221100aabbccddeeff\n"
            "phone: 18011223344\n"
            "Authorization: Bearer token_multi_header\n"
        )
        acc = telecom._parse_account_config(raw, 3)
        self.assertEqual(acc.phone, "18011223344")
        self.assertEqual(acc.sign, "99887766554433221100aabbccddeeff")
        self.assertEqual(acc.authorization, "Bearer token_multi_header")

    def test_parse_account_shorthand(self):
        """简写格式解析。"""
        raw = "18900112233#sign_secret_token_1234567890123#Bearer my_auth"
        acc = telecom._parse_account_config(raw, 1)
        self.assertEqual(acc.phone, "18900112233")
        self.assertEqual(acc.sign, "sign_secret_token_1234567890123")
        self.assertEqual(acc.authorization, "Bearer my_auth")

    def test_load_all_accounts_from_env(self):
        """环境变量序列加载。"""
        fake_env = {
            "TELECOM_HEADER_1": "phone=18911112222; sign=sign_token_user_one",
            "TELECOM_HEADER_2": "phone=18933334444; sign=sign_token_user_two",
        }
        with patch.dict(os.environ, fake_env, clear=True):
            accounts = telecom.load_all_accounts()
            self.assertEqual(len(accounts), 2)
            self.assertEqual(accounts[0].phone, "18911112222")
            self.assertEqual(accounts[0].sign, "sign_token_user_one")
            self.assertEqual(accounts[1].phone, "18933334444")
            self.assertEqual(accounts[1].sign, "sign_token_user_two")

    def test_load_all_accounts_multiline(self):
        """多行抓包整串应保持单账号而不被按行拆分。"""
        multiline_capture = (
            "HTTP/2 200\n"
            "server: openresty\n"
            "content-type: application/json\n\n"
            '{"userNum":"mock_user_num_aabbccddeeff1122","resoultCode":"0",'
            '"sign":"mock_sign_token_aabbccddeeff1122","accId":"xxx","resoultMsg":"请求成功"}'
        )
        fake_env = {"TELECOM_HEADER_1": multiline_capture}
        with patch.dict(os.environ, fake_env, clear=True):
            accounts = telecom.load_all_accounts()
            self.assertEqual(len(accounts), 1)
            self.assertEqual(accounts[0].sign, "mock_sign_token_aabbccddeeff1122")

    def test_parse_full_http_request_with_cookies(self):
        """完整 HTTP 请求抓包解析（全量虚拟 Mock 数据：Cookie、UA、distinct_id 手机号反解与 sign）。"""
        # MTg5MDAxMjM0NTY= 为虚拟手机号 18900123456 的 Base64
        # UA 中的 MTIzNDU2!#!MTg5MDA 为 18900 与 123456 的分段 Base64
        raw = (
            "POST /jt-sign/webSign/homepage HTTP/2\n"
            "host: wappark.189.cn\n"
            "user-agent: CtClient;13.4.0;Android;9;mock_device;MTIzNDU2!#!MTg5MDA\n"
            "sign: mock_sign_token_aabbccddeeff9988\n"
            "cookie: 3k9kkc0re5ZOO=mock_cookie_val_1\n"
            "cookie: zhizhendata2015jssdkcross=%7B%22distinct_id%22%3A%22MTg5MDAxMjM0NTY%3D%22%7D\n\n"
            '{"para":"mock_payload_data"}'
        )
        acc = telecom._parse_account_config(raw, 1)
        self.assertEqual(acc.sign, "mock_sign_token_aabbccddeeff9988")
        self.assertEqual(acc.phone, "18900123456")
        self.assertIn("CtClient;13.4.0", acc.user_agent)
        self.assertIn("3k9kkc0re5ZOO", acc.cookie)
        self.assertIn("zhizhendata2015jssdkcross", acc.cookie)
        self.assertTrue(acc.has_credentials())

    def test_load_all_accounts_empty(self):
        """缺省无凭证处理。"""
        with patch.dict(os.environ, {}, clear=True):
            accounts = telecom.load_all_accounts()
            self.assertEqual(accounts, [])

    def test_aes_encrypt(self):
        """AES 载荷加密与解密往返。"""
        if not telecom.HAS_CRYPTO:
            self.skipTest("缺少 pycryptodome 库，跳过测试")
        data = {"phone": "18912345678", "date": 1725700000000}
        enc_hex = telecom._encrypt_aes(data)
        self.assertTrue(len(enc_hex) > 0)
        self.assertEqual(len(enc_hex) % 32, 0)

        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad

        cipher = AES.new(telecom.AES_SIGN_KEY, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(bytes.fromhex(enc_hex)), 16)
        parsed = json.loads(decrypted.decode("utf-8"))
        self.assertEqual(parsed["phone"], "18912345678")
        self.assertEqual(parsed["date"], 1725700000000)

    def test_rsa_encrypt_chunked_hex(self):
        """RSA 分段加密格式验证。"""
        if not telecom.HAS_CRYPTO:
            self.skipTest("缺少 pycryptodome 库，跳过测试")
        data = {"phone": "18912345678", "shopId": "20001"}
        enc_hex = telecom._encrypt_rsa(data)
        self.assertTrue(len(enc_hex) >= 256)
        self.assertEqual(len(enc_hex) % 256, 0)
        self.assertRegex(enc_hex, r"^[0-9a-f]+$")

    def test_candidate_proxies_fallback(self):
        """CN 代理出口复用调度。"""
        fake_env = {
            "SMZDM_PROXY": "socks5://user:pass@114.114.114.114:1080#测试-CN出口",
        }
        with patch.dict(os.environ, fake_env, clear=True):
            proxies = telecom._get_candidate_proxies()
            self.assertTrue(len(proxies) >= 1)
            self.assertIn("测试-CN出口", proxies[0].name)
            self.assertEqual(proxies[0].protocol, "socks5")

    def test_execute_telecom_task_success(self):
        """业务流程执行模拟。"""
        if not telecom.HAS_CRYPTO:
            self.skipTest("缺少 pycryptodome 库，跳过测试")

        acc = telecom.TelecomAccount(
            index=1,
            phone="18912345678",
            sign="dummy_sign_token_1234567890123456",
            authorization="Bearer test_token",
        )
        mock_http = MagicMock()
        client = telecom.TelecomClient(acc, mock_http)

        def fake_req(method, url, headers=None, json_data=None, data=None, timeout=15):
            if "webSign/sign" in url:
                return {"code": 0, "msg": "签到成功 +10 金豆"}
            if "api/home/userStatusInfo" in url:
                return {"code": 0, "data": {"signDay": 7}}
            if "webSign/continueSignDays" in url:
                return {"code": 0, "data": {"continueSignDays": 15}}
            if "webSign/exchangePrize" in url:
                return {"code": 0, "msg": "成功领取连签奖励"}
            if "queryTurnTable" in url:
                return {"code": 0, "biz": {"wzTurntable": {"code": "act_turntable_001"}}}
            if "detail/check" in url:
                return {"code": 0, "biz": {"resultInfo": {"userMaximum": 1, "userCount": 0}}}
            if "golden/api/lottery" in url:
                return {"code": 0, "biz": {"prizeName": "100M全国流量日包"}}
            if "webSign/homepage" in url:
                return {"code": 0, "data": {"biz": {"adItems": [{"taskId": "t1", "taskState": "0", "contentOne": "18"}]}}}
            if "webSign/polymerize" in url:
                return {"code": 0, "msg": "任务完成成功"}
            if "paradise/food" in url:
                return {"code": 0, "resoultMsg": "喂食成功，已达今日上限"}
            if "paradise/getParadiseInfo" in url:
                return {"code": 0, "data": {"coin": 2580}}
            return {}

        client._req = MagicMock(side_effect=fake_req)
        with patch.object(client, "restore_cached_session", return_value=True), \
             patch.object(client, "save_session", return_value=None), \
             patch("sys.stdout", new_callable=io.StringIO):
            outcome = telecom.execute_telecom_task(client)

        self.assertEqual(outcome["status"], "成功")
        self.assertEqual(outcome["gain_bean"], 10)
        self.assertEqual(outcome["streak_days"], 7)
        self.assertEqual(outcome["lottery_res"], "100M全国流量日包")
        self.assertEqual(outcome["task_res"], "完成1项")
        self.assertEqual(outcome["food_res"], "喂食1次")
        self.assertEqual(outcome["total_bean"], "2580")

    def test_execute_telecom_task_expired_session(self):
        """401 未授权访问或会话失效时必须明确报错失败，绝不冒充完成。"""
        if not telecom.HAS_CRYPTO:
            self.skipTest("缺少 pycryptodome 库，跳过测试")

        acc = telecom.TelecomAccount(
            index=1,
            phone="18912345678",
            sign="expired_sign_token_123456789012345",
        )
        mock_http = MagicMock()
        client = telecom.TelecomClient(acc, mock_http)
        client._req = MagicMock(return_value={"code": "401", "msg": "未授权访问"})

        with patch.object(client, "restore_cached_session", return_value=True), \
             patch("sys.stdout", new_callable=io.StringIO):
            outcome = telecom.execute_telecom_task(client)

        self.assertEqual(outcome["status"], "失败")
        self.assertIn("会话已失效", outcome["error"])
        self.assertIn("未授权访问", outcome["error"])

    def test_execute_telecom_task_network_http_error(self):
        """网络异常或 WAF 412 时必须判定失败，触发代理重试或报错。"""
        if not telecom.HAS_CRYPTO:
            self.skipTest("缺少 pycryptodome 库，跳过测试")

        acc = telecom.TelecomAccount(
            index=1,
            phone="18912345678",
            sign="mock_sign_token_1234567890123456",
        )
        mock_http = MagicMock()
        client = telecom.TelecomClient(acc, mock_http)
        client._req = MagicMock(return_value={"code": 412, "msg": "HTTP 412", "_http_error": True})

        with patch.object(client, "restore_cached_session", return_value=True), \
             patch("sys.stdout", new_callable=io.StringIO):
            outcome = telecom.execute_telecom_task(client)

        self.assertEqual(outcome["status"], "失败")
        self.assertIn("网络请求异常", outcome["error"])

    def test_run_account_proxy_rotation(self):
        """主代理网络失败时应轮换到下一个候选代理并成功。"""
        acc = telecom.TelecomAccount(
            index=1,
            phone="18912345678",
            sign="mock_sign_token_1234567890123456",
        )
        ep1 = MagicMock()
        ep1.display_name = "主出口"
        ep1.url = "socks5://1.1.1.1:1080"
        ep2 = MagicMock()
        ep2.display_name = "备用出口"
        ep2.url = "socks5://2.2.2.2:1080"

        calls = []
        def fake_exec(client):
            calls.append(client.http)
            if len(calls) == 1:
                return {"status": "失败", "error": "网络请求异常（HTTP -1）"}
            return {
                "status": "成功",
                "gain_bean": 10,
                "streak_days": 1,
                "lottery_res": "",
                "task_res": "",
                "food_res": "",
                "total_bean": "100",
                "error": "",
            }

        with patch.object(telecom, "_get_candidate_proxies", return_value=[ep1, ep2]), \
             patch.object(telecom, "execute_telecom_task", side_effect=fake_exec), \
             patch("sys.stdout", new_callable=io.StringIO):
            ok, outcome = telecom._run_account(acc)

        self.assertTrue(ok)
        self.assertEqual(len(calls), 2)
        self.assertEqual(outcome["status"], "成功")

    def test_run_account_rotates_on_mint_network_failure(self):
        """现签因出口网络失败未取得 sign 时，必须轮换下一代理而非放弃。"""
        acc = telecom.TelecomAccount(index=1, phone="18912345678")
        ep1 = MagicMock()
        ep1.display_name = "主出口"
        ep1.url = "socks5://1.1.1.1:1080"
        ep2 = MagicMock()
        ep2.display_name = "备用出口"
        ep2.url = "socks5://2.2.2.2:1080"

        calls = []
        def fake_exec(client):
            calls.append(client.http)
            if len(calls) == 1:
                return {"status": "失败",
                        "error": "网络请求异常（现签未取得 sign：出口连接失败或被 WAF 拦截）"}
            return {"status": "成功", "gain_bean": 10, "streak_days": 1,
                    "lottery_res": "", "task_res": "", "food_res": "",
                    "total_bean": "100", "error": ""}

        with patch.object(telecom, "_get_candidate_proxies", return_value=[ep1, ep2]), \
             patch.object(telecom, "execute_telecom_task", side_effect=fake_exec), \
             patch("sys.stdout", new_callable=io.StringIO):
            ok, outcome = telecom._run_account(acc)

        self.assertTrue(ok)
        self.assertEqual(len(calls), 2)
        self.assertEqual(outcome["status"], "成功")

    def test_run_account_no_rotation_on_real_missing_credentials(self):
        """真正缺少凭据（prepare_auth 失败）仍应直接放弃，不轮换烧尝试次数。"""
        acc = telecom.TelecomAccount(index=1, phone="18912345678")
        ep1 = MagicMock()
        ep1.display_name = "主出口"
        ep1.url = "socks5://1.1.1.1:1080"

        calls = []
        def fake_exec(client):
            calls.append(client.http)
            return {"status": "失败", "error": "缺少 App 抓包凭据（请在 TELECOM_HEADER_1 配置抓包整串）"}

        with patch.object(telecom, "_get_candidate_proxies", return_value=[ep1]), \
             patch.object(telecom, "execute_telecom_task", side_effect=fake_exec), \
             patch("sys.stdout", new_callable=io.StringIO):
            ok, outcome = telecom._run_account(acc)

        self.assertFalse(ok)
        self.assertEqual(len(calls), 1)
        self.assertIn("缺少 App 抓包凭据", outcome["error"])

    def test_mint_network_failure_flag_on_timeout(self):
        """mint 遇到连接超时/-1 响应时必须置 mint_network_failure 标记。"""
        if not telecom.HAS_CRYPTO:
            self.skipTest("缺少 pycryptodome 库，跳过测试")
        from common import Response

        acc = telecom.TelecomAccount(
            index=1, phone="13800138000",
            app_token="V1.0ABC", uid="1000000001", target_id="fake0000",
        )
        mock_http = MagicMock()
        mock_http.request = MagicMock(return_value=Response(-1, None, b"", "url"))
        client = telecom.TelecomClient(acc, mock_http)
        with patch("sys.stdout", new_callable=io.StringIO):
            ok = client.mint_ticket_with_token()
        self.assertFalse(ok)
        self.assertTrue(client.mint_network_failure)

    def test_is_credential_desc_patterns(self):
        """密码类硬错误关键词判定（正向/负向）。"""
        self.assertTrue(telecom._is_credential_desc("用户密码错误，请重新输入"))
        self.assertTrue(telecom._is_credential_desc("弱密码，请点击“忘记密码”重置您的密码后登录"))
        self.assertTrue(telecom._is_credential_desc("密码已被锁定，请24小时后再试"))
        self.assertTrue(telecom._is_credential_desc("账号不存在"))
        self.assertFalse(telecom._is_credential_desc("登录未成功"))
        self.assertFalse(telecom._is_credential_desc("网络超时，请稍后重试"))
        self.assertFalse(telecom._is_credential_desc(""))
        self.assertFalse(telecom._is_credential_desc(None))

    def test_login_credential_error_flagged(self):
        """userLoginNormal 返回密码类硬错误时必须打上 credential_error 标记。"""
        if not telecom.HAS_CRYPTO:
            self.skipTest("缺少 pycryptodome 库，跳过测试")

        from common import Response
        acc = telecom.TelecomAccount(index=1, phone="18912345678", password="000000")
        mock_http = MagicMock()
        body = json.dumps({
            "responseData": {
                "resultCode": "8105",
                "resultDesc": "弱密码，请点击“忘记密码”重置您的密码后登录",
                "data": None,
            }
        }).encode("utf-8")
        mock_http.request = MagicMock(return_value=Response(200, None, body, "url"))
        client = telecom.TelecomClient(acc, mock_http)
        with patch("sys.stdout", new_callable=io.StringIO):
            ok = client.login_with_password()
        self.assertFalse(ok)
        self.assertIn("弱密码", client.credential_error)

    def test_execute_blocks_retry_after_credential_error(self):
        """credential_error 置位后 execute_telecom_task 必须直接失败且不再触发登录。"""
        acc = telecom.TelecomAccount(
            index=1, phone="18912345678", sign="mock_sign_token_1234567890123456", password="000000",
        )
        client = telecom.TelecomClient(acc, MagicMock())
        client.credential_error = "用户密码错误"
        with patch.object(client, "prepare_auth", return_value=True), \
             patch("sys.stdout", new_callable=io.StringIO):
            outcome = telecom.execute_telecom_task(client)
        self.assertEqual(outcome["status"], "失败")
        self.assertIn("服务密码凭证错误", outcome["error"])
        self.assertIn("用户密码错误", outcome["error"])

    def test_run_account_trips_breaker_on_credential_error(self):
        """密码类硬错误必须立即熔断当日重试（防服务密码连错锁定 24h）。"""
        acc = telecom.TelecomAccount(
            index=1, phone="18912345678", sign="mock_sign_token_1234567890123456", password="000000",
        )
        with patch.object(telecom, "_get_candidate_proxies", return_value=[]), \
             patch.object(telecom, "execute_telecom_task",
                          return_value={"status": "失败",
                                        "error": "服务密码凭证错误（用户密码错误）——已停止当日重试"}), \
             patch.object(telecom, "trip_circuit_breaker") as mock_trip, \
             patch("sys.stdout", new_callable=io.StringIO):
            ok, _ = telecom._run_account(acc)
        self.assertFalse(ok)
        mock_trip.assert_called_once()
        self.assertEqual(mock_trip.call_args.args[0], "telecom")
        self.assertIn("服务密码凭证错误", mock_trip.call_args.kwargs.get("reason", ""))

    def test_token_only_account_passes_credential_filter(self):
        """仅持 token 三件套的账号必须被 load_all_accounts/has_credentials 认可（CI 回归）。"""
        acc = telecom._parse_account_config(
            "phone=13800138000; "
            "token=V1.0FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE; "
            "uid=1000000001; target=deadbeefcafebabe0123456789abcdef00",
            1,
        )
        self.assertTrue(acc.has_credentials())

    def test_parse_token_triple(self):
        """App 长效 Token 三件套（token/uid/target）解析。"""
        acc = telecom._parse_account_config(
            "phone=13800138000; "
            "token=V1.0FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE; "
            "uid=1000000001; "
            "target=deadbeefcafebabe0123456789abcdef00",
            1,
        )
        self.assertEqual(acc.phone, "13800138000")
        self.assertTrue(acc.app_token.startswith("V1.0"))
        self.assertEqual(acc.uid, "1000000001")
        self.assertEqual(acc.target_id, "deadbeefcafebabe0123456789abcdef00")
        # token 不得被误吞为 authorization
        self.assertEqual(acc.authorization, "")

    def test_build_getsingle_xml(self):
        """getSingle XML 模板必须与 App 抓包结构一致（UserLoginName 带尾分号）。"""
        xml = telecom._build_getsingle_xml("V1.0ABC", "1000000001", "fake0000", "20260919020000")
        self.assertIn("<Code>getSingle</Code>", xml)
        self.assertIn("<Timestamp>20260919020000</Timestamp>", xml)
        self.assertIn("<Token>V1.0ABC</Token>", xml)
        self.assertIn("<UserLoginName>1000000001;</UserLoginName>", xml)
        self.assertIn("<TargetId>fake0000</TargetId>", xml)
        self.assertIn("<SourcePassword>Sid98s</SourcePassword>", xml)

    def test_mint_ticket_with_token(self):
        """Token 现签：解析 Ticket（3DES）并经 ssoHomLogin 换 sign 的完整链路。"""
        if not telecom.HAS_CRYPTO:
            self.skipTest("缺少 pycryptodome 库，跳过测试")

        from Crypto.Cipher import DES3
        from Crypto.Util.Padding import pad
        from common import Response

        plain_ticket = "48cb5b01testticketplaintext0123456789abcdef"
        des = DES3.new(telecom.KEY_3DES, DES3.MODE_CBC, telecom.IV_3DES)
        ticket_hex = des.encrypt(pad(plain_ticket.encode(), DES3.block_size)).hex()
        xml_resp = (
            '<Response><HeaderInfos><Code>0000</Code><Reason>成功</Reason></HeaderInfos>'
            f'<ResponseData><ResultCode>0000</ResultCode><Data><Ticket>{ticket_hex}</Ticket>'
            '</Data></ResponseData></Response>'
        )

        acc = telecom.TelecomAccount(
            index=1, phone="13800138000",
            app_token="V1.0ABC", uid="1000000001", target_id="fake0000",
        )
        mock_http = MagicMock()
        mock_http.request = MagicMock(return_value=Response(200, None, xml_resp.encode(), "url"))
        client = telecom.TelecomClient(acc, mock_http)
        client._req = MagicMock(return_value={"resoultCode": "0", "sign": "f" * 32})
        with patch("sys.stdout", new_callable=io.StringIO):
            ok = client.mint_ticket_with_token()
        self.assertTrue(ok)
        self.assertEqual(client.ticket, plain_ticket)
        self.assertEqual(client.sign, "f" * 32)

    def test_prepare_auth_mints_fresh_session_over_stale_cache(self):
        """持有 Token 三件套时必须先现签：陈旧缓存 sign 不得抢跑（wappark 对死会话 412 短路）。"""
        acc = telecom.TelecomAccount(
            index=1, phone="13800138000",
            app_token="V1.0ABC", uid="1000000001", target_id="fake0000",
        )
        client = telecom.TelecomClient(acc, MagicMock())
        client.sign = "stale_sign_from_2_days_ago_12345678"
        client.cookie = "acw_sc__v2=stale_clearance"
        client._cookie_from_cache = True
        with patch.object(client, "restore_cached_session", return_value=True), \
             patch.object(client, "mint_ticket_with_token", return_value=True) as m_mint, \
             patch.object(client, "exchange_ticket", return_value=True) as m_exchange, \
             patch.object(client, "login_with_password", return_value=False) as m_pwd, \
             patch("sys.stdout", new_callable=io.StringIO):
            ok = client.prepare_auth()
        self.assertTrue(ok)
        m_mint.assert_called_once()
        m_exchange.assert_not_called()
        m_pwd.assert_not_called()
        self.assertEqual(client.cookie, "")

    def test_prepare_auth_preserves_header_provided_cookie(self):
        """用户 HEADER 抓包提供的 cookie（非缓存来源）不得被清理。"""
        acc = telecom.TelecomAccount(
            index=1, phone="13800138000",
            app_token="V1.0ABC", uid="1000000001", target_id="fake0000",
        )
        client = telecom.TelecomClient(acc, MagicMock())
        client.cookie = "cookie_from_header_capture=1"
        with patch.object(client, "restore_cached_session", return_value=True), \
             patch.object(client, "mint_ticket_with_token", return_value=True), \
             patch.object(client, "exchange_ticket", return_value=True), \
             patch("sys.stdout", new_callable=io.StringIO):
            ok = client.prepare_auth()
        self.assertTrue(ok)
        self.assertEqual(client.cookie, "cookie_from_header_capture=1")

    def test_prepare_auth_falls_back_to_cached_sign_when_mint_fails(self):
        """现签失败（如 Token 过期）时回退缓存 sign，不再重复换票。"""
        acc = telecom.TelecomAccount(
            index=1, phone="13800138000",
            app_token="V1.0ABC", uid="1000000001", target_id="fake0000",
        )
        client = telecom.TelecomClient(acc, MagicMock())
        client.sign = "cached_sign_still_valid_1234567890"
        with patch.object(client, "restore_cached_session", return_value=True), \
             patch.object(client, "mint_ticket_with_token", return_value=False) as m_mint, \
             patch.object(client, "exchange_ticket", return_value=True) as m_exchange, \
             patch("sys.stdout", new_callable=io.StringIO):
            ok = client.prepare_auth()
        self.assertTrue(ok)
        m_mint.assert_called_once()
        m_exchange.assert_not_called()
        self.assertEqual(client.sign, "cached_sign_still_valid_1234567890")

    def test_prepare_auth_uses_cached_ticket_when_mint_fails_without_sign(self):
        """现签失败且无缓存 sign 时，回退缓存 ticket 换票老路。"""
        acc = telecom.TelecomAccount(
            index=1, phone="13800138000",
            app_token="V1.0ABC", uid="1000000001", target_id="fake0000",
        )
        client = telecom.TelecomClient(acc, MagicMock())
        client.ticket = "c" * 256
        with patch.object(client, "restore_cached_session", return_value=True), \
             patch.object(client, "mint_ticket_with_token", return_value=False), \
             patch.object(client, "exchange_ticket", return_value=True) as m_exchange, \
             patch("sys.stdout", new_callable=io.StringIO):
            ok = client.prepare_auth()
        self.assertTrue(ok)
        m_exchange.assert_called_once()

    def test_prepare_auth_without_token_keeps_legacy_order(self):
        """无 Token 三件套的老配置（ticket 路线）不受影响：缓存 ticket 照常换票。"""
        acc = telecom.TelecomAccount(index=1, phone="13800138000")
        client = telecom.TelecomClient(acc, MagicMock())
        client.ticket = "c" * 256
        with patch.object(client, "restore_cached_session", return_value=True), \
             patch.object(client, "exchange_ticket", return_value=True) as m_exchange, \
             patch("sys.stdout", new_callable=io.StringIO):
            ok = client.prepare_auth()
        self.assertTrue(ok)
        m_exchange.assert_called_once()

    def test_restore_cached_session_rejects_truncated_ua(self):
        """状态恢复的截断 UA 必须弃用（wappark WAF 对非完整浏览器 UA 一律 412）。"""
        acc = telecom.TelecomAccount(index=1, phone="13800138000")
        client = telecom.TelecomClient(acc, MagicMock())
        state = {
            "sign": "s" * 32,
            "user_agent": "Mozilla/5.0 (Linux; Android 12; zh-cn)",
            "updated_at": "2026-09-17 07:07:53",
        }
        with patch("telecom.load_kv_state", return_value=state), \
             patch("sys.stdout", new_callable=io.StringIO):
            ok = client.restore_cached_session()
        self.assertTrue(ok)
        self.assertEqual(client.user_agent, "")

    def test_restore_cached_session_accepts_full_ua(self):
        """完整浏览器 UA（Mozilla+AppleWebKit+Safari）应正常恢复采用。"""
        acc = telecom.TelecomAccount(index=1, phone="13800138000")
        client = telecom.TelecomClient(acc, MagicMock())
        ua = ("Mozilla/5.0 (Linux; U; Android 12; zh-cn) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Version/4.0 Mobile Safari/537.36 CtClient;10.4.1")
        state = {
            "sign": "s" * 32,
            "user_agent": ua,
            "updated_at": "2026-09-17 07:07:53",
        }
        with patch("telecom.load_kv_state", return_value=state), \
             patch("sys.stdout", new_callable=io.StringIO):
            ok = client.restore_cached_session()
        self.assertTrue(ok)
        self.assertEqual(client.user_agent, ua)

    def test_candidate_proxies_include_singbox_fallback(self):
        """sing-box 统一出站应作为电信候选兜底（排在 CN 家宽之后）。"""
        env = {
            "TELECOM_PROXY": "http://113.9.9.9:8080#电信家宽",
            "SINGBOX_SOCKS_URL": "socks5://127.0.0.1:1080",
        }
        with patch.dict(os.environ, env, clear=True):
            eps = telecom._get_candidate_proxies()
        urls = [ep.url for ep in eps]
        self.assertEqual(urls[0], "http://113.9.9.9:8080")
        self.assertIn("socks5://127.0.0.1:1080", urls)

    def test_candidate_proxies_dedup_singbox(self):
        """sing-box 出口若与既有候选重复则不重复加入。"""
        env = {
            "TELECOM_PROXY": "socks5://127.0.0.1:1080#同址出口",
            "SINGBOX_SOCKS_URL": "socks5://127.0.0.1:1080",
        }
        with patch.dict(os.environ, env, clear=True):
            eps = telecom._get_candidate_proxies()
        self.assertEqual([ep.url for ep in eps].count("socks5://127.0.0.1:1080"), 1)

    def test_report_fields_extractor(self):
        """报告字段解析器提取验证。"""
        sample_output = """
【中国电信 签到】
[proxy] 已加载境内 CN 代理出口: 电信CN代理#1

👤 用户: 【189****1234】
• 签到: 【成功】 (+10 金豆) 连签天数: 【7】天
• 抽奖: 【100M全国流量日包】
• 任务: 【完成1项】
• 乐园: 【喂食1次】
• 资产: 金豆 【2,580】

总结：成功 1/1
"""
        res = extract_for("telecom.py", sample_output)
        self.assertEqual(len(res["lines"]), 1)
        self.assertIn("189****1234", res["lines"][0])
        self.assertIn("签到成功", res["lines"][0])
        self.assertIn("+10金豆", res["lines"][0])
        self.assertIn("连签 7 天", res["lines"][0])
        self.assertIn("金豆 2,580", res["lines"][0])

        self.assertEqual(res["streak"], 7)
        self.assertIn(("金豆", 10.0), res["gains"])
        self.assertIn(("金豆", 2580.0), res["assets"])
        self.assertIn(("reward", "+10 金豆"), res["badges"])
        self.assertIn(("streak", "连签 7 天"), res["badges"])
        self.assertIn(("reward", "抽奖 100M全国流量日包"), res["badges"])

    def test_report_fields_legacy_goal_line_ignored(self):
        """旧结果缓存（14 天 TTL）残留的「• 目标:」行必须静默忽略，
        不得把下线活动的进度文案带进日报。"""
        sample_output = """
【中国电信 签到】

👤 用户: 【189****1234】
• 签到: 【成功】 (+10 金豆) 连签天数: 【7】天
• 资产: 金豆 【2,580】
• 目标: 【距离【10元话费直充券】(8000金豆) 还差 5420 金豆 (进度: 32.2%)】

总结：成功 1/1
"""
        res = extract_for("telecom.py", sample_output)
        self.assertEqual(len(res["lines"]), 1)
        self.assertNotIn("10元话费直充券", res["lines"][0])
        self.assertNotIn("目标", res["lines"][0])

    def test_legacy_goal_mechanism_removed(self):
        """10元话费达标兑换机制已下线移除（2026-11-19 用户指令）：
        主链路不得再探测/提示/触发兑换，goal_res 字段与 BEANS 常量不复存在。"""
        if not telecom.HAS_CRYPTO:
            self.skipTest("缺少 pycryptodome 库，跳过测试")

        self.assertFalse(hasattr(telecom, "TELECOM_EXCHANGE_BEANS"))
        self.assertFalse(hasattr(telecom.TelecomClient, "try_exchange_phone_bill"))

        acc = telecom.TelecomAccount(
            index=1,
            phone="18912345678",
            sign="mock_sign_token_1234567890123456",
        )
        client = telecom.TelecomClient(acc, MagicMock())
        exchange_calls = []

        def fake_req(method, url, headers=None, json_data=None, data=None, timeout=15):
            if "receiverRights" in url or "queryLevelRightInfo" in url:
                exchange_calls.append(url)
            if "webSign/sign" in url:
                return {"resoultCode": "0", "data": {"code": 0}, "resoultMsg": "成功"}
            if "userCoinInfo" in url:
                return {"resoultCode": "0", "totalCoin": 99999}  # 远超旧门槛也不触发
            return {"resoultCode": "0", "resoultMsg": "成功"}

        client._req = MagicMock(side_effect=fake_req)
        with patch.object(client, "restore_cached_session", return_value=True), \
             patch.object(client, "save_session", return_value=None), \
             patch("sys.stdout", new_callable=io.StringIO):
            outcome = telecom.execute_telecom_task(client)

        self.assertEqual(outcome["status"], "成功")
        self.assertNotIn("goal_res", outcome)
        self.assertEqual(exchange_calls, [], "主链路不得触碰等级权益兑换接口")

    def _import_goal_constant(self, extra_env):
        """在独立子进程中导入 telecom，返回 GOAL 常量，隔离模块级 env 解析。"""
        code = (
            "import os, sys\n"
            f"sys.path.insert(0, {str(BASE)!r})\n"
            "import telecom\n"
            "print(telecom.TELECOM_EXCHANGE_GOAL)\n"
        )
        env = {k: v for k, v in os.environ.items() if not k.startswith("TELECOM_")}
        env.update(extra_env)
        proc = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(BASE.parent),
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout.strip()

    def test_exchange_env_custom_value(self):
        """自定义兑换目标应被正确读取（0 点场专项任务用）。"""
        goal = self._import_goal_constant({"TELECOM_EXCHANGE_GOAL": "2元话费"})
        self.assertEqual(goal, "2元话费")

    def test_exchange_env_fallback_blank(self):
        """目标空串/纯空白时回退默认「等级权益话费」，不得导入即崩。"""
        for bad in ("", "   "):
            with self.subTest(value=bad):
                goal = self._import_goal_constant({"TELECOM_EXCHANGE_GOAL": bad})
                self.assertEqual(goal, "等级权益话费")


class TestJindouExchange(unittest.TestCase):
    """金豆商城（wapact.189.cn:9001）话费抢兑链路测试。"""

    def _client(self):
        acc = telecom.TelecomAccount(index=1, phone="18912345678")
        return telecom.TelecomClient(acc, MagicMock())

    def test_ensure_bearer_from_existing_ticket(self):
        """authorization 为空 + 现有 ticket 可用：统一登录一次即得 Bearer，不现签。"""
        client = self._client()
        client.ticket = "t" * 256
        with patch.object(client, "jindou_unified_login", return_value="tok" * 40) as m_login, \
             patch.object(client, "mint_ticket_with_token", return_value=True) as m_mint, \
             patch("sys.stdout", new_callable=io.StringIO):
            bearer = client.ensure_jindou_bearer()
        self.assertEqual(bearer, "tok" * 40)
        self.assertEqual(client.authorization, "tok" * 40)
        m_login.assert_called_once()
        m_mint.assert_not_called()

    def test_ensure_bearer_mints_when_ticket_stale(self):
        """ticket 过期（统一登录 502）+ 持有 Token 三件套：现签新 ticket 后重试换取。"""
        acc = telecom.TelecomAccount(index=1, phone="18912345678",
                                     app_token="V1.0ABC", uid="1000000001",
                                     target_id="fake0000")
        client = telecom.TelecomClient(acc, MagicMock())
        client.ticket = "stale" * 64
        observed_tickets: list[str] = []

        def login_side_effect() -> str:
            # 记录每次统一登录时 client 实际持有的 ticket，用于断言重试已换新票
            observed_tickets.append(client.ticket)
            return "" if len(observed_tickets) == 1 else "fresh_bearer"

        def mint_side_effect() -> bool:
            client.ticket = "fresh_ticket"
            return True

        with patch.object(client, "jindou_unified_login",
                          side_effect=login_side_effect) as m_login, \
             patch.object(client, "mint_ticket_with_token",
                          side_effect=mint_side_effect) as m_mint, \
             patch("sys.stdout", new_callable=io.StringIO):
            bearer = client.ensure_jindou_bearer()
        self.assertEqual(bearer, "fresh_bearer")
        self.assertEqual(client.authorization, "fresh_bearer")
        self.assertEqual(m_login.call_count, 2)
        self.assertEqual(observed_tickets, ["stale" * 64, "fresh_ticket"])
        m_mint.assert_called_once()

    def test_ensure_bearer_failure_stays_empty(self):
        """统一登录与现签均失败：返回空串且不误写 authorization。"""
        acc = telecom.TelecomAccount(index=1, phone="18912345678",
                                     app_token="V1.0ABC", uid="1000000001",
                                     target_id="fake0000")
        client = telecom.TelecomClient(acc, MagicMock())
        client.ticket = "t" * 256
        with patch.object(client, "jindou_unified_login", return_value=""), \
             patch.object(client, "mint_ticket_with_token", return_value=False), \
             patch("sys.stdout", new_callable=io.StringIO):
            bearer = client.ensure_jindou_bearer()
        self.assertEqual(bearer, "")
        self.assertEqual(client.authorization, "")

    def test_ensure_bearer_reuses_existing_authorization(self):
        """已持有 authorization：直接复用，不发任何换取请求。"""
        client = self._client()
        client.authorization = "already_have_bearer"
        with patch.object(client, "jindou_unified_login") as m_login, \
             patch.object(client, "mint_ticket_with_token") as m_mint:
            bearer = client.ensure_jindou_bearer()
        self.assertEqual(bearer, "already_have_bearer")
        m_login.assert_not_called()
        m_mint.assert_not_called()

    # ---------- 转盘 Bearer 自愈（CodeRabbit 评审指认：状态缓存旧 Bearer 失效） ----------

    def test_turntable_auth_reject_refreshes_and_retries_once(self):
        """queryTurnTable 鉴权拒绝：清空 authorization 现场重取，重试一次后成功。"""
        client = self._client()
        calls = []

        def fake_req(method, url, headers=None, **kw):
            calls.append(headers.get("Authorization"))
            if len(calls) == 1:
                return {"code": 401, "msg": "HTTP 401"}   # 旧 Bearer 失效
            return {"code": 0, "message": "成功", "biz": {"wzTurntable": {"code": "act1"}}}

        client.authorization = "stale_bearer"
        with patch.object(client, "ensure_jindou_bearer",
                          side_effect=["stale_bearer", "fresh_bearer"]), \
             patch.object(client, "_req", side_effect=fake_req):
            res = client.jindou_query_turntable()
        self.assertEqual(res.get("code"), 0)
        self.assertEqual(client.authorization, "fresh_bearer")
        self.assertEqual(calls, ["Bearer stale_bearer", "Bearer fresh_bearer"])

    def test_turntable_non_auth_failure_no_retry(self):
        """非鉴权类失败（业务错误）：不重试，单发原路返回。"""
        client = self._client()
        client.authorization = "bearer_ok"
        with patch.object(client, "ensure_jindou_bearer", return_value="bearer_ok"), \
             patch.object(client, "_req",
                          return_value={"code": 5, "msg": "系统错误"}) as m_req:
            res = client.jindou_query_turntable()
        self.assertEqual(res.get("code"), 5)
        m_req.assert_called_once()

    def test_is_auth_reject_detects_transport_status(self):
        """_req 透出的 _http_status（body 带非空 JSON 时 HTTP 状态不丢）可判定鉴权拒绝。"""
        self.assertTrue(telecom.TelecomClient._is_auth_reject(
            {"code": 0, "message": "Unauthorized", "_http_status": 401}))
        self.assertTrue(telecom.TelecomClient._is_auth_reject({"code": 403}))
        self.assertFalse(telecom.TelecomClient._is_auth_reject(
            {"code": 5, "msg": "系统错误", "_http_status": 200}))
        self.assertFalse(telecom.TelecomClient._is_auth_reject({"code": 999999}))

    def test_turntable_no_bearer_short_circuits(self):
        """换取 Bearer 失败：短路返回，不打转盘请求。"""
        client = self._client()
        with patch.object(client, "ensure_jindou_bearer", return_value=""), \
             patch.object(client, "_req") as m_req:
            res = client.jindou_query_turntable()
        self.assertNotEqual(res.get("code"), 0)
        m_req.assert_not_called()

    # ---------- 等级权益话费抢兑（2026-11-19 现行链路）----------

    def _rights(self, cur_level=4):
        """合成 queryLevelRightInfo 响应（V1..V6 话费档 + 干扰项）。"""
        data = {"resoultCode": "0", "currentLevel": cur_level}
        phone = {3: ("1元", "200"), 4: ("2元", "400"), 5: ("3元", "600"), 6: ("5元", "1000")}
        for lv in range(1, 7):
            items = []
            if lv in phone:
                amt, price = phone[lv]
                items.append({
                    "activityId": f"V1.0FAKEright{lv}", "title": f"LV{lv}等级权益{amt}话费",
                    "promotionalPrice": price, "showType": "9003",
                    "showEffect": "8", "isReceive": "false",
                })
            items.append({"activityId": f"V1.0FAKEcoupon{lv}", "title": f"LV{lv}专享优惠券",
                          "promotionalPrice": "10", "showType": "9001", "showEffect": "7"})
            data[f"V{lv}"] = items
        return data

    def test_pick_phone_right_goal_hit(self):
        item, note = telecom._pick_phone_right(self._rights(6), "5元话费")
        self.assertIsNotNone(item)
        self.assertEqual(item["title"], "LV6等级权益5元话费")
        self.assertIn("命中", note)

    def test_pick_phone_right_downgrade(self):
        """LV4 账号目标 5元 → 自动降级到 2元（等级不足不硬抢）。"""
        item, note = telecom._pick_phone_right(self._rights(4), "5元话费")
        self.assertEqual(item["title"], "LV4等级权益2元话费")
        self.assertIn("降级", note)

    def test_pick_phone_right_auto_max(self):
        item, note = telecom._pick_phone_right(self._rights(4), "等级权益话费")
        self.assertEqual(item["title"], "LV4等级权益2元话费")
        self.assertIn("最高档", note)

    def test_pick_phone_right_no_level(self):
        item, note = telecom._pick_phone_right({"resoultCode": "0"}, "5元话费")
        self.assertIsNone(item)
        self.assertIn("无法确定账号等级", note)

    def test_pick_phone_right_ignores_coupons(self):
        """showType=9001 优惠券不得被当成话费档。"""
        rights = self._rights(4)
        rights["V4"] = [it for it in rights["V4"] if it["showType"] != "9003"]
        item, _ = telecom._pick_phone_right(rights, "2元话费")
        # V3 1元档仍在（<=4），降级到 1元而非误选优惠券
        self.assertEqual(item["title"], "LV3等级权益1元话费")

    def _rights_client(self):
        client = self._client()
        client.sign = "V1.0FAKEsign"
        client.acc_id = "V1.0FAKEacc"
        return client

    def _run_rights(self, client, rights=None, stock=102, receive_results=None, burst=3):
        rights = rights if rights is not None else self._rights(4)
        seq = list(receive_results or [])

        def fake_req(method, url, **kw):
            if "queryLevelRightInfo" in url:
                return rights
            if "querystockNum" in url:
                return {"resoultCode": "0", "stockNum": stock}
            if "receiverRights" in url:
                return seq.pop(0) if seq else {"resoultCode": "1", "resoultMsg": "系统繁忙"}
            return {}

        client._req = MagicMock(side_effect=fake_req)
        with patch.object(telecom.time, "sleep", lambda *_: None):
            return telecom.run_rights_exchange(
                client, "2元话费", wait_for_window=False, burst=burst)

    def test_rights_exchange_success(self):
        ok, msg = self._run_rights(self._rights_client(), receive_results=[
            {"resoultCode": "0", "resoultMsg": "兑换成功"}])
        self.assertTrue(ok)
        self.assertIn("成功兑换", msg)
        self.assertIn("2元话费", msg)

    def test_rights_exchange_level_insufficient_terminal(self):
        ok, msg = self._run_rights(self._rights_client(), receive_results=[
            {"resoultCode": "1", "resoultMsg": "你还未达到该等级"}])
        self.assertTrue(ok)
        self.assertIn("等级不足", msg)

    def test_rights_exchange_monthly_limit_terminal(self):
        ok, msg = self._run_rights(self._rights_client(), receive_results=[
            {"resoultCode": "1", "resoultMsg": "本月已兑换过话费奖品"}])
        self.assertTrue(ok)
        self.assertIn("本月已兑", msg)

    def test_rights_exchange_sold_out_terminal(self):
        ok, msg = self._run_rights(self._rights_client(), receive_results=[
            {"resoultCode": "1", "resoultMsg": "奖品已抢光"}])
        self.assertTrue(ok)
        self.assertIn("售罄", msg)

    def test_rights_exchange_already_received_terminal(self):
        rights = self._rights(4)
        for it in rights["V4"]:
            if it["showType"] == "9003":
                it["isReceive"] = "true"
        ok, msg = self._run_rights(self._rights_client(), rights=rights)
        self.assertTrue(ok)
        self.assertIn("本月已兑换", msg)

    def test_rights_exchange_burst_exhausted_transient(self):
        ok, msg = self._run_rights(self._rights_client(), receive_results=[
            {"resoultCode": "1", "resoultMsg": "系统繁忙，再试一次吧"}] * 3)
        self.assertFalse(ok)
        self.assertIn("未成功", msg)

    def test_rights_exchange_429_backoff_then_success(self):
        ok, msg = self._run_rights(self._rights_client(), receive_results=[
            {"resoultCode": "1", "resoultMsg": "", "_http_status": 429},
            {"resoultCode": "0", "resoultMsg": "兑换成功"}])
        self.assertTrue(ok)
        self.assertIn("成功兑换", msg)

    def test_rights_exchange_waf_transient(self):
        ok, msg = self._run_rights(self._rights_client(), receive_results=[
            {"resoultCode": "1", "resoultMsg": "", "_http_status": 412}])
        self.assertFalse(ok)
        self.assertIn("WAF", msg)

    def test_rights_exchange_missing_credentials(self):
        client = self._client()  # 无 sign/accId
        ok, msg = telecom.run_rights_exchange(client, "2元话费", wait_for_window=False)
        self.assertFalse(ok)
        self.assertIn("缺少 sign/accId", msg)

    def test_rights_exchange_auth_failure_transient(self):
        client = self._rights_client()
        client._req = MagicMock(return_value={"resoultCode": "1", "resoultMsg": "登录已失效"})
        ok, msg = telecom.run_rights_exchange(client, "2元话费", wait_for_window=False)
        self.assertFalse(ok)
        self.assertIn("鉴权失败", msg)

    def test_rights_exchange_no_fake_submitted(self):
        """回归护栏：兑换失败严禁出现旧链路「已提交」假成功文案。"""
        client = self._client()  # 无凭据
        ok, msg = telecom.run_rights_exchange(client, "2元话费", wait_for_window=False)
        self.assertFalse(ok)
        self.assertNotIn("已提交", msg)

    def test_rights_exchange_http_500_no_fake_submitted(self):
        """回归护栏（full review）：带凭据的 receiverRights HTTP 500 必须
        如实失败，不得出现「已提交」/「成功兑换」假成功文案。"""
        client = self._rights_client()
        client._req = MagicMock(return_value={
            "code": 500, "msg": "HTTP 500", "_http_error": True})
        with patch.object(telecom.time, "sleep", lambda *_: None):
            ok, msg = telecom.run_rights_exchange(client, "2元话费", wait_for_window=False)
        self.assertFalse(ok)
        self.assertNotIn("已提交", msg)
        self.assertNotIn("成功兑换", msg)

    def test_rights_next_window_midnight(self):
        from datetime import datetime as _dt
        # 23:00 → 次日 00:00；00:30 → 再次日 00:00
        w1 = telecom._rights_next_window(_dt(2026, 11, 19, 23, 0, tzinfo=telecom.BJT))
        self.assertEqual((w1.day, w1.hour, w1.minute), (20, 0, 0))
        w2 = telecom._rights_next_window(_dt(2026, 11, 19, 0, 30, tzinfo=telecom.BJT))
        self.assertEqual((w2.day, w2.hour, w2.minute), (20, 0, 0))

    def test_rights_next_due_2330(self):
        """自排程钉在 0 点场前 30 分钟（23:30 BJT）；未开抢场次的暂时性失败
        不得跨过场次（PR #34 评审）。"""
        from datetime import datetime as _dt
        # 22:00 暂时性失败 → 当晚 23:30
        due = telecom._rights_next_due(False, _dt(2026, 11, 19, 22, 0, tzinfo=telecom.BJT))
        self.assertEqual((due.day, due.hour, due.minute), (19, 23, 30))
        # 00:30 终局 → 当晚 23:30（下一个 0 点场是 20 日 00:00）
        due2 = telecom._rights_next_due(True, _dt(2026, 11, 19, 0, 30, tzinfo=telecom.BJT))
        self.assertEqual((due2.day, due2.hour, due2.minute), (19, 23, 30))
        # 23:45 暂时性失败（场次未开抢）→ 立即重试保留场次，不得排到明晚
        t3 = _dt(2026, 11, 19, 23, 45, tzinfo=telecom.BJT)
        due3 = telecom._rights_next_due(False, t3)
        self.assertEqual(due3, t3)
        # 23:59:25 预检抖动（距 0 点 35s）→ 同样立即重试
        t4 = _dt(2026, 11, 19, 23, 59, 25, tzinfo=telecom.BJT)
        self.assertEqual(telecom._rights_next_due(False, t4), t4)
        # 23:45 终局（售罄/限兑）→ 下一场 23:30（次日）
        due5 = telecom._rights_next_due(True, _dt(2026, 11, 19, 23, 45, tzinfo=telecom.BJT))
        self.assertEqual((due5.day, due5.hour, due5.minute), (20, 23, 30))
        # 00:05 暂时性失败（场次已过）→ 下一场 23:30
        due6 = telecom._rights_next_due(False, _dt(2026, 11, 20, 0, 5, tzinfo=telecom.BJT))
        self.assertEqual((due6.day, due6.hour, due6.minute), (20, 23, 30))

    def test_registry_task_is_rolling(self):
        """telecom-exchange 必须注册为 rolling（24h），rolling 检查先于退避检查，
        才能屏蔽心跳半点量化对突发时刻的推移。"""
        from task_registry import TASKS
        cfg = TASKS["telecom-exchange"]
        self.assertEqual(cfg.get("sched", {}).get("type"), "rolling")
        self.assertEqual(float(cfg["sched"].get("period_h")), 24.0)
        self.assertEqual(cfg.get("env", {}).get("TELECOM_MODE"), "exchange")

    def test_rights_schedule_writes_dedicated_rolling_key(self):
        """滚动排程必须写专用 state:rolling: 键 + .rolling_state_ 文件。

        notify 状态键在任务结束后被 orchestrator 整键覆盖——旧实现复用该键
        导致 last_credit_ts 每次运行即被抹掉（2026-11-05 复盘）。
        固定时钟：_rights_next_due 默认读真实 now，CI 在 23:30~00:00 BJT
        窗口内跑时 terminal=False 走「立即重试」分支，断言 23:30 会假红。"""
        captured = {}

        def fake_save(redis_key, state_file, state):
            captured["redis_key"] = redis_key
            captured["state_file"] = state_file
            captured["state"] = state

        from datetime import datetime
        fixed_now = datetime(2026, 11, 19, 22, 0, tzinfo=telecom.BJT)

        class _FixedDT(datetime):
            @classmethod
            def now(cls, tz=None):
                return fixed_now if tz is None else fixed_now.astimezone(tz)

        with patch.dict(os.environ, {"CAT_CHECKIN_REDIS_PREFIX": "cat_checkin:"}, clear=False), \
             patch.object(telecom, "save_kv_state", side_effect=fake_save), \
             patch.object(telecom, "datetime", _FixedDT), \
             patch("sys.stdout", new_callable=io.StringIO):
            telecom._rights_schedule_next_run(terminal=False)
        self.assertEqual(captured["redis_key"], "cat_checkin:state:rolling:telecom-exchange")
        self.assertEqual(captured["state_file"], ".rolling_state_telecom-exchange.json")
        next_due = float(captured["state"]["last_credit_ts"]) + 24 * 3600
        due_dt = datetime.fromtimestamp(next_due, telecom.BJT)
        self.assertEqual(due_dt.strftime("%H:%M"), "23:30")

    # ---------- 抢兑主流程出口顺序与会话持久化（2026-11-19 CI 复盘） ----------

    def test_exchange_mode_direct_egress_first(self):
        """0 点抢兑出口队列必须直连优先：CI 实测现签链在所有代理出口失败、
        唯一直连成功；代理先烧 ~60s 超时会侵蚀 23:59:20 预检窗口。"""
        acc = telecom.TelecomAccount(index=1, phone="18912345678")
        observed_labels = []

        def fake_http(task_name=None, proxy=None, **kw):
            observed_labels.append(proxy)
            # 直连候选必须 infer_proxy=False（规则 11）
            if proxy == "":
                self.assertFalse(kw.get("infer_proxy", True))
            return MagicMock()

        with patch.object(telecom, "load_all_accounts", return_value=[acc]), \
             patch.object(telecom, "_get_candidate_proxies",
                          return_value=[MagicMock(url="socks5://fake", display_name="代理A")]), \
             patch.object(telecom, "Http", side_effect=fake_http), \
             patch.object(telecom.TelecomClient, "prepare_auth", return_value=True), \
             patch.object(telecom, "run_rights_exchange",
                          return_value=(True, "🎉 成功兑换【LV4等级权益2元话费】")), \
             patch.object(telecom.TelecomClient, "save_session") as m_save, \
             patch.object(telecom, "_rights_schedule_next_run"), \
             patch("sys.stdout", new_callable=io.StringIO):
            rc = telecom.run_exchange_mode()
        self.assertEqual(rc, 0)
        # 首个出口必须是直连（proxy=""），代理仅作兜底
        self.assertEqual(observed_labels[0], "")
        # 终局后会话必须落盘（sign/accId 供下一场复用）
        m_save.assert_called_once()

    def test_exchange_mode_rotates_to_proxy_on_auth_failure(self):
        """直连鉴权类失败 → 轮换代理候选；代理终局后不再继续。"""
        acc = telecom.TelecomAccount(index=1, phone="18912345678")
        ep = MagicMock(url="socks5://fake", display_name="代理A")
        outcomes = [(False, "等级权益查询鉴权失败: 登录已失效"),
                    (True, "🎉 成功兑换【LV4等级权益2元话费】")]
        with patch.object(telecom, "load_all_accounts", return_value=[acc]), \
             patch.object(telecom, "_get_candidate_proxies", return_value=[ep]), \
             patch.object(telecom, "Http", return_value=MagicMock()), \
             patch.object(telecom.TelecomClient, "prepare_auth", return_value=True), \
             patch.object(telecom, "run_rights_exchange", side_effect=outcomes) as m_run, \
             patch.object(telecom.TelecomClient, "save_session"), \
             patch.object(telecom, "_rights_schedule_next_run"), \
             patch("sys.stdout", new_callable=io.StringIO):
            rc = telecom.run_exchange_mode()
        self.assertEqual(rc, 0)
        self.assertEqual(m_run.call_count, 2)

    def test_acc_id_roundtrips_through_session_cache(self):
        """accId 必须随 sign 持久化/恢复：缓存 sign 回退档缺 accId 会被
        「缺少 sign/accId」闸门拦死（ticket 一次性，补换大概率失败）。"""
        client = self._rights_client()
        captured = {}

        def fake_save(redis_key, state_file, state):
            captured.update(state)

        with patch.object(telecom, "save_kv_state", side_effect=fake_save), \
             patch("sys.stdout", new_callable=io.StringIO):
            client.save_session()
        self.assertEqual(captured.get("acc_id"), "V1.0FAKEacc")

        fresh = self._client()
        with patch.object(telecom, "load_kv_state", return_value=captured), \
             patch("sys.stdout", new_callable=io.StringIO):
            fresh.restore_cached_session()
        self.assertEqual(fresh.acc_id, "V1.0FAKEacc")
        self.assertEqual(fresh.sign, "V1.0FAKEsign")

    def test_acc_id_not_restored_across_account_switch(self):
        """配置提供新账号 sign 时，不得恢复旧账号缓存的 accId（PR #34 评审）：
        sign/accId 必须同源配对，错配会把兑换打到旧账户。"""
        acc = telecom.TelecomAccount(index=1, phone="18912345678", sign="V1.0FAKEnewsign")
        client = telecom.TelecomClient(acc, MagicMock())
        stale_cache = {"sign": "V1.0FAKEoldsign", "acc_id": "V1.0FAKEoldacc"}
        with patch.object(telecom, "load_kv_state", return_value=stale_cache), \
             patch("sys.stdout", new_callable=io.StringIO):
            client.restore_cached_session()
        self.assertEqual(client.sign, "V1.0FAKEnewsign")
        self.assertEqual(client.acc_id, "", "换账号后旧 accId 不得配到新 sign")

    def test_rights_exchange_negative_success_text_not_terminal(self):
        """「未兑换成功，请稍后重试」含「兑换成功」子串但 rc=1：不得判成功。"""
        ok, msg = self._run_rights(self._rights_client(), receive_results=[
            {"resoultCode": "1", "resoultMsg": "未兑换成功，请稍后重试"}] * 3)
        self.assertFalse(ok)
        self.assertNotIn("成功兑换", msg)

    def test_rights_exchange_stock_service_error_not_terminal(self):
        """「库存服务异常」含「库存」但是故障文案：不得判售罄终局。"""
        ok, msg = self._run_rights(self._rights_client(), receive_results=[
            {"resoultCode": "1", "resoultMsg": "库存服务异常，请稍后重试"}] * 3)
        self.assertFalse(ok)
        self.assertNotIn("售罄", msg)

    def test_rights_exchange_unknown_level_transient(self):
        """协议成功但 currentLevel 缺失：暂时性失败交框架重试，不得终局。"""
        client = self._rights_client()
        client._req = MagicMock(return_value={"resoultCode": "0"})
        with patch.object(telecom.time, "sleep", lambda *_: None):
            ok, msg = telecom.run_rights_exchange(client, "2元话费", wait_for_window=False)
        self.assertFalse(ok)
        self.assertIn("无法确定账号等级", msg)

    def test_rights_exchange_limit_query_error_not_terminal(self):
        """「每月限兑次数查询异常」含「每月/限兑」但是故障文案：不得判终局
        （PR #34 第二轮评审）。"""
        ok, msg = self._run_rights(self._rights_client(), receive_results=[
            {"resoultCode": "1", "resoultMsg": "每月限兑次数查询异常，请稍后重试"}] * 3)
        self.assertFalse(ok)
        self.assertNotIn("本月已兑", msg)

    # ---------- 每日签到大转盘（2026-11-19 HAR 逆向接入） ----------

    def _wheel_client(self, remain=3, beans=1000, cost=20):
        client = self._rights_client()
        self._wheel_status = {"resoultCode": "0", "data": {
            "remainCount": remain, "userMaximum": "3", "amount": cost,
            "beanAmount": beans, "showEntry": True, "state": "1",
        }}
        self._wheel_submits = []
        return client

    def _wheel_req(self, client, submit_results):
        seq = list(submit_results)

        def fake_req(method, url, **kw):
            if "getWheelStatusAndInfo" in url:
                return self._wheel_status
            if "wheelRewardSubmit" in url:
                self._wheel_submits.append(kw.get("json_data"))
                return seq.pop(0) if seq else {"code": 1, "msg": "系统繁忙"}
            return {}

        client._req = MagicMock(side_effect=fake_req)

    def test_wheel_draws_all_remaining(self):
        """remainCount=3 → 连抽 3 次，奖品汇总；para.phone 必须填 accId。"""
        client = self._wheel_client(remain=3)
        self._wheel_req(client, [
            {"code": 0, "data": {"prizeName": "88金豆", "prizeState": "0"}},
            {"code": 0, "data": {"prizeName": "188金豆", "prizeState": "0"}},
            {"code": 0, "data": {"prizeName": "漫花纸品10元优惠券", "prizeState": "0"}},
        ])
        with patch.object(telecom.time, "sleep", lambda *_: None), \
             patch("sys.stdout", new_callable=io.StringIO):
            res = client.wheel_daily_draws()
        self.assertEqual(res, "88金豆、188金豆、漫花纸品10元优惠券")
        self.assertEqual(len(self._wheel_submits), 3)

    def test_wheel_respects_server_remain_zero(self):
        """remainCount=0 → 今日已抽，不发任何提交。"""
        client = self._wheel_client(remain=0)
        self._wheel_req(client, [])
        with patch("sys.stdout", new_callable=io.StringIO):
            res = client.wheel_daily_draws()
        self.assertEqual(res, "今日已抽")
        self.assertEqual(len(self._wheel_submits), 0)

    def test_wheel_stops_on_insufficient_beans(self):
        """余额 < 单抽成本 → 停手不硬抽。"""
        client = self._wheel_client(remain=3, beans=10, cost=20)
        self._wheel_req(client, [])
        with patch("sys.stdout", new_callable=io.StringIO):
            res = client.wheel_daily_draws()
        self.assertIn("金豆不足", res)
        self.assertEqual(len(self._wheel_submits), 0)

    def test_wheel_server_exhausted_stops(self):
        """服务端裁决次数用尽（「今日已抽完」）→ 停手，不继续提交。"""
        client = self._wheel_client(remain=3)
        self._wheel_req(client, [
            {"code": 0, "data": {"prizeName": "88金豆"}},
            {"code": 1, "resoultMsg": "今日抽奖次数已用完", "data": {}},
        ])
        with patch.object(telecom.time, "sleep", lambda *_: None), \
             patch("sys.stdout", new_callable=io.StringIO):
            res = client.wheel_daily_draws()
        self.assertEqual(res, "88金豆")
        self.assertEqual(len(self._wheel_submits), 2)

    def test_wheel_timeout_msg_not_reported_as_drawn(self):
        """「抽奖请求已超时，请稍后重试」是传输故障，不得因含「已」「抽」
        误判为「今日已抽」（PR #34 终局评审，规则 9a(1)）。"""
        client = self._wheel_client(remain=3)
        self._wheel_req(client, [
            {"code": 500, "msg": "抽奖请求已超时，请稍后重试", "data": {}},
        ])
        with patch.object(telecom.time, "sleep", lambda *_: None), \
             patch("sys.stdout", new_callable=io.StringIO):
            res = client.wheel_daily_draws()
        self.assertIn("提交故障", res)
        self.assertIn("超时", res)
        self.assertNotIn("今日已抽", res)
        self.assertEqual(len(self._wheel_submits), 1, "故障后不得继续提交")

    def test_wheel_non_200_with_code0_not_success(self):
        """HTTP 非 200 即使正文带 code:0 + prizeName 也不得判成功
        （网关错误页可能回显业务字段，PR #34 第十三轮评审）。"""
        client = self._wheel_client(remain=3)
        self._wheel_req(client, [
            {"code": 0, "_http_status": 502, "data": {"prizeName": "88金豆"}},
        ])
        with patch.object(telecom.time, "sleep", lambda *_: None), \
             patch("sys.stdout", new_callable=io.StringIO):
            res = client.wheel_daily_draws()
        self.assertIn("提交故障", res)
        self.assertNotIn("88金豆", res)
        self.assertEqual(len(self._wheel_submits), 1)

    def test_wheel_server_msg_pii_redacted_before_truncate(self):
        """服务端原始 msg 含裸手机号：必须先全文 PII 脱敏再截断，
        不得把完整号码带进公开日志/日报（PR #34 终局自审）。"""
        client = self._wheel_client(remain=3)
        self._wheel_req(client, [
            {"code": 1, "msg": "账号13812345678抽奖失败，请稍后重试", "data": {}},
        ])
        with patch.object(telecom.time, "sleep", lambda *_: None), \
             patch("sys.stdout", new_callable=io.StringIO):
            res = client.wheel_daily_draws()
        self.assertNotIn("13812345678", res)
        self.assertIn("提交故障", res)

    def test_rights_terminal_msg_pii_redacted(self):
        """等级权益终局文案（售罄/限兑）里的裸手机号同样必须脱敏。"""
        client = self._rights_client()
        ok, msg = self._run_rights(client, receive_results=[
            {"resoultCode": "1", "resoultMsg": "账号13812345678已抢光，请下次再来"},
        ])
        self.assertTrue(ok)
        self.assertNotIn("13812345678", msg)
        self.assertIn("已售罄", msg)

    def test_wheel_mixed_code1_resoult0_not_success(self):
        """提交接口 code=1 + resoultCode="0" 混合响应不得判成功：
        转盘提交成功码只认 code=0（PR #34 第十四轮评审）。"""
        client = self._wheel_client(remain=3)
        self._wheel_req(client, [
            {"code": 1, "resoultCode": "0", "data": {"prizeName": "88金豆"}},
        ])
        with patch.object(telecom.time, "sleep", lambda *_: None), \
             patch("sys.stdout", new_callable=io.StringIO):
            res = client.wheel_daily_draws()
        self.assertNotIn("88金豆", res)
        self.assertIn("提交故障", res)
        self.assertEqual(len(self._wheel_submits), 1)

    def test_wheel_missing_creds_silent(self):
        """缺 sign/accId → 空串静默跳过（不重复刷屏）。"""
        client = self._client()
        self.assertEqual(client.wheel_daily_draws(), "")

    def test_wheel_para_phone_is_acc_id(self):
        """协议护栏：para.phone 字段填 accId（JS 实证），不是手机号。"""
        client = self._wheel_client(remain=1)
        captured = {}

        def fake_encrypt(payload):
            captured.update(payload)
            return "V1.0FAKEcipher"

        self._wheel_req(client, [{"code": 0, "data": {"prizeName": "88金豆"}}])
        with patch.object(telecom, "_encrypt_rsa", side_effect=fake_encrypt), \
             patch.object(telecom.time, "sleep", lambda *_: None), \
             patch("sys.stdout", new_callable=io.StringIO):
            client.wheel_daily_draws()
        self.assertEqual(captured.get("phone"), "V1.0FAKEacc")
        self.assertEqual(captured.get("provinceCode"), telecom.WHEEL_PROVINCE_CODE)

    def test_wheel_missing_remain_count_not_reported_as_drawn(self):
        """查询成功但缺 remainCount：字段异常，不得报「今日已抽」
        （PR #34 第三轮评审）。"""
        client = self._rights_client()
        client._req = MagicMock(return_value={"resoultCode": "0", "data": {"amount": 20}})
        with patch("sys.stdout", new_callable=io.StringIO):
            res = client.wheel_daily_draws()
        self.assertIn("字段异常", res)
        self.assertNotIn("今日已抽", res)

    def test_wheel_submit_failure_stops_and_reports(self):
        """提交故障（系统繁忙）：立即停手、如实报故障，不得报「未中奖」、
        不得继续盲提交（PR #34 第三轮评审）。"""
        client = self._wheel_client(remain=3)
        self._wheel_req(client, [
            {"code": 0, "data": {"prizeName": "88金豆"}},
            {"code": 1, "msg": "系统繁忙，请稍后再试"},
        ])
        with patch.object(telecom.time, "sleep", lambda *_: None), \
             patch("sys.stdout", new_callable=io.StringIO):
            res = client.wheel_daily_draws()
        self.assertIn("88金豆", res)
        self.assertIn("提交故障", res)
        self.assertNotIn("未中奖", res)
        self.assertEqual(len(self._wheel_submits), 2, "故障后不得继续提交")

    def test_wheel_all_submit_failure_not_reported_as_no_prize(self):
        """全部提交故障：报故障而非「未中奖」。"""
        client = self._wheel_client(remain=3)
        self._wheel_req(client, [{"code": -1, "msg": "HTTP -1"}])
        with patch.object(telecom.time, "sleep", lambda *_: None), \
             patch("sys.stdout", new_callable=io.StringIO):
            res = client.wheel_daily_draws()
        self.assertIn("提交故障", res)
        self.assertNotIn("未中奖", res)
        self.assertEqual(len(self._wheel_submits), 1)

    def test_wheel_non_dict_data_no_crash(self):
        """data 非字典（如 [1]）：返回字段异常，不得抛 AttributeError 中断
        已签到账号的后续任务（PR #34 第四轮评审）。"""
        client = self._rights_client()
        client._req = MagicMock(return_value={"resoultCode": "0", "data": [1]})
        with patch("sys.stdout", new_callable=io.StringIO):
            res = client.wheel_daily_draws()
        self.assertIn("字段异常", res)

    def test_wheel_submit_beans_insufficient_reason_kept(self):
        """查询余额足够但提交时服务端裁决金豆不足：保留真实拒绝原因，
        不得吞成「今日已抽」（PR #34 第四轮评审）。"""
        client = self._wheel_client(remain=3, beans=1000)
        self._wheel_req(client, [{"code": 1, "resoultMsg": "金豆不足，无法抽奖", "data": {}}])
        with patch.object(telecom.time, "sleep", lambda *_: None), \
             patch("sys.stdout", new_callable=io.StringIO):
            res = client.wheel_daily_draws()
        self.assertIn("金豆不足", res)
        self.assertNotEqual(res, "今日已抽")
        self.assertEqual(len(self._wheel_submits), 1)


    # ---------- 0 点场提速/降级回归（2026-11-24 CI 复盘）----------

    def test_rights_precheck_before_long_wait(self):
        """23:30 派发时先查权益/库存，不得跨越 29 分钟长睡后再鉴权。

        旧实现先 sleep 到 23:59 再查询，sign 在等待期失效 → 换出口烧掉
        4 分钟 → 00:04 抢兑，库存早已售罄（2026-11-23/24 CI 实证）。"""
        rights = self._rights(4)
        rights["V3"][0]["isReceive"] = "false"
        client = self._rights_client()
        calls = []

        def fake_req(method, url, **kw):
            calls.append(url.rsplit("/", 1)[-1])
            if "queryLevelRightInfo" in url:
                return rights
            if "querystockNum" in url:
                return {"resoultCode": "0", "stockNum": 102}
            return {"resoultCode": "1", "resoultMsg": "系统繁忙"}

        client._req = MagicMock(side_effect=fake_req)
        fixed_now = datetime(2026, 11, 24, 23, 30, tzinfo=telecom.BJT)

        class _FixedDT(datetime):
            @classmethod
            def now(cls, tz=None):
                return fixed_now

        def fake_sleep(seconds):
            if seconds < 1:
                return
            raise RuntimeError("LONG_WAIT_REACHED")

        with patch.object(telecom.time, "sleep", side_effect=fake_sleep), \
             patch.object(telecom, "datetime", _FixedDT), \
             patch.object(telecom, "_rights_refresh_session", return_value=True), \
             patch("sys.stdout", new_callable=io.StringIO):
            try:
                telecom.run_rights_exchange(client, "2元话费", wait_for_window=True, burst=1)
            except RuntimeError as exc:
                self.assertEqual(str(exc), "LONG_WAIT_REACHED")
        self.assertEqual(calls[0], "queryLevelRightInfo")
        self.assertEqual(calls[1], "querystockNum")

    def test_rights_sold_out_primary_falls_back_to_available_tier(self):
        """主档售罄 + 备用档有库存：必须继续抢低档，不得直接判「今日终止」。"""
        rights = self._rights(4)
        client = self._rights_client()
        submitted_ids = []

        def fake_req(method, url, **kw):
            if "queryLevelRightInfo" in url:
                return rights
            if "querystockNum" in url:
                para = kw.get("json_data", {}).get("para", "")
                # 主档 activityId 末位 4；备用档 V3 末位 3
                return {"resoultCode": "0", "stockNum": 0 if "right4" in para else 12}
            if "receiverRights" in url:
                para = kw.get("json_data", {}).get("para", "")
                rid = "main" if "right4" in para else "alt"
                submitted_ids.append(rid)
                if rid == "main":
                    return {"resoultCode": "1", "resoultMsg": "抱歉，奖品已领完"}
                return {"resoultCode": "0", "resoultMsg": "兑换成功"}
            return {}

        client._req = MagicMock(side_effect=fake_req)
        fixed_now = datetime(2026, 11, 25, 0, 30, tzinfo=telecom.BJT)

        class _FixedDT(datetime):
            @classmethod
            def now(cls, tz=None):
                return fixed_now

        with patch.object(telecom.time, "sleep", lambda *_: None), \
             patch.object(telecom, "datetime", _FixedDT), \
             patch.object(telecom, "_encrypt_rsa", lambda data: json.dumps(data, ensure_ascii=False)), \
             patch.object(telecom, "RIGHTS_FALLBACK_TIERS", 2), \
             patch("sys.stdout", new_callable=io.StringIO):
            ok, msg = telecom.run_rights_exchange(
                client, "2元话费", wait_for_window=True, burst=2)
        self.assertTrue(ok)
        self.assertIn("成功兑换", msg)
        self.assertIn("1元", msg)
        self.assertEqual(submitted_ids, ["main", "alt"])


if __name__ == "__main__":
    unittest.main()
