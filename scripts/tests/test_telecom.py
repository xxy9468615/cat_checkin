#!/usr/bin/env python3
"""中国电信签到脚本单元测试。"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import telecom
from report_fields import extract_for


class TestTelecom(unittest.TestCase):
    def test_parse_account_key_value(self):
        """键值格式抓包串解析。"""
        raw = "phone=18912345678; sign=a1b2c3d4e5f67890a1b2c3d4e5f67890; authorization=Bearer test_jwt_token"
        acc = telecom._parse_account_config(raw, 1)
        self.assertEqual(acc.index, 1)
        self.assertEqual(acc.phone, "18912345678")
        self.assertEqual(acc.sign, "a1b2c3d4e5f67890a1b2c3d4e5f67890")
        self.assertEqual(acc.authorization, "Bearer test_jwt_token")
        self.assertTrue(acc.has_credentials())
        self.assertIn("189****5678", acc.display_name)

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
            "phone=17762551109; "
            "token=V1.0KonaH//Utf5WqBO3dyQTy0r9KIhQrXAAZq5cSpJGz6q3tIVYtEJ8ArF7TUOqAsfFjZHpk=; "
            "uid=3998477332; target=598d26069a564aeb4e5c6a25c25d77d9641cc4800bcc5886",
            1,
        )
        self.assertTrue(acc.has_credentials())

    def test_parse_token_triple(self):
        """App 长效 Token 三件套（token/uid/target）解析。"""
        acc = telecom._parse_account_config(
            "phone=17762551109; "
            "token=V1.0KonaH//Utf5WqBO3dyQTy0r9KIhQrXAAZq5cSpJGz6q3tIVYtEJ8ArF7TUOqAsfFjZHpk=; "
            "uid=3998477332; "
            "target=598d26069a564aeb4e5c6a25c25d77d9641cc4800bcc5886",
            1,
        )
        self.assertEqual(acc.phone, "17762551109")
        self.assertTrue(acc.app_token.startswith("V1.0"))
        self.assertEqual(acc.uid, "3998477332")
        self.assertEqual(acc.target_id, "598d26069a564aeb4e5c6a25c25d77d9641cc4800bcc5886")
        # token 不得被误吞为 authorization
        self.assertEqual(acc.authorization, "")

    def test_build_getsingle_xml(self):
        """getSingle XML 模板必须与 App 抓包结构一致（UserLoginName 带尾分号）。"""
        xml = telecom._build_getsingle_xml("V1.0ABC", "3998477332", "598d2606", "20260919020000")
        self.assertIn("<Code>getSingle</Code>", xml)
        self.assertIn("<Timestamp>20260919020000</Timestamp>", xml)
        self.assertIn("<Token>V1.0ABC</Token>", xml)
        self.assertIn("<UserLoginName>3998477332;</UserLoginName>", xml)
        self.assertIn("<TargetId>598d2606</TargetId>", xml)
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
            index=1, phone="17762551109",
            app_token="V1.0ABC", uid="3998477332", target_id="598d2606",
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
• 目标: 【距离【10元话费直充券】(8000金豆) 还差 5420 金豆 (进度: 32.2%)】

总结：成功 1/1
"""
        res = extract_for("telecom.py", sample_output)
        self.assertEqual(len(res["lines"]), 1)
        self.assertIn("189****1234", res["lines"][0])
        self.assertIn("签到成功", res["lines"][0])
        self.assertIn("+10金豆", res["lines"][0])
        self.assertIn("连签 7 天", res["lines"][0])
        self.assertIn("金豆 2,580", res["lines"][0])
        self.assertIn("10元话费直充券", res["lines"][0])

        self.assertEqual(res["streak"], 7)
        self.assertIn(("金豆", 10.0), res["gains"])
        self.assertIn(("金豆", 2580.0), res["assets"])
        self.assertIn(("reward", "+10 金豆"), res["badges"])
        self.assertIn(("streak", "连签 7 天"), res["badges"])
        self.assertIn(("reward", "抽奖 100M全国流量日包"), res["badges"])

    def test_exchange_goal_progress(self):
        """金豆兑换目标进度计算与达标兑换。"""
        if not telecom.HAS_CRYPTO:
            self.skipTest("缺少 pycryptodome 库，跳过测试")

        acc = telecom.TelecomAccount(
            index=1,
            phone="18912345678",
            sign="mock_sign_token_1234567890123456",
        )
        mock_http = MagicMock()
        client = telecom.TelecomClient(acc, mock_http)

        def fake_req(method, url, headers=None, json_data=None, data=None, timeout=15):
            if "webSign/sign" in url:
                return {"resoultCode": "0", "data": {"code": 0}, "resoultMsg": "成功"}
            if "userCoinInfo" in url:
                return {"resoultCode": "0", "totalCoin": 1500}
            return {"resoultCode": "0", "resoultMsg": "成功"}

        client._req = MagicMock(side_effect=fake_req)
        with patch.object(client, "restore_cached_session", return_value=True), \
             patch.object(client, "save_session", return_value=None), \
             patch.dict(os.environ, {"TELECOM_EXCHANGE_GOAL": "10元话费直充券", "TELECOM_EXCHANGE_BEANS": "8000"}), \
             patch("sys.stdout", new_callable=io.StringIO):
            outcome = telecom.execute_telecom_task(client)

        self.assertEqual(outcome["status"], "成功")
        self.assertIn("距离【10元话费直充券】(8000金豆) 还差 6500 金豆", outcome["goal_res"])
        self.assertIn("18.8%", outcome["goal_res"])

    def _import_constants(self, extra_env):
        """在独立子进程中导入 telecom，返回 (BADGES, GOAL) 常量，隔离模块级 env 解析。"""
        code = (
            "import os, sys\n"
            f"sys.path.insert(0, {str(BASE)!r})\n"
            "import telecom\n"
            "print(telecom.TELECOM_EXCHANGE_BEANS, telecom.TELECOM_EXCHANGE_GOAL)\n"
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
        beans, _, goal = proc.stdout.strip().partition(" ")
        return int(beans), goal

    def test_exchange_env_custom_value(self):
        """自定义兑换目标与门槛应被正确读取。"""
        beans, goal = self._import_constants(
            {"TELECOM_EXCHANGE_BEANS": "12000", "TELECOM_EXCHANGE_GOAL": "20元话费券"}
        )
        self.assertEqual(beans, 12000)
        self.assertEqual(goal, "20元话费券")

    def test_exchange_env_fallback_non_numeric(self):
        """门槛误配为非数字/空串/负数时应回退默认 8000，不得导入即崩。"""
        for bad in ("abc", "", "   ", "-5", "0"):
            with self.subTest(value=bad):
                beans, goal = self._import_constants(
                    {"TELECOM_EXCHANGE_BEANS": bad, "TELECOM_EXCHANGE_GOAL": "   "}
                )
                self.assertEqual(beans, 8000)
                self.assertEqual(goal, "10元话费直充券")


if __name__ == "__main__":
    unittest.main()
