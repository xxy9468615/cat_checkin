#!/usr/bin/env python3
"""中国电信签到脚本单元测试。"""
from __future__ import annotations

import json
import os
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
             patch.object(client, "save_session", return_value=None):
            outcome = telecom.execute_telecom_task(client)

        self.assertEqual(outcome["status"], "成功")
        self.assertEqual(outcome["gain_bean"], 10)
        self.assertEqual(outcome["streak_days"], 7)
        self.assertEqual(outcome["lottery_res"], "100M全国流量日包")
        self.assertEqual(outcome["task_res"], "完成1项")
        self.assertEqual(outcome["food_res"], "喂食1次")
        self.assertEqual(outcome["total_bean"], "2580")

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


if __name__ == "__main__":
    unittest.main()
