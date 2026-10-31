#!/usr/bin/env python3
"""ModelScope（魔搭社区）任务扩展单元测试。

验证：
1. 魔粒规则获取与余额解析
2. 点赞喜欢任务执行与封顶
3. AIGC 作品自动化发布流水线
4. 统一日报字段解析器（ex_modelscope）
"""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import modelscope as ms
from report_fields import extract_for


class TestModelScopeTasks(unittest.TestCase):
    def setUp(self):
        self.mock_http = MagicMock()
        self.host = "www.modelscope.cn"
        self.cookie = "m_session_id=synthetic_session_123; csrf_token=test_csrf"

    def test_fetch_all_earn_rules(self):
        mock_resp = MagicMock()
        mock_resp.code = 200
        mock_resp.json.return_value = {
            "success": True,
            "data": [
                {
                    "rule_key": "daily_active",
                    "today_used": 1,
                    "today_remain": 0,
                    "amount": 200,
                },
                {
                    "rule_key": "interaction_like",
                    "daily_cap": 10,
                    "today_used": 2,
                    "today_remain": 8,
                    "amount": 2,
                },
                {
                    "rule_key": "opensource_aigcworks_publish",
                    "daily_cap": 10,
                    "today_used": 0,
                    "today_remain": 10,
                    "amount": 10,
                },
            ],
        }
        self.mock_http.request.return_value = mock_resp

        rules = ms._fetch_all_earn_rules(self.mock_http, self.host, cookie=self.cookie)
        self.assertIn("daily_active", rules)
        self.assertIn("interaction_like", rules)
        self.assertIn("opensource_aigcworks_publish", rules)
        self.assertEqual(rules["interaction_like"]["today_remain"], 8)

    def test_fetch_magicubes_balance(self):
        mock_resp = MagicMock()
        mock_resp.code = 200
        mock_resp.json.return_value = {
            "success": True,
            "data": {
                "total_balance": 500,
                "available_balance": 450,
                "frozen_amount": 50,
            },
        }
        self.mock_http.request.return_value = mock_resp

        bal = ms._fetch_magicubes_balance(self.mock_http, self.host, cookie=self.cookie)
        self.assertEqual(bal["total_balance"], 500)
        self.assertEqual(bal["available_balance"], 450)
        self.assertEqual(bal["frozen_amount"], 50)

    @patch("modelscope._human_pause")
    @patch("modelscope._fetch_mcp_like_targets")
    def test_do_daily_likes(self, mock_targets, mock_pause):
        mock_targets.return_value = [
            {"path": "Alipay", "name": "alipay-subscription"},
            {"path": "TianYanCha", "name": "tyc-mcp"},
        ]
        mock_resp = MagicMock()
        mock_resp.code = 200
        mock_resp.json.return_value = {"Success": True, "Code": 200}
        self.mock_http.request.return_value = mock_resp

        done, earned = ms._do_daily_likes(
            self.mock_http, self.host, cookie=self.cookie, count=2, amount_per_like=2
        )
        self.assertEqual(done, 2)
        self.assertEqual(earned, 4)
        self.assertEqual(self.mock_http.request.call_count, 2)

    def test_do_daily_aigc_publish_success(self):
        # 模拟：1. image/create -> 1.5 create后 muse/image/get 反查诊断
        #       -> 2. image/updateImageGenerateInfo -> 3. aigc/picture/upload -> 4. 后续触碰
        resp_create = MagicMock(code=200)
        resp_create.json.return_value = {
            "data": [{"id": 99901, "url": "https://img.example.com/test.png"}]
        }

        resp_update = MagicMock(code=200)
        resp_update.json.return_value = {"success": True}

        resp_upload = MagicMock(code=200)
        resp_upload.json.return_value = {
            "Success": True,
            "Message": "success",
            "Data": {"id": 88801},
        }

        resp_track = MagicMock(code=200)
        resp_track.json.return_value = {"Code": 200}

        resp_get = MagicMock(code=200)
        resp_get.json.return_value = {"Code": 200}

        self.mock_http.request.side_effect = [
            resp_create,
            resp_get,
            resp_update,
            resp_upload,
            resp_track,
            resp_get,
        ]

        done, earned, last_id = ms._do_daily_aigc_publish(
            self.mock_http, self.host, cookie=self.cookie, count=1, amount_per_publish=10
        )
        self.assertEqual(done, 1)
        self.assertEqual(earned, 10)
        self.assertEqual(last_id, "88801")

    def test_paused_account_skipped(self):
        """暂停名单内的账号序号不加载（封禁账号零触碰）。"""
        env = {
            "MODELSCOPE_COOKIE_1": "m_session_id=synthetic_a",
            "MODELSCOPE_COOKIE_2": "m_session_id=synthetic_b",
        }
        with patch.dict(os.environ, env), patch.object(
            ms, "load_kv_state", return_value={}
        ), patch.object(ms, "PAUSED_CN_ACCOUNTS", {2}):
            accounts = ms._load_accounts("cn")
        self.assertEqual([a["index"] for a in accounts], [1])

    def test_paused_accounts_env_override(self):
        """MODELSCOPE_PAUSED_CN_ACCOUNTS 环境变量整体覆盖硬编码默认名单。"""
        env = {
            "MODELSCOPE_COOKIE_1": "m_session_id=synthetic_a",
            "MODELSCOPE_COOKIE_2": "m_session_id=synthetic_b",
            "MODELSCOPE_PAUSED_CN_ACCOUNTS": "1,2",
        }
        with patch.dict(os.environ, env), patch.object(
            ms, "load_kv_state", return_value={}
        ):
            self.assertEqual(ms._load_accounts("cn"), [])

    def test_valid_ua_rejects_truncated(self):
        """telecom 先例：截断/非法 UA 必须判无效，触发重新选定。"""
        self.assertTrue(ms._valid_ua(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
        ))
        self.assertFalse(ms._valid_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"))
        self.assertFalse(ms._valid_ua(""))
        self.assertFalse(ms._valid_ua(None))
        for ua in ms.UA_POOL:
            self.assertTrue(ms._valid_ua(ua), f"UA 池成员必须自身合法: {ua}")

    def test_touch_user_blacklist_detection(self):
        """403 + 黑名单文案必须识别为风控拉黑（而非普通凭证失效）。"""
        blacklist_body = (
            '{"detail":"错误代码:403 - {\'error\':{\'message\':'
            '\'您的账户因可疑活动被列入黑名单，欢迎通过 contact@modelscope.cn 联系我们\'}}"}'
        )
        resp = MagicMock(code=403)
        resp.json.return_value = {}
        resp.text = blacklist_body
        h = MagicMock()
        h.request.return_value = resp
        with self.assertRaises(RuntimeError) as ctx:
            ms._touch_user(h, self.host, cookie=self.cookie)
        self.assertIn("黑名单", str(ctx.exception))
        self.assertIn("contact@modelscope.cn", str(ctx.exception))

    def test_touch_user_expired_vs_blacklist(self):
        """403 无黑名单文案 → 仍走「凭证失效」分支，提示重取 Cookie。"""
        resp = MagicMock(code=403)
        resp.json.return_value = {}
        resp.text = '{"message":"unauthorized"}'
        h = MagicMock()
        h.request.return_value = resp
        with self.assertRaises(RuntimeError) as ctx:
            ms._touch_user(h, self.host, cookie=self.cookie)
        self.assertIn("已失效/未登录", str(ctx.exception))
        self.assertNotIn("黑名单", str(ctx.exception))

    def test_blacklisted_account_skipped(self):
        """state 中 blacklisted=true 的账号零触碰跳过（自动停用闭环）。"""
        env = {"MODELSCOPE_COOKIE_1": "m_session_id=synthetic_a"}
        with patch.dict(os.environ, env), patch.object(
            ms, "load_kv_state", return_value={"blacklisted": True}
        ):
            self.assertEqual(ms._load_accounts("cn"), [])

    def test_report_fields_ex_modelscope(self):
        sample_output = (
            "【ModelScope 国内站 签到】\n"
            "  1 个账号 @ www.modelscope.cn\n"
            "  [1/1] test_user [Cookie] 签到成功，今日已领取 200 魔粒，阿里云绑定(+50)，"
            "完成点赞 10/10 次 (+20 魔粒)，完成AIGC发布 10/10 次 (+100 魔粒)，"
            "主页置顶(+50)，可用余额 720 魔粒 [Cookie 剩余 15 天]，魔粒 2026-10-22 00:00:00 过期\n"
            "  ModelScope 国内站 签到 总结：成功 1/1\n"
            "国内站：✅ 成功\n"
        )
        res = extract_for("modelscope.py", sample_output)
        self.assertEqual(len(res["lines"]), 1)
        line = res["lines"][0]
        self.assertIn("+200魔粒", line)
        self.assertIn("点赞 10/10(+20)", line)
        self.assertIn("AIGC发布 10/10(+100)", line)
        self.assertIn("主页置顶(+50)", line)
        self.assertIn("阿里云绑定(+50)", line)
        self.assertIn("余720", line)

        # 检查 gains 统计
        gains_dict = {}
        for k, v in res["gains"]:
            gains_dict[k] = gains_dict.get(k, 0.0) + v
        self.assertEqual(gains_dict.get("魔粒"), 420.0)

    def test_report_fields_ex_modelscope_pending_settlement(self):
        sample_output = (
            "【ModelScope 国内站 签到】\n"
            "  1 个账号 @ www.modelscope.cn\n"
            "  [1/1] test_user [Cookie] 签到成功，今日已领取 200 魔粒，阿里云绑定(+50)，"
            "完成点赞 10/10 次 (+20 魔粒)，完成AIGC发布 10 次(待结算)，"
            "主页置顶(+50)，可用余额 320 魔粒 [Cookie 剩余 15 天]，魔粒 2026-10-22 00:00:00 过期\n"
            "  ModelScope 国内站 签到 总结：成功 1/1\n"
            "国内站：✅ 成功\n"
        )
        res = extract_for("modelscope.py", sample_output)
        self.assertEqual(len(res["lines"]), 1)
        line = res["lines"][0]
        self.assertIn("+200魔粒", line)
        self.assertIn("点赞 10/10(+20)", line)
        self.assertIn("AIGC已发10篇(待结算)", line)
        self.assertIn("主页置顶(+50)", line)
        self.assertIn("阿里云绑定(+50)", line)
        self.assertIn("余320", line)

        # 待结算时不虚增 gains
        gains_dict = {}
        for k, v in res["gains"]:
            gains_dict[k] = gains_dict.get(k, 0.0) + v
        self.assertEqual(gains_dict.get("魔粒"), 320.0)


if __name__ == "__main__":
    unittest.main()
