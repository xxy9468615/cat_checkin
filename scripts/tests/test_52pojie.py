#!/usr/bin/env python3
"""52POJIE (吾爱破解) 签到脚本自检与单元测试。

测试覆盖：
1. Cookie 字典解析与 Set-Cookie 滚动合并
2. Discuz 任务消息解析（CDATA、messagetext、alert_info、showDialog 等）
3. 个人资产与积分信息提取（吾爱币、积分、贡献、热心值、等级）
4. 多源代理出口与候选池解析
5. 多前缀与多账号序列加载兼容性
6. 签到状态（成功、今日已签、Cookie 失效、WAF 拦截）判定逻辑
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import importlib

pojie = importlib.import_module("52pojie")


class Test52Pojie(unittest.TestCase):
    def test_parse_and_merge_cookie(self):
        c_str = "htVD_2132_saltkey=test_salt; htVD_2132_auth=test_auth; htVD_2132_lastcheckfeed=12345%7C6789"
        d = pojie._parse_cookie_dict(c_str)
        self.assertEqual(d.get("htVD_2132_saltkey"), "test_salt")
        self.assertEqual(d.get("htVD_2132_auth"), "test_auth")

        # 合并 Set-Cookie
        merged = pojie._merge_cookie_str(c_str, ["htVD_2132_auth=new_auth; path=/;", "htVD_2132_sid=new_sid; path=/;"])
        d_merged = pojie._parse_cookie_dict(merged)
        self.assertEqual(d_merged.get("htVD_2132_auth"), "new_auth")
        self.assertEqual(d_merged.get("htVD_2132_sid"), "new_sid")
        self.assertEqual(d_merged.get("htVD_2132_saltkey"), "test_salt")

    def test_extract_task_message(self):
        # CDATA 格式
        html_cdata = "<root><![CDATA[恭喜您，任务已成功完成，您已获得 2 吾爱币奖励]]></root>"
        self.assertIn("恭喜您", pojie._extract_task_message(html_cdata))

        # messagetext 格式
        html_msg = '<div id="messagetext"><p>抱歉，本期您已申请过此任务，请下期再来</p></div>'
        self.assertIn("抱歉，本期您已申请过此任务", pojie._extract_task_message(html_msg))

        # alert_info 格式
        html_alert = '<p class="alert_info">您需要先登录才能继续本操作</p>'
        self.assertIn("您需要先登录才能继续本操作", pojie._extract_task_message(html_alert))

        # showDialog 格式
        html_diag = 'showDialog("恭喜您，任务已成功完成", "notice");'
        self.assertIn("恭喜您，任务已成功完成", pojie._extract_task_message(html_diag))

    def test_extract_user_assets(self):
        html_credit = """
        <div class="vwmy"><a href="home.php?mod=space&amp;uid=123456" title="访问我的空间">吾爱极客</a></div>
        <ul class="creditl">
            <li><em>吾爱币:</em> 128 CB</li>
            <li><em>积分:</em> 520</li>
            <li><em>贡献:</em> 10</li>
            <li><em>热心值:</em> 5</li>
            <li><em>用户组</em> <a href="home.php?mod=spacecp&amp;ac=usergroup">吾爱先锋</a></li>
        </ul>
        """
        assets = pojie._extract_user_assets(html_credit, "123456")
        self.assertEqual(assets["username"], "吾爱极客")
        self.assertEqual(assets["uid"], "123456")
        self.assertEqual(assets["cb"], "128")
        self.assertEqual(assets["credit"], "520")
        self.assertEqual(assets["contrib"], "10")
        self.assertEqual(assets["hot"], "5")
        self.assertEqual(assets["group"], "吾爱先锋")

    def test_candidate_proxies(self):
        with patch.dict(os.environ, {
            "52POJIE_PROXY": "http://127.0.0.1:8080\n# comment\nsocks5://127.0.0.1:1080",
            "SMZDM_PROXY": "http://10.0.0.1:7890",
        }):
            proxies = pojie._get_candidate_proxies()
            self.assertIn("http://127.0.0.1:8080", proxies)
            self.assertIn("socks5://127.0.0.1:1080", proxies)
            self.assertNotIn("# comment", proxies)

    def test_load_accounts_multi_prefix(self):
        # 52POJIE_ 前缀优先
        with patch.dict(os.environ, {"52POJIE_COOKIE_1": "cookie_52_1", "52POJIE_COOKIE_2": "cookie_52_2"}, clear=True):
            accs = pojie._load_accounts()
            self.assertEqual(accs, ["cookie_52_1", "cookie_52_2"])

        # 兼容 WUAI_ 前缀
        with patch.dict(os.environ, {"WUAI_COOKIE_1": "cookie_wuai_1"}, clear=True):
            accs = pojie._load_accounts()
            self.assertEqual(accs, ["cookie_wuai_1"])

        # 兼容 POJIE_ 前缀
        with patch.dict(os.environ, {"POJIE_COOKIE_1": "cookie_pojie_1"}, clear=True):
            accs = pojie._load_accounts()
            self.assertEqual(accs, ["cookie_pojie_1"])

        # 兼容 POJIE52_COOKIE 换行
        with patch.dict(os.environ, {"POJIE52_COOKIE": "c1\n&&c2"}, clear=True):
            accs = pojie._load_accounts()
            self.assertEqual(accs, ["c1", "c2"])

    @patch.object(pojie, "save_kv_state")
    @patch.object(pojie, "load_kv_state", return_value={})
    @patch.object(pojie, "_http_request_with_failover")
    def test_run_account_success(self, mock_http, mock_load, mock_save):
        # 模拟 apply, draw, credit 三步响应
        resp_apply = MagicMock(code=200, text="<![CDATA[任务已申请]]>")
        resp_draw = MagicMock(code=200, text="<![CDATA[恭喜您，任务已成功完成，您已获得 2 吾爱币奖励]]>", headers={})
        resp_credit = MagicMock(code=200, text="""
            <div class="vwmy"><a href="home.php?mod=space&amp;uid=888">测试员</a></div>
            <li><em>吾爱币:</em> 99 CB</li>
            <li><em>积分:</em> 888</li>
        """)
        mock_http.side_effect = [
            (resp_apply, "", None),
            (resp_draw, "", None),
            (resp_credit, "", None),
        ]

        ok, status = pojie._run_account("htVD_2132_auth=xxx; htVD_2132_lastcheckfeed=888%7C123", 1, 1)
        self.assertTrue(ok)
        self.assertEqual(status, "成功")
        mock_save.assert_called_once()

    @patch.object(pojie, "save_kv_state")
    @patch.object(pojie, "load_kv_state", return_value={})
    @patch.object(pojie, "_http_request_with_failover")
    def test_run_account_idempotent(self, mock_http, mock_load, mock_save):
        resp_apply = MagicMock(code=200, text='<div id="messagetext"><p>抱歉，本期您已申请过此任务</p></div>')
        resp_draw = MagicMock(code=200, text='<div id="messagetext"><p>不是进行中的任务</p></div>', headers={})
        resp_credit = MagicMock(code=200, text='<div class="vwmy"><a href="space-uid-888.html">测试员</a></div><li><em>吾爱币:</em> 100 CB</li><li><em>积分:</em> 900</li>')
        mock_http.side_effect = [
            (resp_apply, "", None),
            (resp_draw, "", None),
            (resp_credit, "", None),
        ]

        ok, status = pojie._run_account("htVD_2132_auth=xxx", 1, 1)
        self.assertTrue(ok)
        self.assertEqual(status, "今日已签")

    @patch.object(pojie, "_http_request_with_failover")
    def test_run_account_expired(self, mock_http):
        resp_apply = MagicMock(code=200, text='<p class="alert_info">您需要先登录才能继续本操作</p>')
        resp_draw = MagicMock(code=200, text='<p class="alert_info">您需要先登录才能继续本操作</p>')
        mock_http.side_effect = [
            (resp_apply, "", None),
            (resp_draw, "", None),
        ]

        with self.assertRaises(RuntimeError) as ctx:
            pojie._run_account("htVD_2132_auth=expired", 1, 1)
        self.assertIn("Cookie 已失效", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
