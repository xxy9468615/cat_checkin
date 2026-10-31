#!/usr/bin/env python3
"""52POJIE (吾爱破解) 签到脚本自检与单元测试。

测试覆盖：
1. Cookie 字典解析与 Set-Cookie 滚动合并
2. Discuz 任务消息解析（CDATA、messagetext、alert_info、showDialog 等）
3. 个人资产与积分信息提取（吾爱币、积分、贡献、热心值、等级）
4. 多源代理出口与候选池解析
5. 多前缀与多账号序列加载兼容性
6. 签到状态（成功、今日已签、Cookie 失效、WAF 拦截）判定逻辑
7. Cookie 有效期自动识别（Set-Cookie Expires/Max-Age 学习、Netscape/JSON
   粘贴格式到期字段、估算窗口耗尽后如实报「未知」不产出假 0 天告警）
"""
from __future__ import annotations

import os
import io
import re
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import importlib

pojie = importlib.import_module("52pojie")
from alert_levels import _COOKIE_DAYS_RE  # noqa: E402  与黄色预警引擎的输出契约


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

        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            ok, status = pojie._run_account("htVD_2132_auth=xxx; htVD_2132_lastcheckfeed=888%7C123", 1, 1)
            output = mock_stdout.getvalue()

        self.assertTrue(ok)
        self.assertEqual(status, "成功")
        self.assertIn("UID: 88***8", output)
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

        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            ok, status = pojie._run_account("htVD_2132_auth=xxx", 1, 1)
            output = mock_stdout.getvalue()

        self.assertTrue(ok)
        self.assertEqual(status, "今日已签")
        self.assertIn("今日已签", output)

    @patch.object(pojie, "load_kv_state", return_value={})
    @patch.object(pojie, "_http_request_with_failover")
    def test_run_account_expired(self, mock_http, mock_load):
        resp_apply = MagicMock(code=200, text='<p class="alert_info">您需要先登录才能继续本操作</p>')
        resp_draw = MagicMock(code=200, text='<p class="alert_info">您需要先登录才能继续本操作</p>')
        mock_http.side_effect = [
            (resp_apply, "", None),
            (resp_draw, "", None),
        ]

        with patch("sys.stdout", new_callable=io.StringIO):
            with self.assertRaises(RuntimeError) as ctx:
                pojie._run_account("htVD_2132_auth=expired", 1, 1)
        self.assertIn("Cookie 已失效", str(ctx.exception))

    # ------------------------------------------------------------------
    # 7. Cookie 有效期自动识别
    # ------------------------------------------------------------------
    def test_parse_set_cookie_expiry(self):
        # Expires（PHP 常用连字符 Netscape 格式）
        ts = pojie._parse_set_cookie_expiry("htVD_2132_auth=abc; path=/; expires=Fri, 04-Dec-2026 08:00:00 GMT; HttpOnly")
        self.assertIsNotNone(ts)
        # 空格格式同样兼容
        self.assertEqual(ts, pojie._parse_set_cookie_expiry("a=b; Expires=Fri, 04 Dec 2026 08:00:00 GMT"))
        # Max-Age → now + 秒数
        now = time.time()
        ts2 = pojie._parse_set_cookie_expiry("htVD_2132_auth=abc; Max-Age=86400")
        self.assertIsNotNone(ts2)
        self.assertTrue(now + 86000 <= ts2 <= time.time() + 86800)
        # 负 Max-Age（删除 cookie）/ 无属性 → None
        self.assertIsNone(pojie._parse_set_cookie_expiry("a=b; Max-Age=0"))
        self.assertIsNone(pojie._parse_set_cookie_expiry("htVD_2132_lastact=123"))

    def test_collect_cookie_expiries(self):
        # urllib 路径：headers dict 内的 Set-Cookie 标头；只认 *_2132_auth，
        # saltkey / WAF 短时效 cookie 一律忽略
        resp = MagicMock()
        resp._raw_cookies = None
        resp.headers = {"Set-Cookie": [
            "htVD_2132_auth=abc; expires=Fri, 04-Dec-2026 08:00:00 GMT; path=/",
            "htVD_2132_saltkey=s; expires=Fri, 04-Dec-2026 08:00:00 GMT",
            "acw_tc=short; expires=Sat, 05-Dec-2026 08:00:00 GMT",
        ]}
        out = pojie._collect_cookie_expiries(resp)
        self.assertIn("htVD_2132_auth", out)
        self.assertNotIn("htVD_2132_saltkey", out)
        self.assertNotIn("acw_tc", out)

        # curl_cffi 路径：CookieJar 内 Cookie 自带 expires
        class _JarCookie:
            def __init__(self, name, expires):
                self.name = name
                self.value = "v"
                self.expires = expires

        resp2 = MagicMock()
        resp2.headers = {}
        resp2._raw_cookies = type(
            "FakeCookies", (), {"jar": [_JarCookie("htVD_2132_auth", 1800000000), _JarCookie("wzws_cid", 1900000000)]}
        )()
        out2 = pojie._collect_cookie_expiries(resp2)
        self.assertEqual(out2, {"htVD_2132_auth": 1800000000})

    def test_pick_expiry(self):
        # 只认 auth cookie：lastcheckfeed 时间更晚也不取
        pairs = {"htVD_2132_saltkey": 100, "htVD_2132_lastcheckfeed": 300, "htVD_2132_auth": 200}
        self.assertEqual(pojie._pick_expiry(pairs), 200)
        self.assertIsNone(pojie._pick_expiry({"htVD_2132_saltkey": 100}))
        self.assertIsNone(pojie._pick_expiry({}))

    def test_parse_explicit_cookie_expiry(self):
        # 普通标头格式无到期字段 → None
        self.assertIsNone(pojie._parse_explicit_cookie_expiry("htVD_2132_auth=abc; htVD_2132_saltkey=s"))

        # Netscape 文件格式：7 列制表符，域名过滤 + auth 优先
        netscape = (
            "# Netscape HTTP Cookie File\n"
            ".52pojie.cn\tTRUE\t/\tTRUE\t1900000000\thtVD_2132_auth\txxx\n"
            ".52pojie.cn\tTRUE\t/\tTRUE\t1899999000\thtVD_2132_saltkey\tyyy\n"
            ".example.com\tTRUE\t/\tTRUE\t1999999999\tother\tzzz\n"
        )
        self.assertEqual(pojie._parse_explicit_cookie_expiry(netscape), 1900000000)
        # 无 auth cookie 时回退站点域内最大值
        netscape_no_auth = (
            "# Netscape HTTP Cookie File\n"
            ".52pojie.cn\tTRUE\t/\tTRUE\t1900000000\thtVD_2132_saltkey\tyyy\n"
            ".example.com\tTRUE\t/\tTRUE\t1999999999\tother\tzzz\n"
        )
        self.assertEqual(pojie._parse_explicit_cookie_expiry(netscape_no_auth), 1900000000)

        # 浏览器 JSON 导出格式（EditThisCookie / DevTools），域名过滤
        json_export = (
            '[{"name": "htVD_2132_saltkey", "value": "s", "domain": ".52pojie.cn", "expirationDate": 1899999000},'
            '{"name": "htVD_2132_auth", "value": "a", "domain": ".52pojie.cn", "expirationDate": 1900000000},'
            '{"name": "other", "value": "o", "domain": ".example.com", "expirationDate": 1999999999}]'
        )
        self.assertEqual(pojie._parse_explicit_cookie_expiry(json_export), 1900000000)

    def test_build_expiry_tag(self):
        now = time.time()
        # 真实到期时间（state 学习值）→ 优先采用并带日期
        tag = pojie._build_expiry_tag("k=v", {"cookie_expire_ts": int(now + 23.4 * 86400)})
        self.assertIn("🔑 Cookie 剩余 23 天", tag)
        self.assertIn("到期", tag)
        # 真实到期且 < 7 天 → ⚠️（必须仍命中 alert_levels 的「剩余 N 天」正则，保住黄色预警链路）
        tag_warn = pojie._build_expiry_tag("k=v", {"cookie_expire_ts": int(now + 0.5 * 86400)})
        self.assertIn("⚠️ Cookie 剩余 0 天", tag_warn)
        m_alert = _COOKIE_DAYS_RE.search(tag_warn)
        self.assertIsNotNone(m_alert)
        self.assertLessEqual(int(m_alert.group(1)), 1)
        # 真实到期时间优先于已耗尽的估算窗口
        tag_real = pojie._build_expiry_tag("k=v", {"cookie_expire_ts": int(now + 40 * 86400), "saved_ts": int(now - 90 * 86400)})
        self.assertIn("Cookie 剩余", tag_real)
        self.assertNotIn("有效期未知", tag_real)

        # 估算分支：近期粘贴（saved_ts 不足 3 天，留 2 小时余量防 floor 抖动）→ 30 天窗口内估算
        tag_est = pojie._build_expiry_tag("k=v", {"saved_ts": int(now - 3 * 86400 + 7200)})
        self.assertIn("🔑 Cookie 剩余 27 天", tag_est)
        # 估算耗尽但登录态存活 → 如实报「未知」，不再产出假 0 天告警
        tag_dead = pojie._build_expiry_tag("k=v", {"saved_ts": int(now - 60 * 86400)})
        self.assertIn("Cookie 有效期未知", tag_dead)
        self.assertNotIn("剩余 0 天", tag_dead)
        # 无任何证据 → 无标签
        self.assertEqual(pojie._build_expiry_tag("k=v", {}), "")

    @patch.object(pojie, "save_kv_state")
    @patch.object(pojie, "load_kv_state", return_value={})
    @patch.object(pojie, "_http_request_with_failover")
    def test_run_account_learns_expiry(self, mock_http, mock_load, mock_save):
        # credit 响应下发带 Expires 的 auth Set-Cookie → 学习到期时间并持久化
        sc = "htVD_2132_auth=abc; path=/; expires=Fri, 04-Dec-2026 08:00:00 GMT"
        resp_credit = MagicMock(
            code=200,
            headers={"Set-Cookie": [sc]},
            text='<div class="vwmy"><a href="home.php?mod=space&amp;uid=888">测试员</a></div>'
            "<li><em>吾爱币:</em> 1 CB</li><li><em>积分:</em> 2</li>",
        )
        resp_apply = MagicMock(code=200, text="<![CDATA[任务已申请]]>", headers={})
        resp_draw = MagicMock(code=200, text="<![CDATA[恭喜您，任务已成功完成]]>", headers={})
        mock_http.side_effect = [(resp_credit, "", None), (resp_apply, "", None), (resp_draw, "", None)]

        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            ok, _ = pojie._run_account("htVD_2132_auth=abc", 1, 1)
            output = mock_stdout.getvalue()

        self.assertTrue(ok)
        self.assertTrue(re.search(r"Cookie 剩余 \d+ 天（2026-12-04 到期）", output))
        from http.cookiejar import http2time

        args = mock_save.call_args.args
        saved = args[2] if args else mock_save.call_args.kwargs["state"]
        self.assertEqual(saved.get("cookie_expire_ts"), http2time("Fri, 04 Dec 2026 08:00:00 GMT"))

    @patch.object(pojie, "save_kv_state")
    @patch.object(pojie, "load_kv_state")
    @patch.object(pojie, "_http_request_with_failover")
    def test_run_account_env_change_resets_expiry(self, mock_http, mock_load, mock_save):
        # 旧状态（env_hash 失配）：90 天前保存 + 陈旧学习值 → 换新凭据后全部作废
        stale_ts = int(time.time() - 90 * 86400)
        mock_load.return_value = {
            "env_hash": "old_hash",
            "cookie": "htVD_2132_auth=rolled",
            "cookie_expire_ts": stale_ts,
            "saved_ts": stale_ts,
        }
        resp_credit = MagicMock(
            code=200,
            headers={},
            text='<div class="vwmy"><a href="home.php?mod=space&amp;uid=888">测试员</a></div>'
            "<li><em>吾爱币:</em> 1 CB</li><li><em>积分:</em> 2</li>",
        )
        resp_apply = MagicMock(code=200, text="<![CDATA[恭喜您，任务已成功完成]]>", headers={})
        resp_draw = MagicMock(code=200, text="<![CDATA[恭喜您，任务已成功完成]]>", headers={})
        mock_http.side_effect = [(resp_credit, "", None), (resp_apply, "", None), (resp_draw, "", None)]

        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            ok, _ = pojie._run_account("htVD_2132_auth=fresh", 1, 1)
            output = mock_stdout.getvalue()

        self.assertTrue(ok)
        # 登录态存活但估算窗口已耗尽 → 「未知」而非假 0 天
        self.assertIn("Cookie 有效期未知", output)
        self.assertNotIn("剩余 0 天", output)
        args = mock_save.call_args.args
        saved = args[2] if args else mock_save.call_args.kwargs["state"]
        # 寿命起点重置为本次运行；陈旧学习值作废；滚动 cookie 弃用（使用新粘贴值）
        self.assertGreater(saved.get("saved_ts", 0), time.time() - 120)
        self.assertNotIn("cookie_expire_ts", saved)
        self.assertEqual(saved.get("cookie"), "htVD_2132_auth=fresh")


if __name__ == "__main__":
    unittest.main()
