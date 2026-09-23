#!/usr/bin/env python3
"""naixi_forum 签到判定回归测试（python3 -m unittest scripts.tests.test_naixi_forum）。

覆盖历史假成功事故：
- 站点升级后全站页脚 PWA 脚本含英文 "already"（"// If app is already installed..."），
  旧判定 already_markers 含裸 "already" → **任何**页面都被判已签到 → 整段真实签到被
  跳过、CI 却输出「今日已签到（幂等放行）」的假绿。本测试锁定状态机不再命中裸 already。
- 未签到页含「您今天还没有签到」必须判 not_signed（提交真实签到），
  绝不能被已签到词（如统计文案）劫持。
- 提交后仍显示未签到 → 红卡（提交未生效），杜绝再次假成功。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import naixi_forum as nf

# 站点全站页脚（登录/未登录页面均含）——PWA 安装提示脚本
_GLOBAL_FOOTER = (
    "<script>window.addEventListener('beforeinstallprompt',(e)=>{e.preventDefault();});"
    "// If app is already installed, open it\nwindow.open('/', '_blank');</script>"
)


class TestNaixiState(unittest.TestCase):
    def test_bare_already_in_footer_is_not_treated_as_signed(self):
        """全站页脚含裸 'already' 时，未签到页必须判 not_signed（核心假成功回归）。"""
        page = "<div>您今天还没有签到</div>" + _GLOBAL_FOOTER
        self.assertEqual(nf._page_signed_state(page), "not_signed")

    def test_footer_only_page_is_unknown_not_signed(self):
        """只有页脚（无任何签到标记）的页面既非已签到也非未签到 → unknown（不假绿）。"""
        self.assertEqual(nf._page_signed_state(_GLOBAL_FOOTER), "unknown")

    def test_already_signed_markers(self):
        for marker in ("您的签到排名：514", "您今天已经签到，明天再来", "签到成功 恭喜", "今日已签"):
            self.assertEqual(nf._page_signed_state(marker), "already_signed", marker)

    def test_not_signed_wins_over_stats_text(self):
        """未签到页即使含统计文案「今日已签到 X 人」也必须判 not_signed。"""
        page = "您今天还没有签到 今日已签到 679 人 连续签到 天"
        self.assertEqual(nf._page_signed_state(page), "not_signed")


class TestFormHash(unittest.TestCase):
    def test_hidden_input(self):
        self.assertEqual(nf._extract_formhash('<input name="formhash" value="6b84bdf6" />'), "6b84bdf6")

    def test_query_form(self):
        self.assertEqual(nf._extract_formhash('href="k_misign-sign.html?formhash=abc123"'), "abc123")

    def test_missing(self):
        self.assertEqual(nf._extract_formhash("<html>no hash here</html>"), "")


class TestSubmitSign(unittest.TestCase):
    def _http(self, text, code=200):
        h = MagicMock()
        h.request = MagicMock(return_value=MagicMock(code=code, text=text))
        return h

    def test_ok_response(self):
        page = '您今天还没有签到 <a href="k_misign-sign.html?operation=qiandao&formhash=deadbeef">'
        h = self._http('<?xml version="1.0"?><root><![CDATA[<div>签到成功，获得 10 经验</div>]]></root>')
        msg = nf._submit_sign(h, "https://forum.naixi.net", page)
        self.assertIn("签到成功", msg)

    def test_undefined_operation_falls_back_and_raises_when_all_fail(self):
        """接口返回「未定义操作」= 站点接口变更信号，绝不能当成功；全部候选失败即红卡。"""
        page = '您今天还没有签到 <a href="k_misign-sign.html?operation=qiandao&formhash=deadbeef">'
        h = self._http('<?xml version="1.0"?><root><![CDATA[<div class="alert_error">未定义操作</div>]]></root>')
        with self.assertRaises(RuntimeError) as cm:
            nf._submit_sign(h, "https://forum.naixi.net", page)
        self.assertIn("未定义操作", str(cm.exception))

    def test_no_candidate_raises(self):
        page = "您今天还没有签到"  # 无 href、无 formhash
        with self.assertRaises(RuntimeError):
            nf._submit_sign(self._http(""), "https://forum.naixi.net", page)


class TestRunOneFalseSuccess(unittest.TestCase):
    """端到端：全站页脚含 already + 未签到页 → 必须真实提交签到，不得因假绿跳过。"""

    def test_not_signed_page_triggers_real_submit(self):
        login_page = '<input name="formhash" value="aaaa" /> loginhash=LH1"'
        sign_page = '<div>您今天还没有签到</div><a href="k_misign-sign.html?operation=qiandao&formhash=bbbb">' + _GLOBAL_FOOTER
        after_page = ('<div>您的签到排名：3</div><input id="lxdays" value="81">'
                      '<input id="lxtdays" value="86">')
        calls = []

        def fake_request(method, url, **kw):
            calls.append(url)
            if "member.php?mod=logging" in url and method == "GET":
                return MagicMock(code=200, text=login_page)
            if "loginsubmit=yes" in url:
                return MagicMock(code=200, text="<![CDATA[欢迎回来]]>")
            if "operation=qiandao" in url:
                return MagicMock(code=200, text='<![CDATA[<div>签到成功</div>]]>')
            if "ac=credit" in url:
                return MagicMock(code=200, text="<em>点数:</em>18 <em>经验:</em>560 <em>积分:</em>560")
            if "id=k_misign%3Asign" in url:
                # 首次 GET 返回未签到页；提交后再 GET 返回已签到页
                return MagicMock(code=200, text=sign_page if not any("operation=qiandao" in c for c in calls) else after_page)
            return MagicMock(code=200, text="")

        with patch.object(nf, "Http", return_value=MagicMock(request=fake_request)):
            line = nf._run_one("user@example.com", "pw")

        self.assertIn("签到成功", line)
        self.assertIn("连续签到：81天（累计86天）", line)
        self.assertTrue(any("operation=qiandao" in c for c in calls), "未签到页必须真实提交签到")


if __name__ == "__main__":
    unittest.main()