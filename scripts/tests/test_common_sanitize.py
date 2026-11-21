#!/usr/bin/env python3
"""common.sanitize_snippet 失败诊断片段脱敏测试。

背景：must_match 等诊断路径会把服务端响应片段拼进异常消息，经 run_task 输出
进入公开 Actions 日志 / Discord 卡片 / 邮件日报，必须先抹除凭据形态内容。
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import common


class TestKvStateWriteConfirmation(unittest.TestCase):
    """save_kv_state 返回 (本地写入成功, 权威写入确认)；load_kv_state
    local_authoritative 模式本地有效时不被远端旧值覆盖（PR #34 第十三轮）。"""

    def test_save_local_mode_confirms_on_local_write(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            with mock.patch.dict(os.environ, {}, clear=True):
                local_ok, confirmed = common.save_kv_state("k", path, {"a": 1})
            self.assertTrue(local_ok)
            self.assertTrue(confirmed)
        finally:
            os.unlink(path)

    def test_save_redis_set_failure_not_confirmed(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            with mock.patch.dict(os.environ, {"UPSTASH_REDIS_REST_URL": "https://fake",
                                              "UPSTASH_REDIS_REST_TOKEN": "V1.0FAKEtok"}, clear=False), \
                 mock.patch.object(common, "upstash_redis_command", return_value=(False, "err")):
                local_ok, confirmed = common.save_kv_state("k", path, {"a": 1})
            self.assertTrue(local_ok)
            self.assertFalse(confirmed, "Redis SET 失败时权威写入未确认")
        finally:
            os.unlink(path)

    def test_save_redis_ok_confirmed(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            with mock.patch.dict(os.environ, {"UPSTASH_REDIS_REST_URL": "https://fake",
                                              "UPSTASH_REDIS_REST_TOKEN": "V1.0FAKEtok"}, clear=False), \
                 mock.patch.object(common, "upstash_redis_command", return_value=(True, {"result": "OK"})):
                local_ok, confirmed = common.save_kv_state("k", path, {"a": 1})
            self.assertTrue(local_ok)
            self.assertTrue(confirmed)
        finally:
            os.unlink(path)

    def test_load_local_authoritative_skips_stale_remote(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write('{"last_credit_ts": 200}')
            path = f.name
        try:
            with mock.patch.object(common, "upstash_redis_command",
                                   return_value=(True, {"result": '{"last_credit_ts": 100}'})) as m_get:
                state = common.load_kv_state("k", path, local_authoritative=True)
            self.assertEqual(state["last_credit_ts"], 200)
            m_get.assert_not_called()
        finally:
            os.unlink(path)

    def test_load_default_remote_still_wins(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write('{"v": 1}')
            path = f.name
        try:
            with mock.patch.dict(os.environ, {"UPSTASH_REDIS_REST_URL": "https://fake",
                                              "UPSTASH_REDIS_REST_TOKEN": "V1.0FAKEtok"}, clear=False), \
                 mock.patch.object(common, "upstash_redis_command",
                                   return_value=(True, {"result": '{"v": 2}'})):
                state = common.load_kv_state("k", path)
            self.assertEqual(state["v"], 2, "默认模式远端优先语义不变")
        finally:
            os.unlink(path)


class TestSanitizeSnippet(unittest.TestCase):
    def test_set_cookie_masked(self):
        raw = 'HTTP/1.1 200 OK\nSet-Cookie: sessionid=abc123def456; Path=/\nServer: nginx'
        out = common.sanitize_snippet(raw)
        self.assertNotIn("abc123def456", out)
        self.assertIn("<masked>", out)
        self.assertIn("Server: nginx", out)

    def test_cookie_header_masked(self):
        out = common.sanitize_snippet("Cookie: token=secret-value-here; uid=1")
        self.assertNotIn("secret-value-here", out)

    def test_bearer_masked(self):
        out = common.sanitize_snippet("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", out)
        self.assertIn("Authorization:", out)

    def test_token_keyvalue_masked(self):
        raw = '{"access_token":"aB3dEf7hIj9kLm1Np3qRs5tU","expires_in":7200}'
        out = common.sanitize_snippet(raw)
        self.assertNotIn("aB3dEf7hIj9kLm1Np3qRs5tU", out)
        self.assertIn("expires_in", out)

    def test_basic_authorization_masked(self):
        # `(?:bearer\s+)?` 只认 Bearer 时，`Basic` 被当成凭据值吃掉，真正的
        # base64 凭据反而留在明文里（CodeRabbit round-8）。合成凭据一律
        # V1.0FAKE 前缀（规则 3/10，round-10 要求）
        fake_basic = "V1.0FAKE" + "dXNlcjpwYXNzd29yZA=="
        self.assertEqual(
            common.sanitize_snippet(f"Authorization: Basic {fake_basic}"),
            "Authorization: <masked>",
        )
        # 无字段名的裸 Basic 形态同样要遮盖
        self.assertEqual(
            common.sanitize_snippet("回显 Basic V1.0FAKEc2VjcmV0MTIzNDU2Nzg5"),
            "回显 <masked>",
        )
        # 反应头值整体遮盖：`Authorization: 未配置` 这类叙述文本一并被遮盖，
        # 诊断价值让位于不泄漏（round-9 起按行尾即字段边界处理）
        self.assertEqual(common.sanitize_snippet("Authorization: 未配置"), "Authorization: <masked>")
        # 不带字段名的普通叙述不在此列，保持原样
        self.assertEqual(common.sanitize_snippet("Basic 认证未配置"), "Basic 认证未配置")

    def test_authorization_unknown_scheme_and_bare_value_masked(self):
        # 枚举方案白名单会漏掉自定义方案与直接携带的裸凭据（CodeRabbit round-9）
        self.assertEqual(
            common.sanitize_snippet("Authorization: Sso-Key V1.0FAKEshort"),
            "Authorization: <masked>",
        )
        self.assertEqual(
            common.sanitize_snippet("Authorization: V1.0FAKEdXNlcjpwYXNzd29yZA=="),
            "Authorization: <masked>",
        )
        self.assertEqual(
            common.sanitize_snippet("Authorization: V1.0FAKEabc"),
            "Authorization: <masked>",
        )

    def test_digest_authorization_masks_whole_parameter_list(self):
        # Digest 的真凭据在 response= 里；只吃一个 token 会在 username="u", 处停下
        # （CodeRabbit round-9）
        out = common.sanitize_snippet(
            'Authorization: Digest username="u", realm="r", nonce="V1.0FAKEnonce", '
            'uri="/x", response="V1.0FAKEdeadbeef"'
        )
        self.assertEqual(out, "Authorization: <masked>")
        for fragment in ("realm", "nonce", "response", "V1.0FAKE"):
            self.assertNotIn(fragment, out)

    def test_authorization_quoted_status_code_is_not_a_boundary(self):
        # 引号内的 `HTTP 401` 是值的一部分，不能据此截断，否则后续的
        # nonce= 等参数会裸奔（CodeRabbit round-10）
        raw = ('Authorization: Digest username="u", '
               'response="HTTP 401 V1.0FAKEsecret", nonce="V1.0FAKEnonce"')
        out = common.sanitize_snippet(raw, limit=None)
        self.assertEqual(out, "Authorization: <masked>")
        self.assertNotIn("V1.0FAKE", out)
        self.assertNotIn("nonce", out)

    def test_credential_internal_http_suffix_stays_masked(self):
        # 凭据内部的 `HTTP401` 不是独立诊断字段：前后边界缺一不可，否则
        # 凭据尾部会以 `HTTP401` 形态留在明文（CodeRabbit round-11）
        for raw in (
            "Authorization: Bearer V1.0FAKEHTTP401",
            "Authorization: Bearer V1.0FAKEabcHTTP 401",
            "Authorization: HTTP 401",
        ):
            out = common.sanitize_snippet(raw, limit=None)
            self.assertEqual(out, "Authorization: <masked>", raw)
            self.assertNotIn("HTTP", out)
        # 独立诊断字段（前有空白、止于字段末尾）仍保留
        self.assertEqual(
            common.sanitize_snippet("Authorization: abc HTTP 401", limit=None),
            "Authorization: <masked> HTTP 401",
        )

    def test_authorization_masking_is_linear(self):
        # 状态码边界前瞻在空格串上会平方级回溯（8k 空格 0.26s）；改为单次
        # 左到右扫描后必须线性（CodeRabbit round-10）
        import time as _time
        for n in (20000, 200000):
            raw = "Authorization: x" + " " * n
            start = _time.monotonic()
            out = common.sanitize_snippet(raw, limit=None)
            elapsed = _time.monotonic() - start
            self.assertEqual(out, "Authorization: <masked>")
            self.assertLess(elapsed, 1.0, f"n={n} 耗时 {elapsed:.3f}s，疑似平方级回溯")

    def test_authorization_many_fields_stay_linear(self):
        # 纯 LF 文本里逐字段 find("\r") 会扫到全文末尾，字段数一多即平方级
        # （CodeRabbit round-12）
        import time as _time
        raw = "\n".join("Authorization: V1.0FAKEfixture" for _ in range(20000))
        start = _time.monotonic()
        out = common.sanitize_snippet(raw, limit=None)
        elapsed = _time.monotonic() - start
        self.assertEqual(out.count("<masked>"), 20000)
        self.assertNotIn("V1.0FAKE", out)
        self.assertLess(elapsed, 1.0, f"耗时 {elapsed:.3f}s，疑似逐字段重扫全文")

    def test_sanitize_limit_none_disables_truncation(self):
        # 脱敏是扩张替换（值 → 定长占位符），按原文长度设上限会在替换后切掉尾部
        raw = "token=ab " * 50 + "z" * 400 + " HTTP 401"
        out = common.sanitize_snippet(raw, limit=None)
        self.assertIn("HTTP 401", out)
        self.assertNotIn("token=ab", out)
        # 显式 limit 仍按语义截断
        self.assertEqual(len(common.sanitize_snippet(raw, limit=300)), 300)

    def test_long_high_entropy_string_masked(self):
        out = common.sanitize_snippet("ok sig=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 done")
        self.assertNotIn("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", out)

    def test_plain_text_preserved(self):
        raw = "登录失败：用户名或密码错误 (error_code=1001)，请检查账号"
        self.assertEqual(common.sanitize_snippet(raw), raw)

    def test_truncated_to_limit(self):
        out = common.sanitize_snippet("登录失败 重试 " * 60, limit=300)
        self.assertEqual(len(out), 300)

    def test_newlines_flattened(self):
        out = common.sanitize_snippet("line1\nline2\nline3")
        self.assertNotIn("\n", out)

    def test_empty_input(self):
        self.assertEqual(common.sanitize_snippet(""), "")
        self.assertEqual(common.sanitize_snippet(None), "")


class TestRedactPii(unittest.TestCase):
    """common.redact_pii 按出现形态脱敏裸 PII（代理标签等无字段名的服务端文案）。

    典型泄漏面：用户把节点命名成自己的邮箱时，公开仓库的 Actions 日志、Discord
    卡片与邮件日报长期暴露该地址，直接招来钓鱼邮件（2026-11-15 用户反馈）。
    """

    def test_ascii_email_masked(self):
        self.assertEqual(common.redact_pii("fixture_user@gmail.com"), "***user@***")
        self.assertEqual(
            common.redact_pii("fixture_user13800138000@example.com"), "***8000@***"
        )
        # 引号包裹的本地部分走兜底：整段保守遮盖，不留可识别前缀
        self.assertEqual(common.redact_pii('"quoted"@example.com'), "***@***")

    def test_idn_email_masked(self):
        # 中文域名此前两个邮箱模式都不匹配，完整地址会进入 display_name 与日志
        self.assertEqual(common.redact_pii("alice@例子.中国"), "***lice@***")
        self.assertEqual(common.redact_pii("user123@香港.example"), "***r123@***")

    def test_phone_shapes_masked(self):
        self.assertEqual(common.redact_pii("13800138000"), "*******8000")
        self.assertEqual(common.redact_pii("+8613800138000"), "+86*******8000")
        # 无 86 的国际号码不得保留前两位
        self.assertEqual(common.redact_pii("+13800138000"), "+*******8000")
        # 常见分隔符写法只留末 4 位（号码拼接后统一遮盖，不保留首位数字）
        self.assertEqual(common.redact_pii("138-0013-8000"), "*******8000")
        self.assertEqual(common.redact_pii("138 0013 8000"), "*******8000")

    def test_intl_phone_with_separators_masked(self):
        # 原规则只认 `+86` + 连续 11 位，其余国家码与分隔写法整条漏过
        # （CodeRabbit round-9）：完整号码会经 _safe_proxy_name 进 display_name
        self.assertEqual(common.redact_pii("+1 202-555-0123"), "+1 ***-***-0123")
        self.assertEqual(common.redact_pii("+44 20 7946 0958"), "+44 ** **** 0958")
        self.assertEqual(common.redact_pii("+86 138 0013 8000"), "+86 *** **** 8000")
        # 分隔符保留、只留末 4 位数字
        out = common.redact_pii("+1 202-555-0123")
        self.assertEqual(out.replace("+1", "").replace(" ", "").replace("-", "")[-4:], "0123")
        # 日期/时间写法不是号码，不得被误伤
        self.assertEqual(common.redact_pii("+1 2020-01-01 12:00"), "+1 2020-01-01 12:00")
        self.assertEqual(common.redact_pii("+1 2020-01-01"), "+1 2020-01-01")
        # 但「日期前缀 + 多余数字」与号码有歧义，必须保守遮盖（round-10）
        for ambiguous in ("+1 2020-01-0188", "+1 2020-01-0112"):
            self.assertNotEqual(common.redact_pii(ambiguous), ambiguous)

    def test_continuous_intl_phone_does_not_guess_country_code(self):
        # 无分隔符时国家码无法可靠切分：`+442079460958` 的真实国家码是 +44，
        # 贪婪取 3 位会把号码首位 `2` 当成国家码留在明文（CodeRabbit round-12）
        out = common.redact_pii("+442079460958")
        self.assertEqual(out[-4:], "0958")          # 只留末 4 位
        self.assertNotIn("207946", out)              # 号码主体不得残留
        self.assertNotIn("442", out)                 # 也不得把首位算进国家码输出
        # 带分隔符的等价输入仍按国家码 + 掩码主体呈现
        self.assertEqual(common.redact_pii("+44 20 7946 0958"), "+44 ** **** 0958")
        # 已识别 +86 的形态保持原样
        self.assertEqual(common.redact_pii("+8613800138000"), "+86*******8000")

    def test_mixed_grouping_intl_phone_keeps_only_last4(self):
        # 分组不规整（`+44` 后没有分隔符、号码中途才有空格）时，连续规则只吃
        # 前半段会把后半段 `0958` 单独放行，国家码贪婪又吃掉号码首位——两种
        # 都会泄漏超过末 4 位（CodeRabbit round-13）
        for raw in ("+44207946 0958", "+442079460958"):
            out = common.redact_pii(raw)
            visible = out.replace("+", "").replace(" ", "").replace("*", "")
            self.assertEqual(visible, "0958", f"{raw} -> {out}")
            self.assertNotIn("7946", out)
            self.assertNotIn("20794", out)
        # 国家码后紧跟分隔符的形态不受影响，仍保留国家码
        self.assertEqual(common.redact_pii("+44 20 7946 0958"), "+44 ** **** 0958")
        # 日期形态在这条兜底路径上同样不被误伤
        self.assertEqual(common.redact_pii("+1 2020-01-01 12:00"), "+1 2020-01-01 12:00")

    def test_non_collateral_preserved(self):
        # 前后邻接数字的 11 位段不命中：13 位毫秒时间戳 / 16 位 GUID / 长 docid
        self.assertEqual(common.redact_pii("1763200000000"), "1763200000000")
        self.assertEqual(common.redact_pii("1234567890123456"), "1234567890123456")
        # 非邮箱/手机号形态保持原样，避免过度遮盖破坏可用信息
        self.assertEqual(common.redact_pii("a@b"), "a@b")
        self.assertEqual(common.redact_pii("香港-01"), "香港-01")
        self.assertEqual(common.redact_pii("socks5://u:p@1.2.3.4:1080"),
                         "socks5://u:p@1.2.3.4:1080")
        # 版本号式连字符数字串不是手机号
        self.assertEqual(common.redact_pii("v1.2.3-4567-8901"), "v1.2.3-4567-8901")

    def test_domain_label_excludes_dot_to_avoid_backtracking(self):
        # 标签含 `.` 时连续点号可被切成多种组合，匹配失败即无界回溯：
        # "x@" + "a."*20 + "!" 实测 0.1s、28 组 3s 未返回。redact_pii 处理任意
        # 输出行，必须在线性时间内返回。
        import time

        hostile = "x@" + "a." * 40 + "!"
        t0 = time.monotonic()
        out = common.redact_pii(hostile)
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 1.0, f"redact_pii 疑似指数回溯，耗时 {elapsed:.3f}s")
        # 连续点号的畸形域名不再被识别为邮箱（保守放弃，不泄漏裸文本即可）
        self.assertIsInstance(out, str)

    def test_empty_input(self):
        self.assertEqual(common.redact_pii(""), "")
        self.assertEqual(common.redact_pii(None), "")


class TestMustMatchUsesSanitize(unittest.TestCase):
    def test_failure_message_is_sanitized(self):
        page = '<html>Set-Cookie: sessionid=supersecret123; Path=/</html>'
        with self.assertRaises(RuntimeError) as ctx:
            common.must_match(r'name="formhash" value="(.+?)"', page, "formhash")
        self.assertNotIn("supersecret123", str(ctx.exception))
        self.assertIn("formhash", str(ctx.exception))

    def test_success_path_unchanged(self):
        self.assertEqual(
            common.must_match(r'value="(.+?)"', 'value="abc"', "v"),
            "abc",
        )


class TestMaskEnhanced(unittest.TestCase):
    """2026-10-31 脱敏增强：手机号只留末4 / 昵称末3 / 邮箱末4+域名全脱 / GDPR 通用。"""

    def test_mask_phone_keeps_last4_only(self):
        # 11 位手机号：只保留末 4 位，前 7 位全掩码（不再露出前 3 位号段）
        self.assertEqual(common.mask_phone("13812345678"), "*******5678")
        self.assertEqual(common.mask_str("13812345678"), "*******5678")
        # 8~15 位纯数字 ID 同规则
        self.assertEqual(common.mask_phone("12345678"), "****5678")
        # 非 11 位形态回退通用规则
        self.assertEqual(common.mask_phone("abc"), "***")

    def test_mask_nickname_keeps_last3(self):
        self.assertEqual(common.mask_nickname("王小虎要加油"), "***要加油")
        self.assertEqual(common.mask_str("王小虎要加油"), "***要加油")
        # ≤4 位全脱（防短名反推）
        self.assertEqual(common.mask_nickname("张三"), "***")
        self.assertEqual(common.mask_nickname("abcd"), "***")

    def test_mask_email_last4_and_full_domain_mask(self):
        # 前缀只留末 4 位，域名全额脱敏（不再保留首字符/TLD）
        self.assertEqual(common.mask_email("user123@gmail.com"), "***r123@***")
        self.assertEqual(common.mask_str("abc@aifre.cyou"), "***@***")
        # 前缀 ≤4 位：全脱
        self.assertEqual(common.mask_email("ab@x.com"), "***@***")
        # 非邮箱形态回退通用规则
        self.assertEqual(common.mask_email("plainname"), "***ame")

    def test_mask_generic_gdpr_defaults(self):
        # 通用：不露头部，定长掩码防长度泄漏；≤4 全脱；≥5 只露末 3
        self.assertEqual(common.mask_str("hun8461"), "***461")
        self.assertEqual(common.mask_str("yd_219491735"), "***735")
        self.assertEqual(common.mask_str("admin"), "***min")
        self.assertEqual(common.mask_str("张三"), "***")
        self.assertEqual(common.mask_str(""), "")
        self.assertEqual(common.mask_str(None), "")

    def test_mask_explicit_keeps_backward_compat(self):
        # 显式 keep_start/keep_end 维持旧语义（调用方显式决策，如 sign 4/4、代理 6/3）
        self.assertEqual(common.mask_str("0123456789abcdef", 4, 4), "0123***cdef")
        self.assertEqual(common.mask_str("abcdef123456", 6, 3), "abcdef***456")
        # 含 @ 的串优先按邮箱路由（新旧一致），显式 keep 参数不改变该优先级
        self.assertEqual(common.mask_str("a@b.com", 1, 1), "***@***")


if __name__ == "__main__":
    unittest.main()
