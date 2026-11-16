#!/usr/bin/env python3
"""common.sanitize_snippet 失败诊断片段脱敏测试。

背景：must_match 等诊断路径会把服务端响应片段拼进异常消息，经 run_task 输出
进入公开 Actions 日志 / Discord 卡片 / 邮件日报，必须先抹除凭据形态内容。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import common


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
        # base64 凭据反而留在明文里（CodeRabbit round-8）
        self.assertEqual(
            common.sanitize_snippet("Authorization: Basic dXNlcjpwYXNzd29yZA=="),
            "Authorization: <masked>",
        )
        # 无字段名的裸 Basic 形态同样要遮盖
        self.assertEqual(
            common.sanitize_snippet("回显 Basic c2VjcmV0MTIzNDU2Nzg5"),
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
            common.sanitize_snippet("Authorization: dXNlcjpwYXNzd29yZA=="),
            "Authorization: <masked>",
        )
        self.assertEqual(common.sanitize_snippet("Authorization: abc"), "Authorization: <masked>")

    def test_digest_authorization_masks_whole_parameter_list(self):
        # Digest 的真凭据在 response= 里；只吃一个 token 会在 username="u", 处停下
        # （CodeRabbit round-9）
        out = common.sanitize_snippet(
            'Authorization: Digest username="u", realm="r", nonce="n", '
            'uri="/x", response="deadbeef"'
        )
        self.assertEqual(out, "Authorization: <masked>")
        for fragment in ("realm", "nonce", "response", "deadbeef"):
            self.assertNotIn(fragment, out)

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
