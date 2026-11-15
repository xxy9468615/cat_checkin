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
        # 常见分隔符写法只留末 4 位
        self.assertEqual(common.redact_pii("138-0013-8000"), "1**-****-8000")
        self.assertEqual(common.redact_pii("138 0013 8000"), "1**-****-8000")

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
