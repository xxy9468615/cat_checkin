#!/usr/bin/env python3
"""cookie_validity 单元测试：全任务共享的凭据有效期引擎。

覆盖：内嵌证据解析（JWT/koa:sess/sid_guard）、Set-Cookie/CookieJar 学习、
粘贴格式导出（JSON/Netscape）、state 指纹跟踪、build_tag 全分支渲染，
以及与 alert_levels / report_fields 的口径兼容。

用法：python3 scripts/tests/test_cookie_validity.py
"""
import base64
import json
import re
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.cookiejar import Cookie
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent  # scripts/
sys.path.insert(0, str(BASE))

import cookie_validity as cv  # noqa: E402

DAY = 86400
NOW = 1_800_000_000  # 固定「当前时间」，全部用例确定性断言


def _b64u(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _b64(obj) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


def _cookie(name, value, expires=None, domain="example.com"):
    return Cookie(
        version=0, name=name, value=value, port=None, port_specified=False,
        domain=domain, domain_specified=True, domain_initial_dot=False, path="/",
        path_specified=True, secure=False, expires=expires, discard=expires is None,
        comment=None, comment_url=None, rest={},
    )


class TestValueParsers(unittest.TestCase):
    """内嵌证据解析：JWT / koa:sess / sid_guard / Set-Cookie。"""

    def test_jwt_exp_standard(self):
        tok = f"aaa.{_b64u({'exp': NOW + 50 * DAY})}.sig"
        self.assertEqual(cv.parse_jwt_exp(tok), NOW + 50 * DAY)

    def test_jwt_payload_first_segment(self):
        # NodeSeek pjwt 把 payload 放在第 1 段（非标准 JWT）
        tok = f"{_b64u({'ts': NOW, 'id': 1})}.sig"
        self.assertEqual(cv.parse_jwt_issued_ts(tok), NOW)

    def test_jwt_millisecond_normalization(self):
        tok = f"aaa.{_b64u({'exp': (NOW + 50 * DAY) * 1000})}.sig"
        self.assertEqual(cv.parse_jwt_exp(tok), NOW + 50 * DAY)

    def test_jwt_invalid(self):
        self.assertIsNone(cv.parse_jwt_exp("not-a-jwt"))
        self.assertIsNone(cv.parse_jwt_exp("a.!!!.c"))

    def test_koa_sess_expire(self):
        from urllib.parse import quote

        raw = quote(_b64({"_expire": (NOW + 20 * DAY) * 1000}))
        self.assertEqual(cv.parse_koa_sess_expire(raw), NOW + 20 * DAY)
        self.assertIsNone(cv.parse_koa_sess_expire("garbage"))

    def test_sid_guard(self):
        v = "abc123|1780000000|5184000"
        self.assertEqual(cv.parse_sid_guard_expire(v), 1780000000 + 5184000)
        self.assertIsNone(cv.parse_sid_guard_expire("no-pipe-here"))

    def test_set_cookie_expiry(self):
        expires = "Wed, 21 Oct 2026 07:28:00 GMT"
        sc = f"a=1; Expires={expires}; Path=/"
        self.assertEqual(cv.parse_set_cookie_expiry(sc), 1792567680)
        sc2 = f"a=1; Max-Age=86400"
        self.assertAlmostEqual(
            cv.parse_set_cookie_expiry(sc2), time.time() + DAY, delta=5
        )
        self.assertIsNone(cv.parse_set_cookie_expiry("a=1; Path=/"))  # 会话 cookie


class TestLearn(unittest.TestCase):
    """学习：响应标头与 CookieJar。"""

    def test_learn_from_response_urllib(self):
        class H:  # http.client.HTTPMessage 风格：get_all
            @staticmethod
            def get_all(name, default=None):
                if name == "Set-Cookie":
                    return [
                        f"BDUSS=x; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/",
                        "acw_tc=y; Path=/",  # 会话 cookie：无证据
                    ]
                return default
        out = cv.learn_from_response(type("R", (), {"headers": H()})())
        self.assertEqual(out, {"BDUSS": 1792567680})

    def test_learn_from_response_dict_headers(self):
        # curl_cffi 风格：headers 为 dict，单标头串接多条
        sc = (
            "s1=v1; Max-Age=3600; Path=/\\n"
            "s2=v2; Max-Age=7200; Path=/"
        ).replace("\\n", "\r\n")
        out = cv.learn_from_response(
            type("R", (), {"headers": {"Set-Cookie": sc.replace("\r\n", "\n")}})()
        )
        self.assertEqual(len(out), 2)
        self.assertIn("s1", out)

    def test_learn_from_jar_with_filter(self):
        jar = [
            _cookie("BDUSS", "x", expires=NOW + 10 * DAY),
            _cookie("acw_tc", "y"),  # 无 expires
            _cookie("other_auth", "z", expires=NOW + 3 * DAY),
        ]
        out = cv.learn_from_jar(jar)
        self.assertEqual(out, {"BDUSS": NOW + 10 * DAY, "other_auth": NOW + 3 * DAY})
        only = cv.learn_from_jar(jar, credential_match=lambda n: n == "BDUSS")
        self.assertEqual(only, {"BDUSS": NOW + 10 * DAY})

    def test_merge_learned(self):
        self.assertEqual(
            cv.merge_learned({"a": 5}, {"a": 9, "b": 1}), {"a": 9, "b": 1}
        )


class TestCookieStrEvidence(unittest.TestCase):
    """粘贴 Cookie 串的内嵌证据提取。"""

    def test_plain_jwt_cookie(self):
        tok = f"aaa.{_b64u({'exp': NOW + 40 * DAY})}.sig"
        s = f"u1s1_session={tok}; foo=bar"
        self.assertEqual(cv.expire_from_cookie_str(s), NOW + 40 * DAY)

    def test_window_anchored_jwt(self):
        tok = f"aaa.{_b64u({'ts': NOW})}.sig"  # 无 exp，仅签发时间
        self.assertEqual(
            cv.expire_from_cookie_str(f"pjwt={tok}", window_days=30),
            NOW + 30 * DAY,
        )
        self.assertIsNone(cv.expire_from_cookie_str(f"pjwt={tok}"))  # 未声明窗口

    def test_koa_sess_in_string(self):
        s = f"koa:sess={_b64({'_expire': (NOW + 15 * DAY) * 1000})}; koa:sess.sig=abc"
        self.assertEqual(cv.expire_from_cookie_str(s), NOW + 15 * DAY)

    def test_credential_filter_excludes_others(self):
        long_jwt = f"aaa.{_b64u({'exp': NOW + 100 * DAY})}.sig"
        cred_jwt = f"aaa.{_b64u({'exp': NOW + 10 * DAY})}.sig"
        s = f"tracker={long_jwt}; sess={cred_jwt}"
        self.assertEqual(
            cv.expire_from_cookie_str(s, credential_match=lambda n: n == "sess"),
            NOW + 10 * DAY,
        )

    def test_json_export(self):
        s = json.dumps([
            {"name": "auth", "domain": ".52pojie.cn", "expirationDate": NOW + 30 * DAY},
            {"name": "other", "domain": ".example.com", "expirationDate": NOW + 99 * DAY},
        ])
        self.assertEqual(
            cv.expire_from_cookie_str(s, domain_hint="52pojie"), NOW + 30 * DAY
        )

    def test_netscape_export(self):
        s = (
            f".52pojie.cn\tTRUE\t/\tTRUE\t{NOW + 25 * DAY}\tauth\txyz\n"
            f".52pojie.cn\tTRUE\t/\tFALSE\t0\tsess\tabc"
        )
        self.assertEqual(cv.expire_from_cookie_str(s, domain_hint="52pojie"), NOW + 25 * DAY)

    def test_empty(self):
        self.assertIsNone(cv.expire_from_cookie_str(""))
        self.assertIsNone(cv.expire_from_cookie_str("a=1; b=2"))


class TestUpdateState(unittest.TestCase):
    """state 指纹跟踪。"""

    def test_first_seen_and_learned(self):
        st = cv.update_state({}, "a=1", {"BDUSS": NOW + 10 * DAY})
        self.assertIn("first_seen_ts", st)
        self.assertEqual(st["cookie_expire_ts"], NOW + 10 * DAY)

    def test_fingerprint_change_resets(self):
        st = cv.update_state({}, "a=1", {"x": NOW + 10 * DAY})
        st2 = cv.update_state(st, "a=2", None)
        self.assertNotIn("cookie_expire_ts", st2)  # 换新 Cookie：旧证据清除
        self.assertEqual(st2["cookie_md5"], cv.update_state({}, "a=2")["cookie_md5"])

    def test_sliding_renewal_only_grows(self):
        st = cv.update_state({}, "a=1", {"x": NOW + 10 * DAY})
        st = cv.update_state(st, "a=1", {"x": NOW + 30 * DAY})
        self.assertEqual(st["cookie_expire_ts"], NOW + 30 * DAY)


class TestBuildTag(unittest.TestCase):
    """渲染分支与告警口径兼容。"""

    def test_real_evidence_ok(self):
        tag = cv.build_tag({"first_seen_ts": NOW - 5 * DAY}, learned={"x": NOW + 20 * DAY}, now=NOW)
        self.assertIn("🔑 Cookie 剩余 20 天", tag)
        self.assertIn("到期", tag)

    def test_real_evidence_warn(self):
        tag = cv.build_tag({}, learned={"x": NOW + 3 * DAY}, now=NOW)
        self.assertIn("⚠️ Cookie 剩余 3 天", tag)
        self.assertIn("请尽快更新", tag)

    def test_fallback_window(self):
        st = {"first_seen_ts": NOW - 20 * DAY}
        tag = cv.build_tag(st, fallback_lifetime_days=45, now=NOW)
        self.assertIn("🔑 Cookie 剩余 25 天", tag)
        # 窗口耗尽但登录态存活 → 如实报未知（杜绝假 0 天）
        st2 = {"first_seen_ts": NOW - 50 * DAY}
        tag2 = cv.build_tag(st2, fallback_lifetime_days=45, now=NOW)
        self.assertIn("有效期未知", tag2)
        # 无 mark_ok 计数的历史状态：按「已运行」口径（first_seen 不冒充成功天数）
        self.assertIn("已运行 50 天", tag2)
        self.assertIn("超出 45 天估算窗口", tag2)
        self.assertIn("建议预防性更新", tag2)

    def test_unknown_with_usage(self):
        tag = cv.build_tag({"first_seen_ts": NOW - 9 * DAY}, now=NOW)
        self.assertIn("🔑 Cookie 有效期未知（已使用 9 天", tag)  # 无计数历史状态沿用已使用口径
        self.assertNotIn("剩余", tag)

    def test_stale_evidence_ignored(self):
        # 到期证据已过期但登录态存活 → 不产出假 0 天，走未知分支
        tag = cv.build_tag(
            {"first_seen_ts": NOW - 40 * DAY, "cookie_expire_ts": NOW - 5 * DAY}, now=NOW
        )
        self.assertIn("有效期未知", tag)
        self.assertNotIn("剩余 0 天", tag)

    def test_no_state_empty_tag(self):
        self.assertEqual(cv.build_tag({}, now=NOW), "")

    def test_token_label(self):
        tag = cv.build_tag({}, learned={"t": NOW + 50 * DAY}, label="Token", now=NOW)
        self.assertIn("Token 剩余 50 天", tag)

    def test_alert_levels_regex_compat(self):
        # alert_levels._COOKIE_DAYS_RE 必须能从标签中提取天数
        from alert_levels import _COOKIE_DAYS_RE

        for learned in ({"x": NOW + 1 * DAY}, {"x": NOW + 20 * DAY}):
            tag = cv.build_tag({}, learned=learned, now=NOW)
            m = _COOKIE_DAYS_RE.search(tag)
            self.assertIsNotNone(m, tag)
            self.assertEqual(int(m.group(1)), cv.remaining_days(max(learned.values()), NOW))

    def test_report_fields_compat(self):
        # report_fields 的「Cookie 有效期未知」解析口径
        tag = cv.build_tag({"first_seen_ts": NOW - 3 * DAY}, now=NOW)
        self.assertIn("Cookie 有效期未知", tag)


if __name__ == "__main__":
    unittest.main(verbosity=2)
