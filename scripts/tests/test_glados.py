"""GLaDOS 签到挑战回归测试；全部挑战、响应与 Cookie 均为合成数据。"""
import importlib.util
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import Mock, patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

_spec = importlib.util.spec_from_file_location("glados_under_test", BASE / "glados.py")
glados = importlib.util.module_from_spec(_spec)
# dataclass 装饰器在 exec 期间需要按模块名回查 sys.modules
sys.modules[_spec.name] = glados
_spec.loader.exec_module(glados)

SYNTHETIC_COOKIE = "koa:sess=V1.0FAKEsynthetic; koa:sess.sig=V1.0FAKEsynthetic-signature"
SYNTHETIC_NONCE = "V1.0FAKEnonce"
# SHA-256("V1.0FAKEnonce.glados-observe-v1")
EXPECTED_PROOF = "319312a6d3208e98cc735de394a8a461778dbea57c3d0cdf8c755b324a3dc709"


def response(data, code=200):
    return Mock(code=code, text="synthetic response", json=Mock(return_value=data))


def build_api(*responses):
    api = glados.GladosAPI("glados.example", 1)
    api.http = Mock()
    api.http.request.side_effect = list(responses)
    return api


class TestCheckinProof(unittest.TestCase):
    def test_proof_matches_frontend_digest(self):
        self.assertEqual(glados.GladosAPI.proof(SYNTHETIC_NONCE), EXPECTED_PROOF)

    def test_proof_is_hex_sha256(self):
        proof = glados.GladosAPI.proof("")
        self.assertEqual(len(proof), 64)
        int(proof, 16)


class TestCheckinFlow(unittest.TestCase):
    def test_challenge_nonce_and_proof_are_submitted(self):
        api = build_api(
            response({"code": 0, "nonce": SYNTHETIC_NONCE, "ttl": 300000}),
            response({"code": 0, "message": "ok", "points": 12}),
        )
        sleeps = []
        with patch.object(glados.time, "sleep", side_effect=sleeps.append):
            status, code, points, _ = api.checkin(SYNTHETIC_COOKIE)

        self.assertEqual((status, code, points), ("签到成功", glados.CHECKIN_SUCCESS, 12))
        payload = api.http.request.call_args_list[1].kwargs["json_data"]
        self.assertEqual(payload["nonce"], SYNTHETIC_NONCE)
        self.assertEqual(payload["proof"], EXPECTED_PROOF)
        self.assertEqual(payload["tsState"], "off")
        self.assertEqual(payload["token"], "glados.example")
        # 前端固定等待 2500ms 才提交，脚本至少要等待一次
        self.assertEqual(len(sleeps), 1)
        self.assertGreater(sleeps[0], 0)

    def test_turnstile_challenge_reports_timeout_state(self):
        api = build_api(
            response({"code": 0, "nonce": SYNTHETIC_NONCE, "turnstile": "0x4AAAAsynthetic"}),
            response({"code": 2, "reason": "turnstile", "message": "Cloudflare verification failed."}),
        )
        with patch.object(glados.time, "sleep"):
            status, code, _, message = api.checkin(SYNTHETIC_COOKIE)

        payload = api.http.request.call_args_list[1].kwargs["json_data"]
        self.assertEqual(payload["tsState"], "timeout")
        self.assertNotIn("turnstile", payload)
        self.assertEqual((status, code), ("签到失败", glados.CHECKIN_FAILURE))
        self.assertIn("reason=turnstile", message)

    def test_legacy_payload_without_challenge(self):
        api = build_api(
            response({"code": 1, "message": "challenge unavailable"}),
            response({"code": 0, "message": "ok", "points": 3}),
        )
        with patch.object(glados.time, "sleep") as sleep:
            status, code, _, _ = api.checkin(SYNTHETIC_COOKIE)

        payload = api.http.request.call_args_list[1].kwargs["json_data"]
        self.assertEqual(payload, {"token": "glados.example"})
        sleep.assert_not_called()
        self.assertEqual((status, code), ("签到成功", glados.CHECKIN_SUCCESS))

    def test_repeat_checkin_is_not_failure(self):
        api = build_api(
            response({"code": 0, "nonce": SYNTHETIC_NONCE}),
            response({"code": glados.CHECKIN_REPEAT, "message": "already checked in"}),
        )
        with patch.object(glados.time, "sleep"):
            status, code, points, _ = api.checkin(SYNTHETIC_COOKIE)
        self.assertEqual((status, code, points), ("重复签到", glados.CHECKIN_REPEAT, 0))

    def test_device_mismatch_surfaces_as_failure_with_hint(self):
        api = build_api(
            response({"code": 0, "nonce": SYNTHETIC_NONCE}),
            response({"code": 4, "reason": "device-mismatch", "message": "device mismatch"}),
        )
        with patch.object(glados.time, "sleep"):
            status, code, _, message = api.checkin(SYNTHETIC_COOKIE)
        self.assertEqual(status, "需重新登录")
        self.assertEqual(code, glados.CHECKIN_FAILURE)
        self.assertIn("device-mismatch", message)

    def test_permission_denied_counts_as_cookie_expired(self):
        api = build_api(response({"code": -2, "message": "没有权限"}))
        with self.assertRaises(glados.CookieExpiredError):
            api.checkin(SYNTHETIC_COOKIE)


class TestBrowserHelpers(unittest.TestCase):
    def test_cookie_pairs_split(self):
        pairs = glados.parse_cookie_pairs(SYNTHETIC_COOKIE)
        self.assertEqual(pairs["koa:sess"], "V1.0FAKEsynthetic")
        self.assertEqual(pairs["koa:sess.sig"], "V1.0FAKEsynthetic-signature")

    def test_cookie_pairs_ignore_malformed(self):
        self.assertEqual(glados.parse_cookie_pairs("broken; a=b; =c"), {"a": "b"})

    def test_resolve_device_aliases(self):
        cases = {
            "Windows": "windows", "Linux": "linux", "macOS": "macos",
            "MacIntel": "macos", "Android": "android", "iOS": "ios",
            "iPhone": "ios", "": "windows", "FreeBSD": "windows",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(glados.resolve_device(raw), expected)

    def test_device_profiles_have_required_fields(self):
        for name, profile in glados.DEVICE_PROFILES.items():
            with self.subTest(device=name):
                for field in ("ua", "platform", "ch_platform", "mobile", "locale"):
                    self.assertTrue(profile.get(field), f"{name} 缺少 {field}")

    def test_browser_disabled_by_env(self):
        with patch.dict("os.environ", {"GLADOS_BROWSER": "off"}):
            self.assertFalse(glados.BrowserCheckin.enabled())
        with patch.dict("os.environ", {"GLADOS_BROWSER": "auto"}):
            self.assertTrue(glados.BrowserCheckin.enabled())

    def test_browser_missing_playwright_falls_back(self):
        bc = glados.BrowserCheckin(proxy="socks5://127.0.0.1:1080")
        with patch.dict("sys.modules", {"playwright": None, "playwright.sync_api": None}):
            self.assertIsNone(bc.checkin(SYNTHETIC_COOKIE, "glados.example"))
        self.assertTrue(bc._failed)


class TestExpiryTag(unittest.TestCase):
    """Cookie 有效期统一走共享引擎：无证据如实报未知，有证据才倒计时。"""

    def _checker(self):
        checker = glados.Checker.__new__(glados.Checker)
        checker.results = []
        checker.devices = {}
        checker.browser = None
        return checker

    def test_no_evidence_reports_unknown(self):
        checker = self._checker()
        with patch.object(glados, "load_kv_state", return_value={}), \
             patch.object(glados, "save_kv_state") as save:
            tag = checker._expiry_tag(Mock(learned={}), SYNTHETIC_COOKIE, 1,
                                      glados.CHECKIN_SUCCESS)
        self.assertIn("Cookie 有效期未知", tag)
        save.assert_called_once()

    def test_learned_expiry_renders_remaining_days(self):
        checker = self._checker()
        ts = int(time.time()) + 40 * 86400
        with patch.object(glados, "load_kv_state", return_value={}), \
             patch.object(glados, "save_kv_state"):
            tag = checker._expiry_tag(Mock(learned={"gld:sess": ts}),
                                      SYNTHETIC_COOKIE, 1, glados.CHECKIN_SUCCESS)
        self.assertIn("Cookie 剩余 39 天", tag)

    def test_success_marks_run_day(self):
        checker = self._checker()
        state = {}
        with patch.object(glados, "load_kv_state", return_value=state), \
             patch.object(glados, "save_kv_state") as save:
            checker._expiry_tag(Mock(learned={}), SYNTHETIC_COOKIE, 1,
                                glados.CHECKIN_SUCCESS)
        saved = save.call_args[0][2]
        self.assertTrue(saved.get("ok_days_total", 0) >= 1)

    def test_failure_does_not_mark_run_day(self):
        checker = self._checker()
        state = {}
        with patch.object(glados, "load_kv_state", return_value=state), \
             patch.object(glados, "save_kv_state") as save:
            checker._expiry_tag(Mock(learned={}), SYNTHETIC_COOKIE, 1,
                                glados.CHECKIN_FAILURE)
        saved = save.call_args[0][2]
        self.assertFalse(saved.get("ok_days_total"))

    def test_engine_error_falls_back_to_unknown(self):
        checker = self._checker()
        with patch.object(glados, "load_kv_state", side_effect=RuntimeError("boom")):
            tag = checker._expiry_tag(Mock(learned={}), SYNTHETIC_COOKIE, 1, 0)
        self.assertIn("Cookie 有效期未知", tag)


if __name__ == "__main__":
    unittest.main()