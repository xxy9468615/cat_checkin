"""GLaDOS 签到挑战回归测试；全部挑战、响应与 Cookie 均为合成数据。"""
import importlib.util
from pathlib import Path
import sys
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


if __name__ == "__main__":
    unittest.main()