"""CapCat solver regression tests; all challenges, responses and credentials are synthetic."""
import base64
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
import zlib

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

# This script invokes main_guard at import time; never run account/network work.
_spec = importlib.util.spec_from_file_location("u1s1_under_test", BASE / "u1s1.py")
u1s1 = importlib.util.module_from_spec(_spec)
with patch("common.main_guard"):
    _spec.loader.exec_module(u1s1)

SYNTHETIC_TOKEN = "V1.0FAKEsynthetic"
SYNTHETIC_CAP = "V1.0FAKEsynthetic-cap"


def response(data, code=200):
    return Mock(code=code, text="synthetic response", json=Mock(return_value=data))


class TestInstrumentation(unittest.TestCase):
    """Remote instrumentation JS is untrusted and must never be executed."""

    def test_instrumentation_rejected_without_execution_or_redeem(self):
        # Fits the old extraction markers and writes a file if ever run by Node.
        js = ("'*');return;}"
              "require('fs').writeFileSync('/tmp/u1s1-instr-marker', 'executed');"
              "return state;})();"
              "parent.postMessage({type: 'cap:instr',result:{i:\"abcdef\"}})")
        compressor = zlib.compressobj(wbits=-15)
        blob = base64.b64encode(compressor.compress(js.encode()) + compressor.flush()).decode()
        for payload in ({"blob": blob}, {}, {"blob": "invalid encoding"}):
            with self.subTest(payload=payload):
                h = Mock()
                h.request.return_value = response({
                    "token": SYNTHETIC_TOKEN, "format": 2,
                    "challenges": [{"protocol": "instrumentation", "payload": payload}],
                })
                with patch("subprocess.run") as execute:
                    with self.assertRaisesRegex(RuntimeError, "instrumentation"):
                        u1s1.fetch_cap_token(h)
                    execute.assert_not_called()
                self.assertEqual(h.request.call_count, 1)

    def test_no_remote_js_harness_remains(self):
        self.assertFalse(hasattr(u1s1, "_run_instr"))
        self.assertFalse(hasattr(u1s1, "_decode_instr_blob"))
        for name in ("base64", "json", "os", "shutil", "subprocess", "tempfile", "zlib"):
            self.assertFalse(hasattr(u1s1, name), f"u1s1 不应再保留 {name} 依赖")

    def test_rejected_challenge_preserves_direct_claim_fallback(self):
        h = Mock()
        h.request.side_effect = [
            response({"token": SYNTHETIC_TOKEN, "format": 2, "challenges": [
                {"protocol": "instrumentation", "payload": {}},
            ]}),
            response({"error": "captcha required"}, code=400),
        ]
        ok, _ = u1s1.run_account(1, 1, SYNTHETIC_TOKEN + "-session", h)
        self.assertFalse(ok)
        self.assertEqual(h.request.call_count, 2)
        self.assertEqual(h.request.call_args.args[1],
                         "https://u1s1.io/api/packages/login-checkin/claim")
        self.assertEqual(h.request.call_args.kwargs["json_data"], {})


class TestSupportedProtocols(unittest.TestCase):
    def test_supported_format_two_redeems_local_solutions(self):
        h = Mock()
        h.request.side_effect = [response({
            "token": SYNTHETIC_TOKEN, "format": 2, "challenges": [
                {"protocol": "rsw", "payload": {"N": "11", "x": "2", "t": 3}},
                {"protocol": "sha256-pow", "payload": {"salt": "test", "target": ""}},
            ],
        }), response({"success": True, "token": SYNTHETIC_CAP})]
        self.assertEqual(u1s1.fetch_cap_token(h), SYNTHETIC_CAP)
        self.assertEqual(h.request.call_args.kwargs["json_data"], {
            "token": SYNTHETIC_TOKEN, "solutions": [{"y": "1"}, {"nonce": 0}],
        })

    def test_legacy_format_redeems_local_solutions(self):
        h = Mock()
        h.request.side_effect = [
            response({"token": SYNTHETIC_TOKEN, "challenge": {"c": 1, "s": 4, "d": 0}}),
            response({"success": True, "token": SYNTHETIC_CAP}),
        ]
        self.assertEqual(u1s1.fetch_cap_token(h), SYNTHETIC_CAP)
        self.assertEqual(h.request.call_args.kwargs["json_data"]["solutions"], [0])


class TestLegacyChallenge(unittest.TestCase):
    def test_nonce_vectors_and_continuous_index(self):
        # Seeds carry the V1.0FAKE fixture prefix, so vectors differ from the
        # pre-prefix values ([2, 3, 400, 279]).
        self.assertEqual(u1s1.solve_challenge(SYNTHETIC_TOKEN, [
            {"c": 2, "s": 16, "d": 1}, {"c": 2, "s": 8, "d": 2},
        ]), [13, 27, 144, 64])
        self.assertEqual(
            u1s1.solve_challenge(SYNTHETIC_TOKEN, {"c": "2", "s": "16", "d": "1"}),
            [13, 27],
        )

    def test_invalid_dimensions_rejected_before_generation(self):
        for key, values in {"c": [-1, 1025, 10**100, True, 1.5, None, "9" * 1000],
                            "s": [-1, 4097], "d": [-1, 65]}.items():
            for value in values:
                with self.subTest(key=key, value=str(value)[:20]):
                    spec = {"c": 1, "s": 16, "d": 1, key: value}
                    with patch.object(u1s1, "_prng") as generate:
                        with self.assertRaises(RuntimeError):
                            u1s1.solve_challenge(SYNTHETIC_TOKEN, spec)
                        generate.assert_not_called()

    def test_aggregate_limits_and_late_invalid_spec(self):
        for specs in ([{"c": 513, "s": 0, "d": 0}] * 2,
                      [{"c": 129, "s": 4096, "d": 0}] * 2,
                      [{"c": 0, "s": 0, "d": 0}] * 1025,
                      [{"c": 1, "s": 1, "d": 0}, {"c": 1, "s": 4097, "d": 0}]):
            with patch.object(u1s1, "_prng") as generate:
                with self.assertRaises(RuntimeError):
                    u1s1.solve_challenge(SYNTHETIC_TOKEN, specs)
                generate.assert_not_called()

    def test_solution_and_generated_byte_boundaries(self):
        self.assertEqual(
            len(u1s1.solve_challenge(SYNTHETIC_TOKEN, {"c": 1024, "s": 0, "d": 0})), 1024)
        self.assertEqual(
            u1s1.solve_challenge(SYNTHETIC_TOKEN, {"c": 256, "s": 4096, "d": 0}), [0] * 256)

    def test_deadline_during_generation(self):
        with patch.object(u1s1.time, "monotonic", side_effect=[0, 0, 121]):
            with self.assertRaisesRegex(RuntimeError, "超时"):
                u1s1._prng(SYNTHETIC_TOKEN, 4096, deadline=120)

    def test_immediate_success_still_checks_deadline(self):
        with patch.object(u1s1, "_prng", return_value=""), patch.object(
                u1s1.time, "monotonic", side_effect=[0, 0, 0, 0, 0, 121]):
            with self.assertRaisesRegex(RuntimeError, "超时"):
                u1s1.solve_challenge(SYNTHETIC_TOKEN, {"c": 2, "s": 0, "d": 0})

    def test_unsuccessful_search_checks_deadline(self):
        with patch.object(u1s1, "_prng", return_value="impossible"), patch.object(
                u1s1.time, "monotonic", side_effect=[0, 0, 0, 0, 0, 121]):
            with self.assertRaisesRegex(RuntimeError, "超时"):
                u1s1.solve_challenge(SYNTHETIC_TOKEN, {"c": 1, "s": 1, "d": 1})

    def test_rejected_remote_challenge_is_not_redeemed(self):
        http = Mock()
        http.request.return_value.text = "synthetic response"
        http.request.return_value.code = 200
        http.request.return_value.json.return_value = {
            "token": SYNTHETIC_TOKEN, "challenge": {"c": 10**20, "s": 1, "d": 0}}
        with self.assertRaises(RuntimeError):
            u1s1.fetch_cap_token(http)
        self.assertEqual(http.request.call_count, 1)


class TestRSW(unittest.TestCase):
    def test_matches_original_formula(self):
        for n in (1, 17, 3233):
            for x in (0, 2, 4000):
                for t in (0, 1, 8, 100):
                    with self.subTest(n=n, x=x, t=t):
                        self.assertEqual(
                            u1s1._solve_rsw({"N": hex(n), "x": hex(x), "t": str(t)}),
                            format(pow(x, 1 << t, n), "x"),
                        )

    def test_rejects_invalid_or_excessive_input_before_work(self):
        base = {"N": "ca1", "x": "2", "t": 10}
        cases = [("t", t) for t in (
            -1, u1s1.RSW_MAX_T + 1, 10**100, "9" * 10000,
            "-1", True, 1.5, None, "1e9",
        )]
        cases += [(key, value) for key in ("N", "x") for value in (
            "f" * (u1s1.RSW_MAX_BITS // 4 + 1), "z", "-1", 17, None,
        )]
        cases.append(("N", "0"))
        for key, value in cases:
            with self.subTest(key=key, value=str(value)[:30]):
                with patch.object(u1s1.time, "monotonic") as clock:
                    with self.assertRaises(ValueError):
                        u1s1._solve_rsw({**base, key: value})
                    clock.assert_not_called()

    def test_max_operand_size(self):
        n = (1 << u1s1.RSW_MAX_BITS) - 1
        self.assertEqual(u1s1._solve_rsw({"N": hex(n), "x": hex(n - 1), "t": 1}), "1")

    def test_max_work_is_accepted_but_deadline_stops_it(self):
        with patch.object(u1s1.time, "monotonic",
                          side_effect=[0, 0, u1s1.RSW_TIMEOUT]):
            with self.assertRaisesRegex(RuntimeError, "RSW"):
                u1s1._solve_rsw({"N": "ca1", "x": "2", "t": u1s1.RSW_MAX_T})

    def test_invalid_challenge_is_not_redeemed(self):
        http = Mock()
        http.request.return_value.json.return_value = {
            "token": SYNTHETIC_TOKEN, "format": 2, "challenges": [
                {"protocol": "rsw", "payload": {"N": "ca1", "x": "2", "t": 10**100}},
            ],
        }
        http.request.return_value.text = "synthetic response"
        http.request.return_value.code = 200
        with self.assertRaises(ValueError):
            u1s1.fetch_cap_token(http)
        self.assertEqual(http.request.call_count, 1)

    def test_valid_challenge_redeems_hex_solution(self):
        http = Mock()
        challenge = response({
            "token": SYNTHETIC_TOKEN, "format": 2, "challenges": [
                {"protocol": "rsw", "payload": {"N": "11", "x": "2", "t": 2}},
            ],
        })
        redeemed = response({"success": True, "token": SYNTHETIC_CAP})
        http.request.side_effect = [challenge, redeemed]
        self.assertEqual(u1s1.fetch_cap_token(http), SYNTHETIC_CAP)
        self.assertEqual(http.request.call_args.kwargs["json_data"]["solutions"],
                         [{"y": "10"}])


if __name__ == "__main__":
    unittest.main()