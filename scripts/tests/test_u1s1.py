"""CapCat protocol regression tests; all responses and credentials are synthetic."""
import base64
import importlib.util
from pathlib import Path
import sys
import tempfile
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


def response(data, code=200):
    return Mock(code=code, text="synthetic response", json=Mock(return_value=data))


class TestCapToken(unittest.TestCase):
    def test_instrumentation_rejected_without_execution_or_redeem(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "executed"
            # Fits the old extraction markers and writes a file if run by Node.
            js = ("'*');return;}"
                  f"require('fs').writeFileSync({str(marker)!r}, 'executed');"
                  "return state;})();"
                  "parent.postMessage({type: 'cap:instr',result:{i:\"abcdef\"}})")
            compressor = zlib.compressobj(wbits=-15)
            blob = base64.b64encode(compressor.compress(js.encode()) + compressor.flush()).decode()
            for payload in ({"blob": blob}, {}, {"blob": "invalid encoding"}):
                with self.subTest(payload=payload):
                    h = Mock()
                    h.request.return_value = response({
                        "token": "synthetic", "format": 2,
                        "challenges": [{"protocol": "instrumentation", "payload": payload}],
                    })
                    with patch("subprocess.run") as execute:
                        with self.assertRaisesRegex(RuntimeError, "instrumentation"):
                            u1s1.fetch_cap_token(h)
                        execute.assert_not_called()
                    self.assertFalse(marker.exists())
                    self.assertEqual(h.request.call_count, 1)

    def test_supported_format_two_redeems_local_solutions(self):
        h = Mock()
        h.request.side_effect = [response({
            "token": "synthetic", "format": 2, "challenges": [
                {"protocol": "rsw", "payload": {"N": "11", "x": "2", "t": 3}},
                {"protocol": "sha256-pow", "payload": {"salt": "test", "target": ""}},
            ],
        }), response({"success": True, "token": "synthetic-cap"})]
        self.assertEqual(u1s1.fetch_cap_token(h), "synthetic-cap")
        self.assertEqual(h.request.call_args.kwargs["json_data"], {
            "token": "synthetic", "solutions": [{"y": "1"}, {"nonce": 0}],
        })

    def test_legacy_format_redeems_local_solutions(self):
        h = Mock()
        h.request.side_effect = [
            response({"token": "synthetic", "challenge": {"c": 1, "s": 4, "d": 0}}),
            response({"success": True, "token": "synthetic-cap"}),
        ]
        self.assertEqual(u1s1.fetch_cap_token(h), "synthetic-cap")
        self.assertEqual(h.request.call_args.kwargs["json_data"]["solutions"], [0])

    def test_rejected_challenge_preserves_direct_claim_fallback(self):
        h = Mock()
        h.request.side_effect = [
            response({"token": "synthetic", "format": 2, "challenges": [
                {"protocol": "instrumentation", "payload": {}},
            ]}),
            response({"error": "captcha required"}, code=400),
        ]
        ok, _ = u1s1.run_account(1, 1, "synthetic-session", h)
        self.assertFalse(ok)
        self.assertEqual(h.request.call_count, 2)
        self.assertEqual(h.request.call_args.args[1],
                         "https://u1s1.io/api/packages/login-checkin/claim")
        self.assertEqual(h.request.call_args.kwargs["json_data"], {})


if __name__ == "__main__":
    unittest.main()
