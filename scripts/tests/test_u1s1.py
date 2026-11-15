"""RSW resource limits and CapCat response handling (no network)."""
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
with patch("common.main_guard"):
    import u1s1


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
        with patch.object(u1s1.time, "monotonic", side_effect=[0, 0, u1s1.RSW_TIMEOUT]):
            with self.assertRaisesRegex(RuntimeError, "RSW"):
                u1s1._solve_rsw({"N": "ca1", "x": "2", "t": u1s1.RSW_MAX_T})

    def test_invalid_challenge_is_not_redeemed(self):
        http = MagicMock()
        http.request.return_value.json.return_value = {
            "token": "synthetic", "format": 2, "challenges": [
                {"protocol": "rsw", "payload": {"N": "ca1", "x": "2", "t": 10**100}},
            ],
        }
        with self.assertRaises(ValueError):
            u1s1.fetch_cap_token(http)
        self.assertEqual(http.request.call_count, 1)

    def test_valid_challenge_redeems_hex_solution(self):
        http = MagicMock()
        response, redeemed = MagicMock(), MagicMock()
        response.json.return_value = {
            "token": "synthetic", "format": 2, "challenges": [
                {"protocol": "rsw", "payload": {"N": "11", "x": "2", "t": 2}},
            ],
        }
        redeemed.json.return_value = {"success": True, "token": "synthetic-cap"}
        http.request.side_effect = [response, redeemed]
        self.assertEqual(u1s1.fetch_cap_token(http), "synthetic-cap")
        self.assertEqual(http.request.call_args.kwargs["json_data"]["solutions"], [{"y": "10"}])
