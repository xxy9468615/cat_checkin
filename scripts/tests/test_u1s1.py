"""Legacy CapCat resource limits; all challenges and HTTP responses are synthetic."""
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
with patch('common.main_guard'):
    import u1s1


class TestLegacyChallenge(unittest.TestCase):
    def test_original_nonce_vectors_and_continuous_index(self):
        self.assertEqual(u1s1.solve_challenge('test', [
            {'c': 2, 's': 16, 'd': 1}, {'c': 2, 's': 8, 'd': 2},
        ]), [2, 3, 400, 279])
        self.assertEqual(u1s1.solve_challenge('test', {'c': '2', 's': '16', 'd': '1'}), [2, 3])

    def test_invalid_dimensions_rejected_before_generation(self):
        for key, values in {'c': [-1, 1025, 10**100, True, 1.5, None, '9'*1000],
                            's': [-1, 4097], 'd': [-1, 65]}.items():
            for value in values:
                with self.subTest(key=key, value=str(value)[:20]):
                    spec = {'c': 1, 's': 16, 'd': 1, key: value}
                    with patch.object(u1s1, '_prng') as generate:
                        with self.assertRaises(RuntimeError):
                            u1s1.solve_challenge('test', spec)
                        generate.assert_not_called()

    def test_aggregate_limits_and_late_invalid_spec(self):
        for specs in ([{'c': 513, 's': 0, 'd': 0}] * 2,
                      [{'c': 129, 's': 4096, 'd': 0}] * 2,
                      [{'c': 0, 's': 0, 'd': 0}] * 1025,
                      [{'c': 1, 's': 1, 'd': 0}, {'c': 1, 's': 4097, 'd': 0}]):
            with patch.object(u1s1, '_prng') as generate:
                with self.assertRaises(RuntimeError):
                    u1s1.solve_challenge('test', specs)
                generate.assert_not_called()

    def test_solution_and_generated_byte_boundaries(self):
        self.assertEqual(len(u1s1.solve_challenge('test', {'c': 1024, 's': 0, 'd': 0})), 1024)
        self.assertEqual(u1s1.solve_challenge('test', {'c': 256, 's': 4096, 'd': 0}), [0]*256)

    def test_deadline_during_generation(self):
        with patch.object(u1s1.time, 'monotonic', side_effect=[0, 0, 121]):
            with self.assertRaisesRegex(RuntimeError, '超时'):
                u1s1._prng('test', 4096, deadline=120)

    def test_immediate_success_still_checks_deadline(self):
        with patch.object(u1s1, '_prng', return_value=''), patch.object(
                u1s1.time, 'monotonic', side_effect=[0, 0, 0, 0, 0, 121]):
            with self.assertRaisesRegex(RuntimeError, '超时'):
                u1s1.solve_challenge('test', {'c': 2, 's': 0, 'd': 0})

    def test_unsuccessful_search_checks_deadline(self):
        with patch.object(u1s1, '_prng', return_value='impossible'), patch.object(
                u1s1.time, 'monotonic', side_effect=[0, 0, 0, 0, 0, 121]):
            with self.assertRaisesRegex(RuntimeError, '超时'):
                u1s1.solve_challenge('test', {'c': 1, 's': 1, 'd': 1})

    def test_rejected_remote_challenge_is_not_redeemed(self):
        http = Mock()
        http.request.return_value.text = "synthetic response"
        http.request.return_value.code = 200
        http.request.return_value.json.return_value = {
            'token': 'synthetic', 'challenge': {'c': 10**20, 's': 1, 'd': 0}}
        with self.assertRaises(RuntimeError):
            u1s1.fetch_cap_token(http)
        self.assertEqual(http.request.call_count, 1)


if __name__ == '__main__':
    unittest.main()
