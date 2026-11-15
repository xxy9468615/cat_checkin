"""Regression coverage for bounded remote instrumentation decompression."""
import base64
import importlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
with patch("common.main_guard"):
    u1s1 = importlib.import_module("u1s1")


def blob_for(data):
    compressor = zlib.compressobj(wbits=-15)
    return base64.b64encode(compressor.compress(data) + compressor.flush()).decode()


class TestInstrumentationLimits(unittest.TestCase):
    def test_utf8_and_output_boundary(self):
        for data in ("挑战".encode(), b"x" * u1s1.INSTR_MAX_JS_BYTES):
            with self.subTest(size=len(data)):
                self.assertEqual(u1s1._decode_instr_blob(blob_for(data)), data.decode())

    def test_expansion_bomb_rejected_before_execution(self):
        blob = blob_for(b"x" * (u1s1.INSTR_MAX_JS_BYTES * 8))
        self.assertLess(len(blob), u1s1.INSTR_MAX_ENCODED_CHARS)
        with patch.object(u1s1.shutil, "which", return_value="node"), patch.object(
            u1s1.subprocess, "run"
        ) as run:
            with self.assertRaisesRegex(RuntimeError, "JS 数据过大"):
                u1s1._run_instr(blob)
            run.assert_not_called()

    def test_one_byte_over_output_budget(self):
        with self.assertRaisesRegex(RuntimeError, "JS 数据过大"):
            u1s1._decode_instr_blob(blob_for(b"x" * (u1s1.INSTR_MAX_JS_BYTES + 1)))

    def test_encoded_limit_checked_before_base64(self):
        with patch.object(u1s1.base64, "b64decode") as decode:
            with self.assertRaises(RuntimeError):
                u1s1._decode_instr_blob("A" * (u1s1.INSTR_MAX_ENCODED_CHARS + 1))
            decode.assert_not_called()

    def test_compressed_limit_checked_before_inflation(self):
        # Base64 padding allows two bytes over the compressed budget at this length.
        blob = base64.b64encode(b"x" * (u1s1.INSTR_MAX_COMPRESSED_BYTES + 1)).decode()
        with patch.object(u1s1.zlib, "decompressobj") as inflate:
            with self.assertRaisesRegex(RuntimeError, "压缩数据过大"):
                u1s1._decode_instr_blob(blob)
            inflate.assert_not_called()

    def test_malformed_or_truncated_stream(self):
        valid = base64.b64decode(blob_for(b"valid JS"))
        for data in (b"", valid[:-1], b"\xff"):
            with self.subTest(data=data), self.assertRaises((RuntimeError, zlib.error)):
                u1s1._decode_instr_blob(base64.b64encode(data).decode())

    def test_valid_challenge_reaches_existing_harness(self):
        js = b'''result:{i:"abc123"}; '*');return;}const state=(() => {return 42;})();parent.postMessage({type: 'cap:instr' '''
        result = unittest.mock.Mock(returncode=0, stdout="STATE:42", stderr="")
        with patch.object(u1s1.shutil, "which", return_value="node"), patch.object(
            u1s1.subprocess, "run", return_value=result
        ) as run:
            self.assertEqual(u1s1._run_instr(blob_for(js))["state"], 42)
            run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
