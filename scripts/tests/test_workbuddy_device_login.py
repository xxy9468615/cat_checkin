"""Local login state confidentiality and exchange regression tests."""
import contextlib
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import workbuddy_device_login as login


class LoginStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'private' / 'state.json'
        patch = mock.patch.object(login, 'STATE_FILE', self.path)
        patch.start()
        self.addCleanup(patch.stop)

    def test_private_under_permissive_umask_and_repeated_login(self):
        old = os.umask(0)
        try:
            login._save_state('first')
            login._save_state('second')
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(login._load_state(), 'second')
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_unsafe_directory_and_symlink_rejected(self):
        self.path.parent.mkdir(mode=0o755)
        self.path.parent.chmod(0o755)
        with self.assertRaises(SystemExit):
            login._save_state('secret')
        self.path.parent.rmdir()
        target = Path(self.temp.name) / 'target'
        target.mkdir(mode=0o700)
        self.path.parent.symlink_to(target, target_is_directory=True)
        with self.assertRaises(SystemExit):
            login._save_state('secret')
        self.assertEqual(list(target.iterdir()), [])

    def test_poll_rejects_public_file_and_hardlink(self):
        login._save_state('secret')
        self.path.chmod(0o644)
        with self.assertRaises(SystemExit):
            login._load_state()
        self.path.chmod(0o600)
        os.link(self.path, Path(self.temp.name) / 'copy')
        with self.assertRaises(SystemExit):
            login._load_state()

    def test_symlink_never_read_or_written_through(self):
        login._save_state('first')
        target = Path(self.temp.name) / 'target'
        target.write_text('unchanged')
        self.path.unlink()
        self.path.symlink_to(target)
        with self.assertRaises(OSError):
            login._load_state()
        login._save_state('second')
        self.assertFalse(self.path.is_symlink())
        self.assertEqual(target.read_text(), 'unchanged')
        self.assertEqual(login._load_state(), 'second')

    def test_failed_replace_keeps_old_state_and_cleans_temporary_file(self):
        login._save_state('first')
        with mock.patch.object(login.os, 'replace', side_effect=OSError('failed')):
            with self.assertRaises(OSError):
                login._save_state('second')
        self.assertEqual(login._load_state(), 'first')
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_url_poll_flow_and_cleanup(self):
        http = mock.Mock()
        http.request.return_value.json.side_effect = [
            {'code': 0, 'data': {'state': 'test-state', 'authUrl': 'https://example.test/login'}},
            {'code': 0, 'data': {'accessToken': 'test-access', 'refreshToken': 'test-refresh'}},
            {'data': {'uid': 'test-user'}},
        ]
        with mock.patch.object(login, 'Http', return_value=http), contextlib.redirect_stdout(io.StringIO()):
            login.cmd_url()
            self.assertEqual(login._load_state(), 'test-state')
            login.cmd_poll()
        self.assertEqual(http.request.call_args_list[1].args[1], login.EP_AUTH_TOKEN + 'test-state')
        self.assertFalse(self.path.exists())

    def test_incomplete_login_retains_state(self):
        login._save_state('test-state')
        http = mock.Mock()
        http.request.return_value.json.return_value = {'code': 1}
        with mock.patch.object(login, 'Http', return_value=http), self.assertRaises(SystemExit):
            login.cmd_poll()
        self.assertEqual(login._load_state(), 'test-state')


if __name__ == '__main__':
    unittest.main()
