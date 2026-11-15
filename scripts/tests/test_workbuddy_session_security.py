"""Session capability URLs must never enter diagnostics."""
import contextlib
import io
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import workbuddy as wb


class SessionDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.session = {
            "link": "https://synthetic-link.invalid/private-path/acp?key=link-capability",
            "e2bEndpoint": "https://synthetic-endpoint.invalid/endpoint-capability",
            "token": "synthetic-token",
            "sessionId": "synthetic-session",
        }

    def assert_no_secrets(self, text):
        for key in ("link", "e2bEndpoint", "token"):
            self.assertNotIn(self.session[key], text)
        for secret in ("private-path", "link-capability", "endpoint-capability"):
            self.assertNotIn(secret, text)

    def test_dump_redacts_capabilities_and_preserves_input(self):
        original = dict(self.session)
        data = {**self.session, "LiNk": self.session["link"],
                "E2BENDPOINT": self.session["e2bEndpoint"], "accessToken": "fake-access"}
        dumped = json.loads(wb._safe_session_dump(data))
        for key in data:
            self.assertEqual(dumped[key], self.session["sessionId"] if key == "sessionId" else "<redacted>")
        self.assertEqual(self.session, original)

    def test_conversation_diagnostics_and_connection_url(self):
        for debug in (False, True):
            for use_link in (False, True):
                with self.subTest(debug=debug, use_link=use_link):
                    session = dict(self.session)
                    if not use_link:
                        del session["link"]
                    output = io.StringIO()
                    with mock.patch.object(wb, "_DEBUG", debug), \
                         mock.patch.object(wb, "_DEBUG_LINES", []), \
                         mock.patch.object(wb, "_create_conversation", return_value={"id": "conversation"}), \
                         mock.patch.object(wb, "_get_conversation_session", return_value=session), \
                         mock.patch.object(wb, "_acp_connect", return_value=("", None, [])) as connect, \
                         contextlib.redirect_stdout(output):
                        _, ok = wb._run_conversation_and_wait(mock.Mock(), "fake-credential")
                        self.assertFalse(ok)
                        self.assert_no_secrets("\n".join(wb._DEBUG_LINES))
                    expected = session.get("link") or session["e2bEndpoint"] + "/acp"
                    self.assertEqual(connect.call_args.args[1], expected)
                    self.assertEqual(connect.call_args.args[3], self.session["token"])
                    self.assertIn("synthetic-session", output.getvalue())
                    self.assert_no_secrets(output.getvalue())

    def test_transport_exceptions_do_not_log_url(self):
        for debug in (False, True):
            output = io.StringIO()
            http = mock.Mock()
            http.opener.open.side_effect = OSError(self.session["link"])
            with mock.patch.object(wb, "_DEBUG", debug), \
                 mock.patch.object(wb, "_DEBUG_LINES", []), contextlib.redirect_stdout(output):
                self.assertEqual(wb._acp_connect(http, self.session["link"], threading.Event())[0], "")
                self.assertEqual(wb._acp_call(http, self.session["link"], "conn", "initialize", {}, 0), -1)
                self.assert_no_secrets("\n".join(wb._DEBUG_LINES))
                wb._flush_dbg()
            self.assertIn("OSError", output.getvalue())
            self.assert_no_secrets(output.getvalue())


if __name__ == "__main__":
    unittest.main()
