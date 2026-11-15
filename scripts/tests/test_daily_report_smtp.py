"""SMTP must verify the peer before releasing credentials or report contents."""
import os
from pathlib import Path
import smtplib
import ssl
import sys
import unittest
from unittest.mock import call, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import daily_report


class TestSmtpTls(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {
            "MAIL_HOST": "smtp.example.test", "MAIL_USER": "sender@example.test",
            "MAIL_PASS": "synthetic-password", "MAIL_PORT": "465", "MAIL_SSL": "",
        }, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.html = patch.object(daily_report, "build_email_html", return_value="<p>report</p>")
        self.html.start()
        self.addCleanup(self.html.stop)

    def assert_verified(self, context):
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def send(self):
        return daily_report.send_email("subject", "sensitive report", [])

    @patch.object(daily_report.smtplib, "SMTP")
    @patch.object(daily_report.smtplib, "SMTP_SSL")
    def test_implicit_tls(self, smtp_ssl, smtp):
        self.assertTrue(self.send())
        smtp.assert_not_called()
        self.assert_verified(smtp_ssl.call_args.kwargs["context"])
        smtp_ssl.assert_called_once_with("smtp.example.test", 465, timeout=60,
                                         context=smtp_ssl.call_args.kwargs["context"])
        server = smtp_ssl.return_value
        server.login.assert_called_once()
        server.sendmail.assert_called_once()

    def test_starttls_on_every_non_ssl_port(self):
        for port in (25, 587, 2525, 465):
            with self.subTest(port=port), patch.dict(os.environ, {
                "MAIL_PORT": str(port), "MAIL_SSL": "false",
            }), patch.object(daily_report.smtplib, "SMTP") as smtp:
                self.assertTrue(self.send())
                server = smtp.return_value
                context = server.starttls.call_args.kwargs["context"]
                self.assert_verified(context)
                self.assertEqual(server.method_calls[:4], [
                    call.ehlo(), call.starttls(context=context), call.ehlo(),
                    call.login("sender@example.test", "synthetic-password"),
                ])
                server.sendmail.assert_called_once()

    def test_failed_upgrade_never_releases_sensitive_data(self):
        for error in (ssl.SSLCertVerificationError("untrusted or mismatched certificate"),
                      smtplib.SMTPNotSupportedError("STARTTLS unavailable"),
                      smtplib.SMTPResponseException(454, b"TLS unavailable")):
            with self.subTest(error=error), patch.dict(os.environ, {"MAIL_PORT": "2525"}), \
                    patch.object(daily_report.smtplib, "SMTP") as smtp:
                server = smtp.return_value
                server.starttls.side_effect = error
                self.assertFalse(self.send())
                server.login.assert_not_called()
                server.sendmail.assert_not_called()
                server.__exit__.assert_called_once()

    @patch.object(daily_report.smtplib, "SMTP")
    @patch.object(daily_report.smtplib, "SMTP_SSL")
    def test_failed_implicit_tls_never_falls_back(self, smtp_ssl, smtp):
        smtp_ssl.side_effect = ssl.SSLCertVerificationError("untrusted certificate")
        self.assertFalse(self.send())
        self.assert_verified(smtp_ssl.call_args.kwargs["context"])
        smtp_ssl.return_value.login.assert_not_called()
        smtp_ssl.return_value.sendmail.assert_not_called()
        smtp.assert_not_called()


if __name__ == "__main__":
    unittest.main()
