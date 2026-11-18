"""Unit tests for the URL red-flag checker (standard library only).

Run from the repository root:  python -m unittest discover tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "task2_phishing_awareness"))
from phishing_training import analyze_url  # noqa: E402


def real_flags(url):
    """Warnings other than the generic 'not HTTPS' note."""
    return [f for f in analyze_url(url) if not f.startswith("Not using HTTPS")]


class AnalyzeUrlTests(unittest.TestCase):
    def test_suspicious_urls_are_flagged(self):
        for url in [
            "http://paypal.com.verify-login.net/secure",
            "http://paypa1-alerts.com/x",
            "https://micros0ft-support.com",
            "https://amaz0n.com",
            "https://faceb00k-login.net",
            "http://192.168.4.7/paypal",
        ]:
            with self.subTest(url=url):
                self.assertTrue(real_flags(url))

    def test_legitimate_urls_are_not_flagged(self):
        for url in [
            "https://www.paypal.com/signin",
            "https://accounts.google.com",
            "https://github.com/anthropics",
            "https://www.python.org/downloads",
        ]:
            with self.subTest(url=url):
                self.assertEqual(real_flags(url), [])


if __name__ == "__main__":
    unittest.main()
