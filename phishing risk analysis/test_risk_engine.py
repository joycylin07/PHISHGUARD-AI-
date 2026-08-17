"""
test_risk_engine.py
---------------------------------------------------------------
Basic sanity tests for risk_engine.py.

Run:
    python -m unittest test_risk_engine.py -v
"""

import unittest

from risk_engine import analyze_url, classify_risk_level


class TestRiskLevelClassification(unittest.TestCase):
    def test_low_boundary(self):
        self.assertEqual(classify_risk_level(0), "LOW")
        self.assertEqual(classify_risk_level(30), "LOW")

    def test_medium_boundary(self):
        self.assertEqual(classify_risk_level(31), "MEDIUM")
        self.assertEqual(classify_risk_level(70), "MEDIUM")

    def test_high_boundary(self):
        self.assertEqual(classify_risk_level(71), "HIGH")
        self.assertEqual(classify_risk_level(100), "HIGH")


class TestAnalyzeUrl(unittest.TestCase):
    def test_benign_url_is_low_risk(self):
        report = analyze_url("https://www.wikipedia.org/wiki/Phishing")
        self.assertEqual(report.risk_level, "LOW")
        self.assertEqual(report.risk_factors, [])

    def test_suspicious_url_flags_keywords(self):
        report = analyze_url("http://verify-account-login.example-xyz.top/confirm")
        labels = " ".join(f.label for f in report.risk_factors)
        self.assertIn("Suspicious keyword", labels)
        self.assertGreater(report.fingerprint["Suspicious Terms"], 0)

    def test_ip_host_flagged(self):
        report = analyze_url("http://192.168.1.1/login")
        labels = " ".join(f.label for f in report.risk_factors)
        self.assertIn("raw IP address", labels)

    def test_at_symbol_obfuscation_flagged(self):
        report = analyze_url("http://user@fake-bank.com/login")
        labels = " ".join(f.label for f in report.risk_factors)
        self.assertIn("@", labels)

    def test_ml_probability_overrides_overall_risk(self):
        report = analyze_url("https://www.wikipedia.org/wiki/Phishing", ml_probability=0.95)
        self.assertEqual(report.overall_risk, 95.0)
        self.assertEqual(report.risk_level, "HIGH")
        self.assertEqual(report.source, "ml+heuristic")

    def test_invalid_probability_raises(self):
        with self.assertRaises(ValueError):
            analyze_url("https://example.com", ml_probability=1.5)

    def test_empty_url_raises(self):
        with self.assertRaises(ValueError):
            analyze_url("")

    def test_fingerprint_keys_present(self):
        report = analyze_url("http://secure-login-paypal.com.verify.xyz/signin")
        for key in ["URL Structure", "Domain Anomaly", "Suspicious Terms", "Obfuscation", "Overall Risk"]:
            self.assertIn(key, report.fingerprint)


if __name__ == "__main__":
    unittest.main()
