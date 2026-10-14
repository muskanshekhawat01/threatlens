import unittest

import app


class ThreatLensTests(unittest.TestCase):
    def setUp(self):
        app.app.config.update(TESTING=True)
        self.client = app.app.test_client()

    def test_home_page_renders_scanner(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"Screenshot", response.data)
        self.assertNotIn(b"OCR", response.data)
        self.assertNotIn(b"BUILT FOR A QUICK SECOND LOOK", response.data)
        self.assertIn(b"Message / Email", response.data)
        self.assertIn(b"Scan history", response.data)
        self.assertIn(b"saved only in this browser", response.data)

    def test_url_scan_flags_unencrypted_link(self):
        response = self.client.post(
            "/api/scan",
            json={"type": "url", "input": "http://example.com"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "The URL does not use HTTPS",
            [finding["title"] for finding in response.json["findings"]],
        )
        self.assertEqual(response.json["risk"], "Low")
        self.assertIn("A warning sign was detected", response.json["advice"])

    def test_text_scan_checks_embedded_links(self):
        response = self.client.post(
            "/api/scan",
            json={
                "type": "text",
                "input": "Verify your account immediately: http://192.0.2.10/login",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(response.json["score"], 30)
        self.assertTrue(response.json["checked_urls"])

    def test_message_patterns_cover_rewards_and_verification_lures(self):
        response = self.client.post(
            "/api/scan",
            json={
                "type": "text",
                "input": "Urgent: You are a winner! Claim reward now. Click here to verify your account. Send your password.",
            },
        )
        self.assertEqual(response.status_code, 200)
        titles = {finding["title"] for finding in response.json["findings"]}
        self.assertIn("Suspicious reward or prize", titles)
        self.assertIn("Suspicious verification request", titles)
        self.assertEqual(response.json["risk"], "High")

    def test_auto_scan_detects_email_headers(self):
        response = self.client.post(
            "/api/scan",
            json={
                "input": "From: sender@example.com\nSubject: Urgent\n\nAct now.",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["type"], "Email")
        self.assertIn("Urgent or threatening language", response.json["reasons"])

    def test_explicit_sms_scan_returns_advice_and_result_notice(self):
        response = self.client.post(
            "/api/scan",
            json={"type": "sms", "input": "Urgent: Pay now with a gift card."},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["type"], "SMS")
        self.assertEqual(response.json["risk"], "Medium")
        self.assertTrue(response.json["advice"])
        self.assertIn("rule-based risk score", response.json["notice"])

    def test_message_input_accepts_up_to_twenty_thousand_characters(self):
        response = self.client.post(
            "/api/scan",
            json={"type": "sms", "input": "a" * 20_000},
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.post(
            "/api/scan",
            json={"type": "sms", "input": "a" * 20_001},
        )
        self.assertEqual(response.status_code, 400)

    def test_url_scan_flags_digit_heavy_and_keyword_hostname(self):
        response = self.client.post(
            "/api/scan",
            json={"type": "url", "input": "https://account12345.example.com"},
        )
        self.assertEqual(response.status_code, 200)
        titles = {finding["title"] for finding in response.json["findings"]}
        self.assertIn("The hostname contains many digits", titles)
        self.assertIn("The hostname contains account-related keywords", titles)


    def test_url_scan_flags_at_symbol_ip_and_multiple_hyphens(self):
        response = self.client.post(
            "/api/scan",
            json={
                "type": "url",
                "input": "http://one-two-three-four.example.com@192.0.2.10/login",
            },
        )
        self.assertEqual(response.status_code, 200)
        titles = {finding["title"] for finding in response.json["findings"]}
        self.assertIn("The URL does not use HTTPS", titles)
        self.assertIn("The URL contains an @ symbol", titles)
        self.assertIn("The URL uses an IP address as its hostname", titles)
        self.assertEqual(response.json["risk"], "High")

    def test_clean_url_has_no_warning_score(self):
        response = self.client.post(
            "/api/scan",
            json={"type": "url", "input": "https://example.com"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["score"], 0)
        self.assertEqual(response.json["risk"], "Low")
        self.assertEqual(response.json["findings"], [])

    def test_unknown_scan_type_is_rejected(self):
        response = self.client.post(
            "/api/scan",
            json={"type": "file", "input": "example"},
        )
        self.assertEqual(response.status_code, 400)

    def test_screenshot_scan_routes_are_removed(self):
        for path in ("/api/scan-image", "/api/scan-screenshot"):
            with self.subTest(path=path):
                response = self.client.post(path)
                self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
