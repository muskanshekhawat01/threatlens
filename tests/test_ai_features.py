import unittest
import app
from ai_engine import predict_phishing_ml, compute_shannon_entropy, analyze_linguistic_content
from url_analyzer import detect_brand_spoofing, compute_entropy, analyze_url_details
from message_analyzer import parse_email_metadata


class ThreatLensAITests(unittest.TestCase):
    def setUp(self):
        app.app.config.update(TESTING=True)
        self.client = app.app.test_client()

    def test_health_endpoint(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("ml_classifier", data["engines"])

    def test_samples_endpoint(self):
        response = self.client.get("/api/samples")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 3)

    def test_batch_scan_endpoint(self):
        response = self.client.post("/api/batch", json={
            "items": [
                {"input": "https://example.com", "type": "url"},
                {"input": "Urgent: Pay now with gift card: http://192.168.1.1/login", "type": "auto"}
            ]
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["count"], 2)
        self.assertEqual(data["results"][0]["risk"], "Low")
        self.assertIn(data["results"][1]["risk"], ["Medium", "High"])

    def test_ml_phishing_classifier_probabilistic(self):
        scam_text = "Urgent: Your account is suspended! Enter your otp and password immediately to claim prize."
        result = predict_phishing_ml(scam_text)
        self.assertGreaterEqual(result["probability"], 0.70)
        self.assertEqual(result["verdict"], "High Confidence Phishing / Scam")
        self.assertTrue(len(result["top_features"]) > 0)

        benign_text = "Here are the release notes and meeting agenda for our open source project on github."
        result_benign = predict_phishing_ml(benign_text)
        self.assertLess(result_benign["probability"], 0.35)

    def test_typosquatting_visual_substitution(self):
        spoof = detect_brand_spoofing("rnicrosoft.com")
        self.assertIsNotNone(spoof)
        self.assertEqual(spoof["brand"], "microsoft")

        spoof_paypal = detect_brand_spoofing("paypa1-security.com")
        self.assertIsNotNone(spoof_paypal)

    def test_subdomain_brand_spoofing(self):
        spoof = detect_brand_spoofing("paypal.com.account-verification-service.xyz")
        self.assertIsNotNone(spoof)
        self.assertEqual(spoof["brand"], "paypal")

    def test_high_abuse_tld_flagged(self):
        findings, meta = analyze_url_details("https://secure-login.top/account")
        titles = [f["title"] for f in findings]
        self.assertTrue(any("High-risk Top-Level Domain" in t for t in titles))
        self.assertEqual(meta["tld"], "top")
        self.assertEqual(meta["tld_risk"], "high")

    def test_shannon_entropy_calculation(self):
        low_entropy = compute_shannon_entropy("apple.com")
        high_entropy = compute_shannon_entropy("x8q1z9a7w2m4k0.top")
        self.assertGreater(high_entropy, low_entropy)

    def test_email_mismatched_reply_to_detection(self):
        email_text = (
            "From: security@chase.com\n"
            "Reply-To: hacker@external-server.xyz\n"
            "Subject: Security Notice\n\n"
            "Please confirm your account."
        )
        meta = parse_email_metadata(email_text)
        self.assertTrue(meta["mismatched_reply_to"])
        self.assertEqual(meta["sender_domain"], "chase.com")
        self.assertEqual(meta["reply_domain"], "external-server.xyz")

    def test_social_media_crypto_lure_detection(self):
        response = self.client.post("/api/scan", json={
            "type": "social",
            "input": "Elon Musk Binance giveaway! Send 1 ETH get 2 ETH back. Message my mentor on Telegram @crypto_mentor"
        })
        self.assertEqual(response.status_code, 200)
        titles = [f["title"] for f in response.get_json()["findings"]]
        self.assertTrue(any("Crypto" in t for t in titles))


if __name__ == "__main__":
    unittest.main()
