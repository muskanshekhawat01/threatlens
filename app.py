import ipaddress
import re
from urllib.parse import urlsplit

from flask import Flask, jsonify, render_template, request

from ai_engine import analyze_linguistic_content
from message_analyzer import analyze_message_content, EMAIL_HEADER_PATTERN
from url_analyzer import analyze_url_details, SHORTENERS, MULTIPLE_PROTOCOL_PATTERN, URL_KEYWORD_PATTERN


app = Flask(__name__)

MAX_TEXT_LENGTH = 20_000
URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\]\[{}\"']+")


def _finding(title, detail, weight):
    return {"title": title, "detail": detail, "weight": weight}


def _result(
    findings,
    checked_urls=None,
    scan_type="URL",
    metadata=None,
    ai_analysis=None,
    urls_metadata=None,
):
    score = min(sum(item["weight"] for item in findings), 100)
    level = "high" if score >= 60 else "caution" if score >= 30 else "low"
    risk = "High" if score >= 60 else "Medium" if score >= 30 else "Low"
    advice = (
        "Avoid clicking links or sharing personal information."
        if score >= 60
        else "Be cautious and verify the sender or website independently."
        if score >= 30
        else "A warning sign was detected. Verify unexpected requests independently; a low score does not prove the content is safe."
        if score > 0
        else "No major warning signs were detected by these basic checks."
    )
    res = {
        "score": score,
        "level": level,
        "risk": risk,
        "type": scan_type,
        "reasons": [item["title"] for item in findings],
        "advice": advice,
        "findings": [
            {"title": item["title"], "detail": item["detail"]}
            for item in findings
        ],
        "checked_urls": checked_urls or [],
        "notice": (
            "This is a rule-based risk score, not a calibrated probability. "
            "False positives and false negatives are possible."
        ),
    }
    if metadata is not None:
        res["metadata"] = metadata
    if ai_analysis is not None:
        res["ai_analysis"] = ai_analysis
    if urls_metadata is not None:
        res["urls_metadata"] = urls_metadata
    return res


def analyze_url(value):
    findings, metadata = analyze_url_details(value)
    return _result(
        findings,
        [value],
        scan_type="URL",
        metadata=metadata,
    )


def analyze_text(value, scan_type="Message"):
    return analyze_message_content(value, scan_type=scan_type)


@app.route("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify({
        "status": "healthy",
        "service": "ThreatLens AI Threat Detection Platform",
        "engines": {
            "ml_classifier": "Probabilistic TF-IDF Naive Bayes / Logistic Regression",
            "linguistic_engine": "7-Vector Behavioral Threat Engine",
            "url_engine": "Deep Lexical, DGA Entropy, Typosquatting & IDN Engine",
            "modality_support": ["URL", "Email", "SMS / Smishing", "Social Media", "Auto"]
        },
        "version": "2.0.0"
    })


@app.get("/api/samples")
def samples():
    """Curated realistic security samples for rapid demonstration and testing."""
    return jsonify([
        {
            "id": "paypal-email",
            "category": "email",
            "label": "PayPal Account Suspension Phishing Email",
            "input": (
                "From: service@paypal-security-update.xyz\n"
                "Reply-To: support@fraud-response-ticket.top\n"
                "Subject: Urgent: Your PayPal account has been suspended!\n\n"
                "Dear customer,\n\n"
                "We detected unauthorized access attempts on your account from an unknown IP address. "
                "Immediate action required: your account will be permanently blocked within 24 hours "
                "unless you verify your identity.\n\n"
                "Click here to confirm your credentials and update billing details: "
                "http://paypal.com.account-verification-service.xyz/login\n\n"
                "Do not reply to this email."
            )
        },
        {
            "id": "sunpass-sms",
            "category": "sms",
            "label": "SunPass Unpaid Toll Smishing Lure",
            "input": (
                "SunPass Notice: Our records indicate you have an unpaid toll invoice balance of $12.50. "
                "To avoid an immediate $50.00 late fee and court action, pay now via our portal: "
                "https://sunpass-toll-billing.click/pay?id=84729"
            )
        },
        {
            "id": "crypto-social",
            "category": "social",
            "label": "Social Media Crypto Doubler Scam",
            "input": (
                "CONGRATULATIONS! You have been selected as an exclusive giveaway winner! "
                "Elon Musk and Binance official airdrop: Send 0.1 BTC to claim 0.5 BTC instantly. "
                "Guaranteed return! Contact my mentor on Telegram @elon_airdrop_admin or tap here: "
                "http://192.168.1.55/binance-claim"
            )
        },
        {
            "id": "typosquat-url",
            "category": "url",
            "label": "Typosquatted & High-Risk TLD URL",
            "input": "http://rnicrosoft-verify-security.top/login.php"
        },
        {
            "id": "legitimate-email",
            "category": "email",
            "label": "Legitimate Engineering Newsletter",
            "input": (
                "From: team@github.com\n"
                "Subject: GitHub Release Notes: New features available\n\n"
                "Hello developer,\n\n"
                "Here are the latest release notes and updates to our open source repositories. "
                "You can review the pull request documentation and meeting notes on our main website.\n\n"
                "Best regards,\nThe GitHub Team\n\n"
                "Unsubscribe: https://github.com/settings/notifications"
            )
        }
    ])


@app.post("/api/scan")
def scan():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Send a JSON object with a scan type and input."), 400

    scan_type = payload.get("type", "auto")
    value = payload.get("input")
    if not isinstance(value, str):
        return jsonify(error="Input must be text."), 400
    if not isinstance(scan_type, str):
        return jsonify(error="Scan type must be text."), 400

    scan_type = scan_type.strip().lower()
    if scan_type not in {"url", "text", "message", "email", "sms", "social", "auto"}:
        return jsonify(
            error="Choose a supported scan type: URL, message, email, SMS, or auto."
        ), 400

    try:
        if scan_type == "url":
            result = analyze_url(value)
        else:
            if scan_type in {"text", "auto"}:
                message_type = (
                    "Email" if EMAIL_HEADER_PATTERN.search(value)
                    else "Message / SMS"
                )
            elif scan_type == "email":
                message_type = "Email"
            elif scan_type == "sms":
                message_type = "SMS"
            elif scan_type == "social":
                message_type = "Social Media"
            else:
                message_type = "Message"
            result = analyze_text(value, message_type)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(result)


@app.post("/api/batch")
def batch_scan():
    """Batch scan multiple inputs (URLs or text snippets)."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        return jsonify(error="Provide a JSON object with an 'items' array of inputs."), 400

    items = payload["items"]
    if len(items) == 0:
        return jsonify(error="Items list cannot be empty."), 400
    if len(items) > 20:
        return jsonify(error="Batch limit is 20 items per request."), 400

    results = []
    for item in items:
        if not isinstance(item, dict):
            continue
        text_val = item.get("input", "")
        item_type = item.get("type", "auto").lower()

        if not isinstance(text_val, str) or not text_val.strip():
            continue

        try:
            if item_type == "url":
                res = analyze_url(text_val)
            else:
                target_type = (
                    "Email" if EMAIL_HEADER_PATTERN.search(text_val)
                    else "SMS" if item_type == "sms"
                    else "Social Media" if item_type == "social"
                    else "Message"
                )
                res = analyze_text(text_val, target_type)
            results.append({
                "input": text_val[:100],
                "type": item_type,
                "score": res["score"],
                "risk": res["risk"],
                "reasons": res["reasons"][:3]
            })
        except Exception as e:
            results.append({
                "input": text_val[:100],
                "error": str(e)
            })

    return jsonify({"count": len(results), "results": results})


if __name__ == "__main__":
    app.run(debug=True)
