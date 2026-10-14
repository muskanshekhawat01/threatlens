import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlsplit

from ai_engine import analyze_linguistic_content, predict_phishing_ml
from url_analyzer import analyze_url_details, detect_brand_spoofing


URL_PATTERN = re.compile(
    r"\b(?:https?://|hxxps?://|www\.)[^\s<>\]\[{}\"']+|"
    r"\b[a-zA-Z0-9-]+\.(?:com|org|net|xyz|top|buzz|work|click|info|co|io|tk|ml|ga|cf|gq|live|shop|me|site)[/\w.-]*",
    re.I,
)

EMAIL_HEADER_PATTERN = re.compile(r"(?im)^(from|to|subject|reply-to):")
SENDER_PATTERN = re.compile(r"(?im)^from:\s*(?:.*?<)?([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))>?")
REPLY_TO_PATTERN = re.compile(r"(?im)^reply-to:\s*(?:.*?<)?([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))>?")
GENERIC_GREETING_PATTERN = re.compile(
    r"(?i)\b(dear (customer|user|client|member|account holder|sir/madam|valued customer)|hello dear)\b"
)
SUSPICIOUS_ATTACHMENT_PATTERN = re.compile(
    r"(?i)\b\w+\.(exe|iso|scr|vbs|zip|rar|cab|bat|cmd|msi|hta|html|shtml)\b"
)

# SMS / Smishing specific lures
SMS_TOLL_PATTERN = re.compile(r"(?i)\b(sunpass|ez-?pass|toll|turnpike|tollway|unpaid toll|traffic violation)\b")
SMS_PACKAGE_PATTERN = re.compile(r"(?i)\b(usps|fedex|ups|dhl|parcel|package|delivery|shipment|redelivery)\b")
SMS_BANK_PATTERN = re.compile(r"(?i)\b(chase|wells fargo|bofa|citi|bank|debit card|locked|fraud alert)\b")

# Social Media scam lures
SOCIAL_CRYPTO_LURE = re.compile(r"(?i)\b(crypto|bitcoin|btc|eth|usdt|doubler|giveaway|airdrop|binance|metamask|100x|pump)\b")
SOCIAL_PIVOT_LURE = re.compile(r"(?i)\b(telegram|whatsapp|dm me|inbox me|contact my mentor|signal group)\b")
SOCIAL_RECOVERY_LURE = re.compile(r"(?i)\b(hacked account|account recovery|recover your account|fix your account|instagram ban)\b")


def _finding(title: str, detail: str, weight: int, category: str = "general") -> Dict[str, Any]:
    return {"title": title, "detail": detail, "weight": weight, "category": category}


def parse_email_metadata(text: str) -> Dict[str, Any]:
    """Extract and analyze email headers and structure."""
    sender_match = SENDER_PATTERN.search(text)
    reply_to_match = REPLY_TO_PATTERN.search(text)
    
    sender_email = sender_match.group(1) if sender_match else None
    sender_domain = sender_match.group(2).lower() if sender_match else None
    
    reply_email = reply_to_match.group(1) if reply_to_match else None
    reply_domain = reply_to_match.group(2).lower() if reply_to_match else None

    mismatched = False
    if sender_domain and reply_domain and sender_domain != reply_domain:
        mismatched = True

    return {
        "is_email": bool(EMAIL_HEADER_PATTERN.search(text)),
        "sender": sender_email,
        "sender_domain": sender_domain,
        "reply_to": reply_email,
        "reply_domain": reply_domain,
        "mismatched_reply_to": mismatched,
        "generic_greeting": bool(GENERIC_GREETING_PATTERN.search(text)),
        "suspicious_attachments": SUSPICIOUS_ATTACHMENT_PATTERN.findall(text),
    }


def analyze_message_content(
    text: str,
    scan_type: str = "Message",
) -> Dict[str, Any]:
    """
    Comprehensive analysis of message text across AI models, linguistic threat vectors,
    channel-specific spoofing cues (Email, SMS, Social Media), and embedded URLs.
    """
    text = text.strip()
    if not text:
        raise ValueError("Enter message text to scan.")
    if len(text) > 20_000:
        raise ValueError("Text must be 20,000 characters or fewer.")

    findings = []
    
    # 1. AI Linguistic & Stylometric Analysis
    ai_results = analyze_linguistic_content(text)
    for signal in ai_results["findings"]:
        findings.append(_finding(
            signal["title"],
            signal["detail"],
            signal["weight"],
            category="linguistic"
        ))

    # Backward compatibility mappings for core tests
    # Ensure specific titles expected by legacy tests are represented
    cat_scores = ai_results["category_scores"]
    legacy_titles = {f["title"] for f in findings}

    if "urgency" in cat_scores and "Urgent or threatening language" not in legacy_titles:
        findings.append(_finding(
            "Urgent or threatening language",
            "The message uses urgency or threatens an account restriction.",
            20,
            category="linguistic"
        ))
    if "credentials" in cat_scores and "Requests for sensitive information" not in legacy_titles:
        findings.append(_finding(
            "Requests for sensitive information",
            "The message mentions credentials or sensitive financial information.",
            25,
            category="linguistic"
        ))
    if "financial" in cat_scores and "Financial pressure" not in legacy_titles:
        findings.append(_finding(
            "Financial pressure",
            "The message applies pressure around a payment, transfer, or refund.",
            25,
            category="linguistic"
        ))
    if "lures_and_greed" in cat_scores and "Suspicious reward or prize" not in legacy_titles:
        findings.append(_finding(
            "Suspicious reward or prize",
            "The message uses reward or prize wording commonly found in lures.",
            20,
            category="linguistic"
        ))
    if "verification_call_to_action" in cat_scores and "Suspicious verification request" not in legacy_titles:
        findings.append(_finding(
            "Suspicious verification request",
            "The message asks you to verify an account or identity, or to click through.",
            10,
            category="linguistic"
        ))

    # 2. Channel Specific Checks
    # Email checks
    email_meta = parse_email_metadata(text)
    if email_meta["is_email"] or scan_type == "Email":
        if email_meta["mismatched_reply_to"]:
            findings.append(_finding(
                "Mismatched Sender and Reply-To Addresses",
                f"The message claims to be from '{email_meta['sender_domain']}', but responses are directed to '{email_meta['reply_domain']}'. This is a prominent email spoofing tactic.",
                30,
                category="email_spoofing"
            ))
        if email_meta["generic_greeting"]:
            findings.append(_finding(
                "Impersonal or Generic Greeting",
                "Phishing campaigns often use generic greetings like 'Dear customer' or 'Dear account holder' rather than your name.",
                10,
                category="email_spoofing"
            ))
        if email_meta["suspicious_attachments"]:
            findings.append(_finding(
                "Mentions of High-Risk Attachments",
                f"The email references potentially hazardous executable or archive attachments: {', '.join(set(email_meta['suspicious_attachments']))}.",
                25,
                category="email_spoofing"
            ))

    # SMS / Smishing checks
    if scan_type in {"SMS", "Message / SMS", "Message"}:
        if SMS_TOLL_PATTERN.search(text) and ("fee" in text.lower() or "pay" in text.lower() or "link" in text.lower() or "http" in text.lower()):
            findings.append(_finding(
                "Smishing: Fake Toll Violation / SunPass Scam Lure",
                "Matches known SMS phishing campaigns impersonating toll services (e.g., SunPass, EZ-Pass) demanding immediate payment for unpaid tolls.",
                25,
                category="smishing"
            ))
        if SMS_PACKAGE_PATTERN.search(text) and ("address" in text.lower() or "fee" in text.lower() or "reschedule" in text.lower() or "click" in text.lower() or "http" in text.lower()):
            findings.append(_finding(
                "Smishing: Fake Package Delivery Redelivery Scam",
                "Matches SMS postal phishing lures impersonating USPS, FedEx, or DHL alleging an incomplete delivery address or customs fee.",
                25,
                category="smishing"
            ))
        if SMS_BANK_PATTERN.search(text) and ("blocked" in text.lower() or "locked" in text.lower() or "verify" in text.lower()):
            findings.append(_finding(
                "Smishing: Fake Bank Debit Card Lock Alert",
                "Matches fraudulent SMS alerts impersonating financial institutions claiming card suspension to steal online banking logins.",
                30,
                category="smishing"
            ))

    # Social Media scam checks
    if scan_type in {"Social Media", "Social", "Message"}:
        if SOCIAL_CRYPTO_LURE.search(text) and SOCIAL_PIVOT_LURE.search(text):
            findings.append(_finding(
                "Social Media Crypto / Investment Scam",
                "Combines cryptocurrency promotion with redirection to unmonitored channels (e.g. Telegram / WhatsApp groups), a classic trading scam pattern.",
                25,
                category="social_media"
            ))
        if SOCIAL_RECOVERY_LURE.search(text):
            findings.append(_finding(
                "Account Recovery / Password Reset Scam",
                "Solicits victims of account lockouts or bans, falsely promising unauthorized account recovery for a fee.",
                25,
                category="social_media"
            ))

    # 3. URL Extraction and Deep Inspection
    urls = []
    for match in URL_PATTERN.finditer(text):
        candidate = match.group(0).rstrip(".,;:!?")
        # Defanging check
        candidate = re.sub(r"(?i)^hxxp(s?)://", r"http\1://", candidate)
        candidate = re.sub(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)", ".", candidate, flags=re.I)
        if candidate not in urls:
            urls.append(candidate)

    if urls:
        findings.append(_finding(
            "The message contains a URL",
            "Unexpected links can lead to deceptive or harmful websites.",
            0,
            category="url"
        ))

    url_findings = []
    analyzed_urls_metadata = []
    suspicious_url_found = False

    for url in urls[:5]:
        try:
            url_details, url_meta = analyze_url_details(url)
            analyzed_urls_metadata.append(url_meta)
            url_score = min(sum(item["weight"] for item in url_details), 100)
            
            for item in url_details:
                url_findings.append(_finding(
                    f"Link: {item['title']}",
                    f"{url} — {item['detail']}",
                    0,
                    category="url_detail"
                ))

            if url_score >= 30:
                suspicious_url_found = True
        except ValueError:
            continue

    if suspicious_url_found:
        findings.append(_finding(
            "The included URL has suspicious characteristics",
            "At least one link in the message triggered multiple URL warning checks.",
            15,
            category="url"
        ))

    findings.extend(url_findings)

    # 4. Final Aggregation and Scoring
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

    return {
        "score": score,
        "level": level,
        "risk": risk,
        "type": scan_type,
        "reasons": [item["title"] for item in findings],
        "advice": advice,
        "findings": [
            {"title": item["title"], "detail": item["detail"], "category": item.get("category", "general")}
            for item in findings
        ],
        "checked_urls": urls[:5],
        "urls_metadata": analyzed_urls_metadata,
        "ai_analysis": {
            "ml_probability": ai_results["ml"]["probability"],
            "ml_verdict": ai_results["ml"]["verdict"],
            "ml_percentage": ai_results["ml"]["percentage"],
            "top_features": ai_results["ml"]["top_features"],
            "matched_phrases": ai_results["matched_phrases"],
            "stylometrics": ai_results["stylometrics"],
            "categories": ai_results["category_scores"],
        },
        "email_metadata": email_meta if email_meta["is_email"] or scan_type == "Email" else None,
        "notice": (
            "This is a rule-based risk score, not a calibrated probability. "
            "False positives and false negatives are possible."
        ),
    }
