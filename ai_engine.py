import math
import re
from typing import Dict, List, Tuple, Any


# Extensive linguistic pattern categories
LINGUISTIC_CATEGORIES = {
    "urgency": {
        "name": "Urgent or threatening language",
        "description": "The message uses urgency or threatens an account restriction.",
        "weight": 20,
        "patterns": [
            r"\b(urgent|act now|immediately|account suspended|suspended|blocked|expire|final warning)\b",
            r"\b(immediate action|respond immediately|account locked|24 hours|48 hours|final courtesy notice|last chance)\b",
            r"\b(expiring soon|action required|critical alert|security notice|unauthorized access|security breach)\b",
        ],
    },
    "credentials": {
        "name": "Requests for sensitive information",
        "description": "The message mentions credentials or sensitive financial information.",
        "weight": 25,
        "patterns": [
            r"\b(password|otp|pin|bank details|cvv|passcode|login details)\b",
            r"\b(passphrase|security code|one-time password|verification code|2fa code|mfa code|auth code)\b",
            r"\b(cvc|card number|social security|ssn|national insurance|tax id|login credentials|seed phrase|private key)\b",
        ],
    },
    "financial": {
        "name": "Financial pressure",
        "description": "The message applies pressure around a payment, transfer, or refund.",
        "weight": 25,
        "patterns": [
            r"\b(send money|payment required|pay now|transfer money|refund|gift card|bank transfer)\b",
            r"\b(wire transfer|western union|moneygram|cashapp|venmo transfer|bitcoin|btc|ethereum|eth|crypto wallet|cryptocurrency payment|usdt)\b",
            r"\b(refund pending|claim refund|processing fee|tax due|overdue fee|toll fee|unpaid toll|ezpass|sunpass|invoice attached)\b",
        ],
    },
    "lures_and_greed": {
        "name": "Suspicious reward or prize",
        "description": "The message uses reward or prize wording commonly found in lures.",
        "weight": 20,
        "patterns": [
            r"\b(you have won|winner|prize|lottery|claim your reward|claim reward|free gift)\b",
            r"\b(jackpot|sweepstakes|prize notification|claim prize|exclusive reward|cash grant|unclaimed funds|inheritance|beneficiary)\b",
            r"\b(giveaway|airdrop|guaranteed return|100x profit|selected as winner|congratulations you won)\b",
        ],
    },
    "verification_call_to_action": {
        "name": "Suspicious verification request",
        "description": "The message asks you to verify an account or identity, or to click through.",
        "weight": 10,
        "patterns": [
            r"\b(verify your account|confirm your identity|click here|tap here|open this link|verify now)\b",
            r"\b(validate your account|follow this link|update your profile|reactivate your account|restore access)\b",
            r"\b(review document|sign document|docusign document|download attachment|click below|use the link below)\b",
        ],
    },
    "authority_impersonation": {
        "name": "Authority & Brand Impersonation",
        "description": "Spoofs well-known organizations, tech platforms, government bodies, or financial institutions.",
        "weight": 22,
        "patterns": [
            r"\b(microsoft security team|apple support|google security alert)\b",
            r"\b(paypal fraud department|chase fraud alert|wells fargo security)\b",
            r"\b(usps delivery failure|fedex shipment notice|dhl customs clearance)\b",
            r"\b(internal revenue service|irs notice|department of revenue|law enforcement)\b",
            r"\b(meta security|instagram verification badge|whatsapp support team)\b",
            r"\b(geek squad|norton antivirus renewal|mcafee security subscription)\b",
        ],
    },
    "extortion_fear": {
        "name": "Blackmail & Fear-Based Extortion",
        "description": "Claims infection by spyware, recording webcam footage, or threatening public humiliation.",
        "weight": 30,
        "patterns": [
            r"\b(i know your password|recorded you through your webcam|recorded video of you)\b",
            r"\b(compromised your device|pegasus spyware installed|trojan installed)\b",
            r"\b(send bitcoin or i will send|blackmail|ruin your reputation)\b",
            r"\b(warrant issued for your arrest|police warrant|court summons pending)\b",
        ],
    },
}

# Compiled regex cache
COMPILED_CATEGORIES = {
    cat_key: {
        "name": cat_info["name"],
        "description": cat_info["description"],
        "weight": cat_info["weight"],
        "compiled": [re.compile(p, re.I) for p in cat_info["patterns"]],
    }
    for cat_key, cat_info in LINGUISTIC_CATEGORIES.items()
}

# Pre-calibrated ML Phishing/Scam Vocabulary and Log-Odds Weights
# Positive weights increase phishing probability; negative weights indicate benign context.
ML_VOCABULARY_WEIGHTS: Dict[str, float] = {
    # High-risk Phishing & Scam tokens
    "suspended": 2.4, "immediately": 2.2, "urgent": 2.1, "verify": 1.9,
    "otp": 2.6, "password": 2.3, "cvv": 2.8, "ssn": 2.9, "pin": 2.0,
    "claim": 1.8, "winner": 2.5, "lottery": 2.7, "gift card": 3.0,
    "bitcoin": 2.4, "btc": 2.2, "crypto": 2.0, "wallet": 1.7,
    "login": 1.5, "click here": 2.4, "tap here": 2.2, "confirm identity": 2.3,
    "security alert": 2.0, "unauthorized": 2.1, "blocked": 1.8, "wire transfer": 2.6,
    "sunpass": 3.2, "ezpass": 3.2, "unpaid toll": 3.4, "overdue toll": 3.4,
    "delivery failed": 2.3, "reschedule delivery": 2.4, "redelivery": 2.5,
    "dhl package": 2.1, "usps tracking": 2.0, "fedex parcel": 2.1,
    "geek squad": 3.1, "norton renewal": 3.0, "mcafee subscription": 2.9,
    "invoice attached": 2.2, "receipt attached": 1.9, "refund of": 2.0,
    "final notice": 2.4, "courtesy notice": 2.3, "warrant": 2.7,
    "seed phrase": 3.5, "private key": 3.2, "metamask": 2.5,
    "airdrop": 2.6, "giveaway": 2.2, "double your": 2.8,
    "act now": 2.2, "account locked": 2.4, "restricted access": 2.3,
    "compromised": 2.1, "reactivate": 2.0, "validate": 1.8,
    "billing details": 2.2, "payment method": 1.6, "credit card": 1.7,
    "banking": 1.5, "western union": 2.8, "moneygram": 2.8,
    "webcam": 2.9, "blackmail": 3.1, "extortion": 3.1, "trojan": 2.4,
    "pegasus": 2.8, "recorded you": 3.0,

    # Benign / Neutral indicator tokens
    "unsubscribe": -1.8, "privacy policy": -2.0, "terms of service": -1.9,
    "newsletter": -2.2, "receipt": -0.8, "meeting notes": -2.5,
    "agenda": -2.4, "quarterly report": -2.6, "github": -1.5,
    "documentation": -2.2, "open source": -2.4, "release notes": -2.3,
    "all rights reserved": -1.7, "preferences": -1.6, "forwarded message": -1.0,
    "pull request": -2.8, "commit": -2.5, "discussion": -2.0,
}


def compute_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy for text randomness."""
    if not text:
        return 0.0
    text_clean = text.strip()
    probabilities = [float(text_clean.count(c)) / len(text_clean) for c in set(text_clean)]
    return -sum(p * math.log2(p) for p in probabilities if p > 0)


def extract_linguistic_signals(text: str) -> Tuple[List[Dict[str, Any]], Dict[str, int], List[str]]:
    """Scan text across linguistic categories and extract structured findings and matched spans."""
    findings = []
    category_scores = {}
    matched_phrases = []

    for cat_key, cat_data in COMPILED_CATEGORIES.items():
        cat_matches = []
        for pattern in cat_data["compiled"]:
            for match in pattern.finditer(text):
                phrase = match.group(0)
                if phrase not in cat_matches:
                    cat_matches.append(phrase)
                if phrase not in matched_phrases:
                    matched_phrases.append(phrase)

        if cat_matches:
            category_scores[cat_key] = cat_data["weight"]
            examples = ", ".join(f"'{m}'" for m in cat_matches[:3])
            findings.append({
                "category": cat_key,
                "title": cat_data["name"],
                "detail": f"{cat_data['description']} Detected phrasing: {examples}.",
                "weight": cat_data["weight"],
                "matches": cat_matches[:5],
            })

    return findings, category_scores, matched_phrases


def compute_stylometrics(text: str) -> Dict[str, Any]:
    """Analyze stylometric anomalies: SHOUTING, punctuation bursts, and entropy."""
    length = len(text)
    if length == 0:
        return {"upper_ratio": 0.0, "punct_bursts": 0, "entropy": 0.0, "anomalous": False}

    alpha_chars = [c for c in text if c.isalpha()]
    upper_chars = [c for c in alpha_chars if c.isupper()]
    upper_ratio = (len(upper_chars) / len(alpha_chars)) if alpha_chars else 0.0

    punct_bursts = len(re.findall(r"[!?$]{2,}", text))
    entropy = round(compute_shannon_entropy(text), 2)

    anomalous = (upper_ratio > 0.45 and len(alpha_chars) > 20) or (punct_bursts >= 3)
    return {
        "upper_ratio": round(upper_ratio, 3),
        "punct_bursts": punct_bursts,
        "entropy": entropy,
        "anomalous": anomalous,
    }


def predict_phishing_ml(text: str) -> Dict[str, Any]:
    """
    Lightweight, deterministic Probabilistic ML Classifier.
    Computes TF-IDF-weighted log-odds score against pre-calibrated security corpus.
    Outputs a calibrated probability in [0.0, 1.0], classification label, and feature importance.
    """
    text_lower = text.lower()
    words = re.findall(r"\b[a-z0-9'-]+\b", text_lower)
    word_count = max(len(words), 1)

    # Base prior log-odds for general incoming messages (slight benign bias prior)
    base_log_odds = -1.2
    active_features = []

    # Check unigrams and bigrams
    checked_tokens = set()
    for token, weight in ML_VOCABULARY_WEIGHTS.items():
        if " " in token:
            # Bigram match
            if token in text_lower:
                freq = text_lower.count(token)
                tfidf_proxy = math.log1p(freq) * (1.0 + math.log(100.0 / (word_count + 1)))
                impact = weight * min(tfidf_proxy, 3.0)
                base_log_odds += impact
                active_features.append({
                    "token": token,
                    "weight": round(impact, 2),
                    "sentiment": "Phishing Signal" if weight > 0 else "Benign Indicator"
                })
        else:
            # Unigram match
            freq = words.count(token)
            if freq > 0:
                tfidf_proxy = math.log1p(freq) * (1.0 + math.log(100.0 / (word_count + 1)))
                impact = weight * min(tfidf_proxy, 3.0)
                base_log_odds += impact
                active_features.append({
                    "token": token,
                    "weight": round(impact, 2),
                    "sentiment": "Phishing Signal" if weight > 0 else "Benign Indicator"
                })

    # Convert log-odds to calibrated sigmoid probability
    # sigmoid(z) = 1 / (1 + exp(-z))
    # Clip z to avoid overflow
    bounded_log_odds = max(min(base_log_odds, 12.0), -12.0)
    probability = 1.0 / (1.0 + math.exp(-bounded_log_odds))

    # Sort top features by absolute magnitude
    active_features.sort(key=lambda x: abs(x["weight"]), reverse=True)

    if probability >= 0.75:
        verdict = "High Confidence Phishing / Scam"
    elif probability >= 0.50:
        verdict = "Suspicious"
    elif probability >= 0.25:
        verdict = "Low Risk / Informational"
    else:
        verdict = "Likely Benign"

    return {
        "probability": round(probability, 4),
        "percentage": round(probability * 100, 1),
        "verdict": verdict,
        "log_odds": round(base_log_odds, 2),
        "top_features": active_features[:8],
    }


def analyze_linguistic_content(text: str) -> Dict[str, Any]:
    """Complete AI and linguistic analysis orchestration."""
    findings, category_scores, matched_phrases = extract_linguistic_signals(text)
    stylometrics = compute_stylometrics(text)
    ml_result = predict_phishing_ml(text)

    # Stylometric finding if anomalous
    if stylometrics["anomalous"]:
        if stylometrics["upper_ratio"] > 0.45:
            findings.append({
                "category": "stylometrics",
                "title": "Abnormal Capitalization (Shouting)",
                "detail": f"{int(stylometrics['upper_ratio'] * 100)}% of characters are uppercase, a recognized sign of urgent psychological coercion.",
                "weight": 10,
                "matches": [],
            })
        if stylometrics["punct_bursts"] >= 3:
            findings.append({
                "category": "stylometrics",
                "title": "Aggressive Punctuation Bursts",
                "detail": "Multiple repetitive punctuation marks (e.g., '!!!', '???') used to simulate emergency.",
                "weight": 8,
                "matches": [],
            })

    # Combine linguistic weights into aggregated score (capped at 100)
    total_linguistic_weight = sum(item["weight"] for item in findings)
    
    # Blended AI linguistic score factoring ML probability
    ml_scaled = ml_result["percentage"]
    blended_score = min(int(round(0.6 * total_linguistic_weight + 0.4 * ml_scaled)), 100)

    return {
        "findings": findings,
        "category_scores": category_scores,
        "matched_phrases": matched_phrases,
        "stylometrics": stylometrics,
        "ml": ml_result,
        "linguistic_score": min(total_linguistic_weight, 100),
        "blended_ai_score": blended_score,
    }
