import json
import math
import os
import re
from typing import Dict, List, Tuple, Any, Optional

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
INTEL_FILE = os.path.join(DATA_DIR, "threat_intelligence.json")
CORPUS_FILE = os.path.join(DATA_DIR, "training_corpus.json")


class ThreatIntelManager:
    """Dynamically loads and hot-reloads threat intelligence rules from external feeds."""
    
    def __init__(self, intel_path: str = INTEL_FILE):
        self.intel_path = intel_path
        self.categories: Dict[str, Any] = {}
        self.compiled_categories: Dict[str, Any] = {}
        self.targeted_brands: Dict[str, str] = {}
        self.high_abuse_tlds: Dict[str, str] = {}
        self.shorteners: set = set()
        self.homoglyphs: Dict[str, str] = {}
        self.channel_rules: Dict[str, Any] = {}
        self.email_indicators: Dict[str, Any] = {}
        self.account_keywords_pattern: Optional[re.Pattern] = None
        self.reload()

    def reload(self):
        if not os.path.exists(self.intel_path):
            raise FileNotFoundError(f"Threat intelligence file not found at {self.intel_path}")
        
        with open(self.intel_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.categories.clear()
        self.categories.update(data.get("linguistic_categories", {}))

        self.targeted_brands.clear()
        self.targeted_brands.update(data.get("targeted_brands", {}))

        self.high_abuse_tlds.clear()
        self.high_abuse_tlds.update(data.get("high_abuse_tlds", {}))

        self.shorteners.clear()
        self.shorteners.update(data.get("shorteners", []))

        self.homoglyphs.clear()
        self.homoglyphs.update(data.get("homoglyphs", {}))

        keywords = data.get("account_keywords", [])
        if keywords:
            self.account_keywords_pattern = re.compile(f"({'|'.join(keywords)})", re.I)

        # Dynamically compile regular expressions for linguistic categories
        self.compiled_categories.clear()
        for cat_key, cat_data in self.categories.items():
            self.compiled_categories[cat_key] = {
                "name": cat_data["name"],
                "description": cat_data["description"],
                "weight": cat_data["weight"],
                "compiled": [re.compile(p, re.I) for p in cat_data.get("patterns", [])],
            }

        # Dynamically compile channel-specific rules (SMS smishing, social media lures)
        self.channel_rules.clear()
        for k, v in data.get("channel_rules", {}).items():
            rule = dict(v)
            if "pattern" in rule:
                rule["compiled_pattern"] = re.compile(rule["pattern"], re.I)
            if "pivot_pattern" in rule:
                rule["compiled_pivot"] = re.compile(rule["pivot_pattern"], re.I)
            self.channel_rules[k] = rule

        # Dynamically compile email indicators
        self.email_indicators.clear()
        for k, v in data.get("email_indicators", {}).items():
            if isinstance(v, str):
                self.email_indicators[k] = re.compile(v, re.I)
            else:
                self.email_indicators[k] = v


class DynamicProbabilisticClassifier:
    """
    Self-training dynamic Machine Learning Classifier.
    Computes vocabulary, TF-IDF weights, and log-odds ratios dynamically from training data.
    Can be dynamically retrained at runtime without restarting the server.
    """

    def __init__(self, corpus_path: str = CORPUS_FILE):
        self.corpus_path = corpus_path
        self.vocabulary: Dict[str, float] = {}
        self.prior_log_odds: float = -1.2
        self.doc_count: int = 0
        self.train_from_file()

    def _tokenize(self, text: str) -> List[str]:
        text_lower = text.lower()
        words = re.findall(r"\b[a-z0-9'-]+\b", text_lower)
        # Generate unigrams and bigrams
        tokens = list(words)
        for i in range(len(words) - 1):
            tokens.append(f"{words[i]} {words[i+1]}")
        return tokens

    def train_from_file(self):
        if not os.path.exists(self.corpus_path):
            return
        with open(self.corpus_path, "r", encoding="utf-8") as f:
            corpus = json.load(f)
        self.train(corpus)

    def train(self, labeled_samples: List[Dict[str, Any]]):
        """Train model parameters dynamically from labeled text samples."""
        self.doc_count = len(labeled_samples)
        if self.doc_count == 0:
            return

        phish_counts: Dict[str, int] = {}
        benign_counts: Dict[str, int] = {}
        total_phish_words = 0
        total_benign_words = 0
        phish_docs = sum(1 for s in labeled_samples if s["label"] == 1)
        benign_docs = self.doc_count - phish_docs

        for sample in labeled_samples:
            label = sample.get("label", 0)
            tokens = self._tokenize(sample.get("text", ""))
            target_dict = phish_counts if label == 1 else benign_counts
            for token in tokens:
                target_dict[token] = target_dict.get(token, 0) + 1
                if label == 1:
                    total_phish_words += 1
                else:
                    total_benign_words += 1

        all_vocab = set(phish_counts.keys()).union(set(benign_counts.keys()))
        vocab_size = len(all_vocab)
        alpha = 1.0  # Laplace smoothing

        # Compute dynamic log-odds ratios
        weights = {}
        for token in all_vocab:
            p_phish = (phish_counts.get(token, 0) + alpha) / (total_phish_words + alpha * vocab_size)
            p_benign = (benign_counts.get(token, 0) + alpha) / (total_benign_words + alpha * vocab_size)
            log_odds = math.log(p_phish / p_benign)
            # Filter low-relevance noise
            if abs(log_odds) > 0.4:
                weights[token] = round(log_odds * 1.8, 2)

        self.vocabulary = weights
        # Prior probability log-odds based on class balance
        if benign_docs > 0 and phish_docs > 0:
            self.prior_log_odds = round(math.log(phish_docs / benign_docs) - 0.8, 2)

    def predict(self, text: str) -> Dict[str, Any]:
        """Dynamically evaluate text using TF-IDF weighted log-odds scoring."""
        text_lower = text.lower()
        words = re.findall(r"\b[a-z0-9'-]+\b", text_lower)
        word_count = max(len(words), 1)

        base_log_odds = self.prior_log_odds
        active_features = []

        for token, weight in self.vocabulary.items():
            freq = 0
            if " " in token:
                if token in text_lower:
                    freq = text_lower.count(token)
            else:
                freq = words.count(token)

            if freq > 0:
                # Dynamic TF-IDF proxy
                tfidf = math.log1p(freq) * (1.0 + math.log(100.0 / (word_count + 1)))
                impact = weight * min(tfidf, 3.2)
                base_log_odds += impact
                active_features.append({
                    "token": token,
                    "weight": round(impact, 2),
                    "sentiment": "Phishing Signal" if weight > 0 else "Benign Indicator"
                })

        # Sigmoid activation
        bounded_log_odds = max(min(base_log_odds, 12.0), -12.0)
        probability = 1.0 / (1.0 + math.exp(-bounded_log_odds))

        active_features.sort(key=lambda x: abs(x["weight"]), reverse=True)

        if probability >= 0.70:
            verdict = "High Confidence Phishing / Scam"
        elif probability >= 0.45:
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


# Global dynamic instances
INTEL_MANAGER = ThreatIntelManager()
ML_CLASSIFIER = DynamicProbabilisticClassifier()


def compute_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy for text randomness."""
    if not text:
        return 0.0
    text_clean = text.strip()
    probabilities = [float(text_clean.count(c)) / len(text_clean) for c in set(text_clean)]
    return -sum(p * math.log2(p) for p in probabilities if p > 0)


def extract_linguistic_signals(text: str) -> Tuple[List[Dict[str, Any]], Dict[str, int], List[str]]:
    """Scan text across dynamically loaded linguistic categories."""
    findings = []
    category_scores = {}
    matched_phrases = []

    for cat_key, cat_data in INTEL_MANAGER.compiled_categories.items():
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
    """Dynamically analyze stylometric anomalies: SHOUTING, punctuation bursts, and entropy."""
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
    """Execute dynamic ML probabilistic classifier."""
    return ML_CLASSIFIER.predict(text)


def analyze_linguistic_content(text: str) -> Dict[str, Any]:
    """Complete dynamic AI and linguistic analysis orchestration."""
    findings, category_scores, matched_phrases = extract_linguistic_signals(text)
    stylometrics = compute_stylometrics(text)
    ml_result = predict_phishing_ml(text)

    if stylometrics["anomalous"]:
        if stylometrics["upper_ratio"] > 0.45:
            findings.append({
                "category": "stylometrics",
                "title": "Abnormal Capitalization (Shouting)",
                "detail": f"{int(stylometrics['upper_ratio'] * 100)}% of characters are uppercase, an indicator of urgent psychological coercion.",
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

    total_linguistic_weight = sum(item["weight"] for item in findings)
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
