import ipaddress
import math
import re
from urllib.parse import urlsplit

from ai_engine import INTEL_MANAGER


MULTIPLE_PROTOCOL_PATTERN = re.compile(r"https?://.*https?://", re.I)

# Dynamic references backed by ThreatIntelManager
SHORTENERS = INTEL_MANAGER.shorteners
HIGH_ABUSE_TLDS = INTEL_MANAGER.high_abuse_tlds
TARGETED_BRANDS = INTEL_MANAGER.targeted_brands
HOMOGLYPH_MAP = INTEL_MANAGER.homoglyphs
URL_KEYWORD_PATTERN = INTEL_MANAGER.account_keywords_pattern


def compute_vowel_consonant_ratio(text: str) -> float:
    """Compute vowel-to-consonant ratio to detect algorithmic unpronounceable domains."""
    alpha = [c.lower() for c in text if c.isalpha()]
    if not alpha:
        return 0.5
    vowels = sum(1 for c in alpha if c in "aeiou")
    return vowels / len(alpha)


def compute_entropy(text: str) -> float:
    """Compute Shannon entropy for a given string."""
    if not text:
        return 0.0
    probabilities = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probabilities if p > 0)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def detect_brand_spoofing(hostname: str):
    """Detect if a hostname attempts brand impersonation or typosquatting."""
    hostname_clean = hostname.lower()
    parts = hostname_clean.split(".")
    
    # Extract registered domain candidate (last two parts or last three for ccTLDs)
    registered_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname_clean
    domain_name = parts[-2] if len(parts) >= 2 else parts[0]
    subdomains = parts[:-2] if len(parts) >= 2 else []

    # 1. Brand in subdomain or sub-label while main domain is different
    for brand, label in TARGETED_BRANDS.items():
        # Check if brand appears in subdomains or hyphenated segments
        for sub in subdomains:
            if brand in sub:
                return {
                    "type": "subdomain_impersonation",
                    "brand": brand,
                    "label": label,
                    "detail": f"Targeted brand '{label}' found in subdomain '{sub}', disguising actual destination '{registered_domain}'."
                }
        
        # Check hyphenated main domain like "paypal-update.com"
        if "-" in domain_name and brand in domain_name:
            if domain_name != brand:
                return {
                    "type": "hyphen_impersonation",
                    "brand": brand,
                    "label": label,
                    "detail": f"Targeted brand '{label}' combined with deceptive keywords in host '{domain_name}'."
                }

    # 2. Typosquatting & visual substitution on main domain AND hyphen-separated tokens
    candidate_tokens = [domain_name]
    if "-" in domain_name:
        candidate_tokens.extend([t for t in domain_name.split("-") if t])

    for token in candidate_tokens:
        normalized_token = token.replace("0", "o").replace("1", "l").replace("rn", "m")
        
        for brand, label in TARGETED_BRANDS.items():
            if brand == token:
                if token != domain_name:
                    return {
                        "type": "hyphen_impersonation",
                        "brand": brand,
                        "label": label,
                        "detail": f"Targeted brand '{label}' combined with deceptive keywords in host '{domain_name}'."
                    }
                continue  # Exact match for full domain

            # Exact match after visually deceptive substitution (e.g. rnicrosoft or paypa1)
            if normalized_token == brand and len(brand) >= 4:
                return {
                    "type": "typosquatting_visual_substitution",
                    "brand": brand,
                    "label": label,
                    "detail": f"Host segment '{token}' uses visual substitution to imitate '{label}'."
                }
                
            dist = levenshtein_distance(token, brand)
            if (len(brand) >= 5 and dist == 1) or (len(brand) >= 7 and dist == 2):
                return {
                    "type": "typosquatting_edit_distance",
                    "brand": brand,
                    "label": label,
                    "detail": f"Host segment '{token}' is suspiciously close in spelling to '{label}' (Levenshtein distance {dist})."
                }

    return None


def detect_homoglyphs(text: str):
    """Detect non-ASCII homoglyphs often used in IDN spoofing."""
    found = []
    for char in text:
        if char in HOMOGLYPH_MAP:
            found.append((char, HOMOGLYPH_MAP[char]))
    return found


def _finding(title: str, detail: str, weight: int):
    return {"title": title, "detail": detail, "weight": weight}


def analyze_url_details(value: str):
    """Deep analysis of a URL, returning findings, metadata, and risk evaluation."""
    value = value.strip()
    if not value:
        raise ValueError("Enter a URL to scan.")
    if len(value) > 2_048:
        raise ValueError("The URL is too long to scan.")

    # Defanging cleanup (e.g. hxxps:// or [.] or (.))
    cleaned_value = re.sub(r"(?i)^hxxp(s?)://", r"http\1://", value)
    cleaned_value = re.sub(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)", ".", cleaned_value, flags=re.I)
    cleaned_value = cleaned_value.rstrip(".,!?;:)")

    if cleaned_value.lower().startswith("www."):
        cleaned_value = f"https://{cleaned_value}"

    candidate = cleaned_value if "://" in cleaned_value else f"https://{cleaned_value}"
    multiple_protocols = bool(MULTIPLE_PROTOCOL_PATTERN.search(candidate))

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Enter a valid HTTP or HTTPS URL.") from exc

    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    if "." not in hostname and not multiple_protocols:
        raise ValueError("The URL format appears invalid.")

    findings = []
    metadata = {
        "raw_url": value,
        "normalized_url": candidate,
        "scheme": parsed.scheme.lower(),
        "hostname": hostname,
        "port": port or (443 if parsed.scheme.lower() == "https" else 80),
        "path": parsed.path or "/",
        "query": parsed.query,
        "is_ip": False,
        "is_shortener": False,
        "entropy": round(compute_entropy(hostname), 2),
        "tld": hostname.split(".")[-1].lower() if "." in hostname else "",
        "tld_risk": "standard",
        "brand_spoofing": None,
        "homoglyphs": [],
        "punycode": False,
    }

    # 1. Transport Encryption
    if parsed.scheme.lower() == "http":
        findings.append(_finding(
            "The URL does not use HTTPS",
            "This link uses an unencrypted HTTP connection.",
            20,
        ))

    # 2. Credential/User-info Injection (@ symbol)
    if parsed.username is not None or parsed.password is not None or "@" in candidate.split("/", 3)[2]:
        findings.append(_finding(
            "The URL contains an @ symbol",
            "An @ symbol in the address can disguise the actual destination host.",
            35,
        ))

    # 3. IP Hostname Check
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        # Check hex or octal IP format (e.g. 0x7f.1)
        if re.match(r"^0x[0-9a-f]+(\.0x[0-9a-f]+)*$", hostname, re.I):
            is_ip = True

    if is_ip:
        metadata["is_ip"] = True
        findings.append(_finding(
            "The URL uses an IP address as its hostname",
            "The link points directly to an IP address rather than a recognizable domain.",
            30,
        ))

    # 4. Hostname Character & Structure Warnings
    if hostname.count("-") >= 3:
        findings.append(_finding(
            "The hostname contains multiple hyphens",
            "Several hyphens in a hostname can make a deceptive address harder to read.",
            15,
        ))

    if len(hostname) > 40:
        findings.append(_finding(
            "The hostname is unusually long",
            "An unusually long hostname can make the real domain harder to recognize.",
            15,
        ))

    if len(re.findall(r"\d", hostname)) >= 5:
        findings.append(_finding(
            "The hostname contains many digits",
            "A hostname with many digits can be harder to recognize and verify.",
            10,
        ))

    # 5. Multiple Protocol Markers
    if multiple_protocols:
        findings.append(_finding(
            "The URL contains multiple protocol patterns",
            "The address contains more than one HTTP or HTTPS protocol marker.",
            25,
        ))

    # 6. Punycode & IDN Homographs
    if "xn--" in hostname.lower():
        metadata["punycode"] = True
        findings.append(_finding(
            "Internationalized domain name",
            "The host contains an encoded domain name (Punycode) that may resemble another site.",
            20,
        ))

    homoglyphs = detect_homoglyphs(candidate)
    if homoglyphs:
        metadata["homoglyphs"] = [f"{h[0]} -> {h[1]}" for h in homoglyphs]
        findings.append(_finding(
            "Cyrillic or Greek homoglyph characters detected",
            f"The link contains look-alike characters ({', '.join(metadata['homoglyphs'][:3])}) used to visually counterfeit legitimate domains.",
            25,
        ))

    # 7. URL Shorteners
    if hostname.lower() in SHORTENERS:
        metadata["is_shortener"] = True
        findings.append(_finding(
            "Shortened link",
            "The final destination is hidden behind a URL-shortening service.",
            14,
        ))

    # 8. Unusually Nested Subdomains
    if len(hostname.split(".")) >= 5:
        findings.append(_finding(
            "Unusually nested domain",
            "The address contains several subdomains, which can make the true site harder to spot.",
            10,
        ))

    # 9. Account Keywords in Hostname
    if URL_KEYWORD_PATTERN.search(hostname):
        findings.append(_finding(
            "The hostname contains account-related keywords",
            "The hostname includes wording commonly used in account or payment lures.",
            10,
        ))

    # 10. Non-Standard Port
    if port is not None and port not in {80, 443}:
        findings.append(_finding(
            "Non-standard web port",
            f"The link uses port {port} rather than a standard web port.",
            10,
        ))

    # 11. High-Abuse Top-Level Domain (TLD)
    tld = metadata["tld"]
    if tld in HIGH_ABUSE_TLDS:
        metadata["tld_risk"] = "high"
        findings.append(_finding(
            f"High-risk Top-Level Domain (.{tld})",
            f"The domain uses the .{tld} TLD. {HIGH_ABUSE_TLDS[tld]}",
            20,
        ))

    # 12. Shannon Entropy / DGA Detection
    if metadata["entropy"] >= 3.8 and len(hostname) > 12 and not is_ip:
        findings.append(_finding(
            "High hostname character entropy",
            f"The hostname exhibits high randomness (Entropy: {metadata['entropy']}), characteristic of Domain Generation Algorithms (DGA) or disposable malicious hosts.",
            15,
        ))

    # 13. Brand Impersonation & Typosquatting
    spoof = detect_brand_spoofing(hostname)
    if spoof:
        metadata["brand_spoofing"] = spoof
        findings.append(_finding(
            f"Suspected brand impersonation: {spoof['label']}",
            spoof["detail"],
            30,
        ))

    # 14. Excessive Path or Suspicious File Extensions in Path
    suspicious_exts = re.search(r"\.(exe|apk|bat|cmd|vbs|scr|iso|msi|ps1|zip|rar)$", parsed.path, re.I)
    if suspicious_exts:
        ext = suspicious_exts.group(1).upper()
        findings.append(_finding(
            f"Direct download of executable/archive ({ext})",
            f"The URL points directly to a high-risk downloadable payload file: .{ext.lower()}.",
            35,
        ))

    return findings, metadata
