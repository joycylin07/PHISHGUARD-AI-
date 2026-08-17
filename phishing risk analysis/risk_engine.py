"""
risk_engine.py
---------------------------------------------------------------
Risk Analysis & Explainable AI Engine (Phishing URL Detection)

Purpose
-------
Machine learning phishing classifiers output a bare label or probability
(e.g. "Phishing = 1", "0.91"). That's useless to an end user. This module
turns that raw prediction into something a human can actually understand:

    - A risk LEVEL (LOW / MEDIUM / HIGH)
    - A ranked list of human-readable RISK FACTORS that fired
    - One or more THREAT CATEGORIES (what kind of attack this looks like)
    - A RISK FINGERPRINT: a per-dimension breakdown (URL Structure, Domain
      Anomaly, Suspicious Terms, Obfuscation) plus an Overall Risk score

Design
------
This module is intentionally decoupled from any specific classifier. It can
be used in two ways:

1. Standalone heuristic mode - pass just a URL. The engine derives its own
   risk fingerprint from rule-based signal detection (no ML model needed).
   Useful for a demo, for unit testing, or as a fallback if the model is
   unavailable.

2. ML-assisted mode - pass a URL *and* a phishing probability produced by
   your trained classifier (e.g. from `model.predict_proba(X)[0][1]`). The
   model's probability becomes the authoritative "Overall Risk" / phishing
   probability, while the heuristics still generate the explanatory risk
   factors, categories, and fingerprint breakdown that justify *why* the
   model flagged the URL. This is what "explainable AI" means here: the
   heuristics don't replace the model, they explain it.

This file only analyzes URLs for defensive / educational purposes (a
phishing *detector*, not a tool for creating phishing content).
"""

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

# =================================================================
# Reference data used by the heuristic signal detectors
# =================================================================

SUSPICIOUS_KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "secure", "security", "account", "update", "confirm", "confirmation",
    "banking", "billing", "password", "credential", "authenticate",
    "suspend", "suspended", "urgent", "immediately", "limited", "unlock",
    "reset", "validate", "recover", "wallet", "invoice", "payment",
    "webscr", "support", "helpdesk", "alert",
]

# Common brand names that phishing sites frequently impersonate.
BRAND_NAMES = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "instagram", "netflix", "bankofamerica", "chase", "wellsfargo",
    "outlook", "office365", "linkedin", "twitter", "coinbase", "binance",
    "dhl", "fedex", "irs",
]

KNOWN_URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".work", ".support", ".gq", ".tk", ".ml",
    ".cf", ".zip", ".review", ".country", ".stream", ".loan", ".men",
]

IP_ADDRESS_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-fA-F:]+\]?$"
)

RISK_LEVELS = [
    (0, 30, "LOW"),
    (31, 70, "MEDIUM"),
    (71, 100, "HIGH"),
]

RISK_LEVEL_ICONS = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴"}


# =================================================================
# Data structures
# =================================================================

@dataclass
class RiskFactor:
    """A single human-readable signal that contributed to the risk score."""
    label: str
    category: str   # one of: URL Structure, Domain Anomaly, Suspicious Terms, Obfuscation
    weight: float    # how much this signal contributes to its category (0-100 scale points)


@dataclass
class RiskReport:
    """Final explainable output handed to the frontend / user."""
    url: str
    overall_risk: float                  # 0-100
    risk_level: str                       # LOW / MEDIUM / HIGH
    phishing_probability: float           # 0-100, same as overall_risk unless ML-assisted differs
    risk_factors: List[RiskFactor] = field(default_factory=list)
    threat_categories: List[str] = field(default_factory=list)
    fingerprint: Dict[str, float] = field(default_factory=dict)
    source: str = "heuristic"             # "heuristic" or "ml+heuristic"


# =================================================================
# Low-level signal detectors
# One function per detector. Each returns (fired: bool, weight: float, label: str)
# so new checks can be added without touching the scoring logic.
# =================================================================

def _url_structure_signals(parsed, raw_url: str) -> List[RiskFactor]:
    signals = []
    host = parsed.netloc.split(":")[0].lower()
    path = parsed.path or ""

    if len(raw_url) > 75:
        signals.append(RiskFactor("Abnormal URL length", "URL Structure", 22))
    if host.count("-") >= 3:
        signals.append(RiskFactor("Excessive hyphens in domain", "URL Structure", 18))
    if sum(c.isdigit() for c in host) >= 4:
        signals.append(RiskFactor("Unusual number of digits in domain", "URL Structure", 15))
    if path.count("/") >= 5:
        signals.append(RiskFactor("Deeply nested URL path", "URL Structure", 15))
    if IP_ADDRESS_PATTERN.match(host):
        signals.append(RiskFactor("Domain is a raw IP address", "URL Structure", 35))
    if parsed.port not in (None, 80, 443):
        signals.append(RiskFactor("Non-standard port specified", "URL Structure", 15))
    return signals


def _domain_anomaly_signals(parsed) -> List[RiskFactor]:
    signals = []
    host = parsed.netloc.split(":")[0].lower()
    labels = host.split(".")
    subdomain_count = max(0, len(labels) - 2)

    if subdomain_count >= 3:
        signals.append(RiskFactor("Multiple subdomains", "Domain Anomaly", 25))
    elif subdomain_count == 2:
        signals.append(RiskFactor("Extra subdomain layer", "Domain Anomaly", 12))

    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        signals.append(RiskFactor("Uncommon / high-risk top-level domain", "Domain Anomaly", 20))

    registrable = ".".join(labels[-2:]) if len(labels) >= 2 else host
    for brand in BRAND_NAMES:
        if brand in host and brand not in registrable.split(".")[0]:
            signals.append(RiskFactor(f"Brand name '{brand}' used outside the real domain", "Domain Anomaly", 30))
            break
        if brand in registrable and registrable.split(".")[0] != brand:
            signals.append(RiskFactor(f"Domain closely mimics brand '{brand}' (possible typosquat)", "Domain Anomaly", 28))
            break

    if "-" in registrable.split(".")[0] and any(b in registrable for b in BRAND_NAMES):
        signals.append(RiskFactor("Brand name combined with extra words via hyphen", "Domain Anomaly", 18))

    return signals


def _suspicious_terms_signals(raw_url: str) -> List[RiskFactor]:
    signals = []
    lowered = raw_url.lower()
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered]
    if hits:
        # Weight scales with number of distinct suspicious keywords found, capped.
        weight = min(90, 20 + 15 * len(hits))
        display_hits = ", ".join(sorted(set(hits))[:4])
        signals.append(RiskFactor(f"Suspicious keyword(s) detected: {display_hits}", "Suspicious Terms", weight))
    return signals


def _obfuscation_signals(raw_url: str, parsed) -> List[RiskFactor]:
    signals = []
    host = parsed.netloc.split(":")[0].lower()

    if "@" in raw_url:
        signals.append(RiskFactor("'@' symbol used to mask real destination", "Obfuscation", 35))
    if "%" in raw_url:
        signals.append(RiskFactor("URL-encoded (percent-escaped) characters present", "Obfuscation", 20))
    if any(short in host for short in KNOWN_URL_SHORTENERS):
        signals.append(RiskFactor("Known URL shortener used to hide destination", "Obfuscation", 25))
    if re.search(r"xn--", host):
        signals.append(RiskFactor("Punycode / internationalized domain (possible homograph attack)", "Obfuscation", 30))
    if raw_url.count("//") > 1:
        signals.append(RiskFactor("Multiple protocol markers suggest embedded redirect", "Obfuscation", 20))
    return signals


# =================================================================
# Scoring
# =================================================================

CATEGORY_WEIGHTS = {
    "URL Structure": 0.20,
    "Domain Anomaly": 0.30,
    "Suspicious Terms": 0.30,
    "Obfuscation": 0.20,
}


def _category_score(signals: List[RiskFactor], category: str) -> float:
    """Combine multiple weighted signals in a category into one 0-100 score.

    Signals are combined with diminishing returns (not simple addition) so
    that, e.g., 3 minor signals don't automatically imply certainty, but do
    still meaningfully raise the score.
    """
    relevant = [s.weight for s in signals if s.category == category]
    if not relevant:
        return 0.0
    score = 0.0
    for w in sorted(relevant, reverse=True):
        score += (100 - score) * (w / 100)
    return round(min(score, 100), 1)


def classify_risk_level(overall_risk: float) -> str:
    for low, high, label in RISK_LEVELS:
        if low <= overall_risk <= high:
            return label
    return "HIGH"  # safety fallback, should not normally trigger


def _derive_threat_categories(signals: List[RiskFactor], fingerprint: Dict[str, float]) -> List[str]:
    """Map the strongest signals/categories onto human-facing threat labels."""
    categories = []

    domain_anomaly_labels = " ".join(s.label for s in signals if s.category == "Domain Anomaly")
    terms_labels = " ".join(s.label for s in signals if s.category == "Suspicious Terms")
    obf_labels = " ".join(s.label for s in signals if s.category == "Obfuscation")

    if "typosquat" in domain_anomaly_labels or "mimics brand" in domain_anomaly_labels:
        categories.append("Domain Spoofing")
    if "Brand name" in domain_anomaly_labels:
        categories.append("Brand Impersonation")
    if any(k in terms_labels.lower() for k in ["login", "signin", "sign-in", "password", "credential"]):
        categories.append("Credential Theft")
    if any(k in terms_labels.lower() for k in ["verify", "account", "secure", "confirm"]) and fingerprint["Domain Anomaly"] > 40:
        categories.append("Suspicious Login")
    if fingerprint["Obfuscation"] >= 40:
        categories.append("URL Obfuscation")

    if not categories and fingerprint["Overall Risk"] >= 31:
        categories.append("Suspicious Activity")

    # De-duplicate while preserving order.
    seen = set()
    ordered = []
    for c in categories:
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    return ordered


# =================================================================
# Public API
# =================================================================

def analyze_url(url: str, ml_probability: Optional[float] = None) -> RiskReport:
    """
    Analyze a URL and produce a full explainable risk report.

    Args:
        url: the URL to analyze.
        ml_probability: optional phishing probability (0.0-1.0) from a
            trained ML classifier (e.g. model.predict_proba(X)[0][1]).
            When provided, it becomes the authoritative overall risk score;
            heuristic signals are still computed to explain *why*.

    Returns:
        RiskReport
    """
    if not url or not isinstance(url, str):
        raise ValueError("A non-empty URL string is required.")

    normalized = url.strip()
    if "://" not in normalized:
        normalized = "http://" + normalized

    parsed = urlparse(normalized)
    if not parsed.netloc:
        raise ValueError(f"Could not parse a valid domain from URL: {url!r}")

    signals: List[RiskFactor] = []
    signals += _url_structure_signals(parsed, normalized)
    signals += _domain_anomaly_signals(parsed)
    signals += _suspicious_terms_signals(normalized)
    signals += _obfuscation_signals(normalized, parsed)

    fingerprint = {
        "URL Structure": _category_score(signals, "URL Structure"),
        "Domain Anomaly": _category_score(signals, "Domain Anomaly"),
        "Suspicious Terms": _category_score(signals, "Suspicious Terms"),
        "Obfuscation": _category_score(signals, "Obfuscation"),
    }

    heuristic_overall = round(
        sum(fingerprint[cat] * w for cat, w in CATEGORY_WEIGHTS.items()), 1
    )

    if ml_probability is not None:
        if not (0.0 <= ml_probability <= 1.0):
            raise ValueError("ml_probability must be between 0.0 and 1.0")
        overall_risk = round(ml_probability * 100, 1)
        source = "ml+heuristic"
    else:
        overall_risk = heuristic_overall
        source = "heuristic"

    fingerprint["Overall Risk"] = overall_risk
    risk_level = classify_risk_level(overall_risk)
    threat_categories = _derive_threat_categories(signals, fingerprint)

    # Sort risk factors strongest-first for display.
    signals_sorted = sorted(signals, key=lambda s: s.weight, reverse=True)

    return RiskReport(
        url=url,
        overall_risk=overall_risk,
        risk_level=risk_level,
        phishing_probability=overall_risk,
        risk_factors=signals_sorted,
        threat_categories=threat_categories or ["No specific threat pattern identified"],
        fingerprint=fingerprint,
        source=source,
    )


def format_report(report: RiskReport) -> str:
    """Render a RiskReport as the human-readable text block used in the UI/CLI."""
    icon = RISK_LEVEL_ICONS.get(report.risk_level, "⚠")
    lines = []
    lines.append(f"URL: {report.url}")
    lines.append(f"{icon} {report.risk_level} RISK")
    lines.append(f"Phishing Probability: {report.phishing_probability:.0f}%")
    lines.append("")
    lines.append("Risk Factors:")
    if report.risk_factors:
        for f in report.risk_factors:
            lines.append(f"  ✓ {f.label}")
    else:
        lines.append("  (none detected)")
    lines.append("")
    lines.append("Threat Categories:")
    for cat in report.threat_categories:
        lines.append(f"  • {cat}")
    lines.append("")
    lines.append("Risk Fingerprint:")
    for cat in ["URL Structure", "Domain Anomaly", "Suspicious Terms", "Obfuscation"]:
        lines.append(f"  {cat:<20} {report.fingerprint[cat]:.0f}%")
    lines.append(f"  {'Overall Risk':<20} {report.overall_risk:.0f}%")
    lines.append(f"\n(source: {report.source})")
    return "\n".join(lines)


def report_to_dict(report: RiskReport) -> dict:
    """JSON-serializable representation, e.g. for an API response or a Streamlit app."""
    return {
        "url": report.url,
        "risk_level": report.risk_level,
        "phishing_probability": report.phishing_probability,
        "overall_risk": report.overall_risk,
        "risk_factors": [f.label for f in report.risk_factors],
        "threat_categories": report.threat_categories,
        "fingerprint": report.fingerprint,
        "source": report.source,
    }
