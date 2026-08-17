"""
demo.py
---------------------------------------------------------------
Demonstrates the Risk Analysis & Explainable AI engine against a handful
of example URLs (a mix of phishing-style and legitimate-style patterns),
in both:

  1. Heuristic-only mode (no ML model involved)
  2. ML-assisted mode (simulating a probability handed off by a trained
     phishing classifier, e.g. scikit-learn's model.predict_proba)

Run:
    python demo.py
"""

import sys

# Ensure UTF-8 output encoding for consoles (e.g. Windows)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from risk_engine import analyze_url, format_report, report_to_dict

EXAMPLE_URLS = [
    # Style: credential-theft / brand impersonation phishing pattern
    "http://secure-login-paypal.com.verify-account.xyz/signin/update?user=confirm",
    # Style: obfuscated with IP host + '@' trick
    "http://192.168.14.9@mybank-support.top/login.php%20account",
    # Style: typosquatted brand with suspicious subdomain chain
    "http://accounts.google.com.security-alert.support.review/verify",
    # Style: ordinary, benign-looking URL
    "https://www.wikipedia.org/wiki/Phishing",
    # Style: shortened URL (destination hidden)
    "http://bit.ly/3xJ8kLq",
]


def run_heuristic_demo():
    print("=" * 70)
    print("MODE 1: Heuristic-only (no ML model)")
    print("=" * 70)
    for url in EXAMPLE_URLS:
        report = analyze_url(url)
        print(format_report(report))
        print("-" * 70)


def run_ml_assisted_demo():
    print("\n" + "=" * 70)
    print("MODE 2: ML-assisted (probability supplied by a trained classifier)")
    print("=" * 70)
    # In a real system these numbers come from:
    #   prob = model.predict_proba(X)[0][1]
    # Here we simulate plausible outputs for each example URL to show how
    # the ML probability becomes the authoritative score while the
    # heuristics still explain *why*.
    simulated_ml_probabilities = [0.91, 0.87, 0.83, 0.04, 0.55]

    for url, prob in zip(EXAMPLE_URLS, simulated_ml_probabilities):
        report = analyze_url(url, ml_probability=prob)
        print(format_report(report))
        print("-" * 70)


def run_json_example():
    print("\n" + "=" * 70)
    print("Example JSON payload (for a Streamlit / API frontend)")
    print("=" * 70)
    report = analyze_url(EXAMPLE_URLS[0], ml_probability=0.91)
    import json
    print(json.dumps(report_to_dict(report), indent=2))


if __name__ == "__main__":
    run_heuristic_demo()
    run_ml_assisted_demo()
    run_json_example()
