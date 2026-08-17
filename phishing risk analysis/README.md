# 🧠 Risk Analysis & Explainable AI Module (Phishing URL Detection)

Turns a raw ML prediction (`Phishing = 1`, `0.91`) into a human-readable
risk report:

```
🔴 HIGH RISK
Phishing Probability: 91%

Risk Factors:
  ✓ Suspicious keyword(s) detected: account, confirm, login, secure
  ✓ Brand name 'paypal' used outside the real domain
  ✓ Abnormal URL length
  ✓ Uncommon / high-risk top-level domain
  ✓ Excessive hyphens in domain
  ✓ Extra subdomain layer

Threat Categories:
  • Brand Impersonation
  • Credential Theft
  • Suspicious Login

Risk Fingerprint:
  URL Structure        36%
  Domain Anomaly       51%
  Suspicious Terms     90%
  Obfuscation          0%
  Overall Risk         91%
```

## Files

| File                    | Purpose                                                          |
|--------------------------|-------------------------------------------------------------------|
| `risk_engine.py`          | Core explainability engine — all logic lives here                |
| `demo.py`                 | CLI demo against 5 example URLs (heuristic + ML-assisted modes)  |
| `app.py`                  | Streamlit UI for interactive demoing                              |
| `test_risk_engine.py`     | Unit tests (11 tests, run with `python -m unittest`)              |
| `requirements.txt`        | Only needs `streamlit`, for the UI                                 |

## How it fits into the team project

This module is **decoupled from any specific classifier** so you can build
and demo it independently of whoever is training the actual phishing model:

- **Heuristic-only mode** — call `analyze_url(url)` with just a URL. The
  engine derives its own risk fingerprint from rule-based signal detection.
  Useful standalone, for testing, or as a fallback if the model is down.
- **ML-assisted mode** — call `analyze_url(url, ml_probability=0.91)` once
  the modeling teammate's classifier is ready
  (`prob = model.predict_proba(X)[0][1]`). The model's probability becomes
  the authoritative **Overall Risk** score, while the heuristics still
  generate the **risk factors**, **threat categories**, and **fingerprint**
  that explain *why* — that's the "explainable AI" part.

When your teammate's model is ready, integration is one line:

```python
from risk_engine import analyze_url, format_report

prob = model.predict_proba(extract_features(url))[0][1]
report = analyze_url(url, ml_probability=prob)
print(format_report(report))
```

## Risk levels

| Range   | Level  |
|---------|--------|
| 0–30%   | 🟢 LOW    |
| 31–70%  | 🟡 MEDIUM |
| 71–100% | 🔴 HIGH   |

## Risk fingerprint categories

- **URL Structure** — length, hyphens, digit density, path depth, raw IP
  hostnames, non-standard ports
- **Domain Anomaly** — subdomain count, suspicious TLDs, brand names used
  outside the real registrable domain (typosquatting / impersonation)
- **Suspicious Terms** — phishing-associated keywords (login, verify,
  suspend, urgent, etc.)
- **Obfuscation** — `@` tricks, percent-encoding, known URL shorteners,
  punycode/homograph domains, embedded redirects

Each category is scored 0–100 with diminishing returns (multiple weak
signals don't simply add up to certainty, but do meaningfully raise the
score). The four categories combine into the **Overall Risk** using
weighted averaging (Domain Anomaly and Suspicious Terms weighted highest,
since they're the strongest phishing indicators), *unless* an ML
probability is supplied, in which case that becomes the overall score.

## Threat categories

Derived from which risk factors fired:

- **Credential Theft** — login/password/credential-related keywords
- **Brand Impersonation** — a known brand name appears outside its real
  domain
- **Domain Spoofing** — domain closely mimics a brand (typosquat pattern)
- **Suspicious Login** — account/verify/security language combined with
  domain anomalies
- **URL Obfuscation** — high obfuscation-category score

A single URL can trigger multiple categories at once.

## Run it

```bash
pip install -r requirements.txt   # only needed for the Streamlit UI

python demo.py                     # CLI demo, no dependencies needed
python -m unittest test_risk_engine.py -v   # run tests
streamlit run app.py               # interactive UI
```

## Notes for the viva / write-up

- This is a **detection/defense** tool: it analyzes URLs to flag phishing
  risk, not a tool for constructing phishing content.
- All scoring is rule-based and transparent by design — every point on the
  fingerprint traces back to a specific, explainable signal, which is the
  whole point of an "explainable AI" layer sitting on top of a black-box
  classifier.
- The keyword/brand/TLD/shortener lists in `risk_engine.py` are easy to
  extend — add entries to `SUSPICIOUS_KEYWORDS`, `BRAND_NAMES`,
  `SUSPICIOUS_TLDS`, or `KNOWN_URL_SHORTENERS` as needed.
