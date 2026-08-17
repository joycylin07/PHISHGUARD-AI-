"""
app.py
---------------------------------------------------------------
Streamlit demo UI for the Risk Analysis & Explainable AI engine.

Run:
    streamlit run app.py

This is a standalone demo of the explainability layer. In the full
phishing-detection system, `ml_probability` below would come from your
team's trained classifier, e.g.:

    from your_model_module import load_model, extract_ml_features
    model = load_model()
    prob = model.predict_proba(extract_ml_features(url))[0][1]
    report = analyze_url(url, ml_probability=prob)

Here, a slider lets you simulate that probability so this piece can be
demoed and tested independently of the modeling team's progress.
"""

import streamlit as st

from risk_engine import analyze_url, report_to_dict, RISK_LEVEL_ICONS

st.set_page_config(page_title="Phishing Risk Explainability", page_icon="🛡️", layout="centered")

st.title("🛡️ Phishing URL Risk Analysis")
st.caption("Explainable AI layer — turns a raw model prediction into a human-readable risk report.")

st.markdown("---")

url = st.text_input("Enter a URL to analyze", placeholder="http://example-login-secure.com/verify")

use_ml = st.checkbox("Simulate an ML classifier probability (ML-assisted mode)", value=True)
ml_prob = None
if use_ml:
    ml_prob = st.slider(
        "Simulated phishing probability from your ML model",
        min_value=0, max_value=100, value=50,
        help="In production this comes from model.predict_proba(X)[0][1], not a slider.",
    ) / 100.0

analyze_clicked = st.button("🔍 Analyze URL", type="primary", use_container_width=True)

if analyze_clicked:
    if not url.strip():
        st.error("Please enter a URL to analyze.")
        st.stop()
    try:
        report = analyze_url(url, ml_probability=ml_prob)
    except ValueError as e:
        st.error(f"⚠️ {e}")
        st.stop()
    except Exception:
        st.error("⚠️ Something went wrong while analyzing this URL. Please check the format and try again.")
        st.stop()

    icon = RISK_LEVEL_ICONS.get(report.risk_level, "⚠")
    color = {"LOW": "green", "MEDIUM": "orange", "HIGH": "red"}[report.risk_level]

    st.markdown(f"## {icon} :{color}[{report.risk_level} RISK]")
    st.metric("Phishing Probability", f"{report.phishing_probability:.0f}%")

    st.markdown("### ✅ Risk Factors")
    if report.risk_factors:
        for f in report.risk_factors:
            st.markdown(f"- ✓ {f.label}")
    else:
        st.write("No risk signals detected.")

    st.markdown("### 🎯 Threat Categories")
    for cat in report.threat_categories:
        st.markdown(f"- {cat}")

    st.markdown("### 📊 Risk Fingerprint")
    for cat in ["URL Structure", "Domain Anomaly", "Suspicious Terms", "Obfuscation"]:
        st.progress(int(report.fingerprint[cat]), text=f"{cat}: {report.fingerprint[cat]:.0f}%")
    st.progress(int(report.overall_risk), text=f"Overall Risk: {report.overall_risk:.0f}%")

    with st.expander("Raw JSON (for API / logging)"):
        st.json(report_to_dict(report))

    st.caption(f"Source: {report.source} — heuristics explain the *why*; the ML model (when connected) drives the *overall risk score*.")
