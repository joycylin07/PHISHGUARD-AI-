import os
import joblib
import pandas as pd
from feature_extraction import extract_domain_features, FEATURE_NAMES

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(BASE_DIR, "model", "phishing_model.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "model", "model_features.pkl")

if not os.path.exists(MODEL_PATH) or not os.path.exists(FEATURES_PATH):
    raise FileNotFoundError("Model files missing. Please run train_model.py first.")

# Load model and feature order once
model = joblib.load(MODEL_PATH)
model_features = joblib.load(FEATURES_PATH)

def predict_domain(domain: str, raw_features: dict = None) -> dict:
    """
    Predicts whether a domain is phishing or legitimate.
    Combines input features with extracted domain string features.
    """
    domain_feats = extract_domain_features(domain)
    
    combined_dict = raw_features.copy() if raw_features else {}
    combined_dict.update(domain_feats)

    # Align features strictly to training order
    feature_vector = [combined_dict.get(f, 0) for f in model_features]
    input_df = pd.DataFrame([feature_vector], columns=model_features)

    prob = float(model.predict_proba(input_df)[0][1])
    pred_class = int(model.predict(input_df)[0])

    return {
        "domain": domain,
        "prediction": "phishing" if pred_class == 1 else "legitimate",
        "probability": round(prob, 4),
        "extracted_features": combined_dict
    }

if __name__ == "__main__":
    test_res = predict_domain("paypal-account-verify.xyz")
    print("\n--- Test Prediction ---")
    print(f"Domain     : {test_res['domain']}")
    print(f"Prediction : {test_res['prediction']}")
    print(f"Probability: {test_res['probability']}")