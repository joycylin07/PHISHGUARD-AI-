from flask import Flask, request, jsonify
import sys
import os

# Add ML model folder to Python path
ML_MODEL_PATH = os.path.join(os.path.dirname(__file__), "ml-model")
sys.path.insert(0, ML_MODEL_PATH)

# Add Risk Analysis folder to Python path
RISK_ENGINE_PATH = os.path.join(
    os.path.dirname(__file__),
    "phishing risk analysis"
)
sys.path.insert(0, RISK_ENGINE_PATH)

from predict import predict_domain
from risk_engine import analyze_url, report_to_dict

app = Flask(__name__)


@app.route("/")
def home():
    return jsonify({
        "status": "running",
        "message": "PhishGuard AI Backend is running"
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()

        if not data or "url" not in data:
            return jsonify({
                "error": "URL is required"
            }), 400

        url = data["url"].strip()

        if not url:
            return jsonify({
                "error": "URL cannot be empty"
            }), 400

        # Remove protocol for the ML domain predictor
        domain = url

        if "://" in domain:
            domain = domain.split("://", 1)[1]

        domain = domain.split("/", 1)[0]
        domain = domain.split("?", 1)[0]

        # Step 1: ML prediction
        ml_result = predict_domain(domain)

        # Step 2: Risk Analysis using ML probability
        risk_report = analyze_url(
            url,
            ml_probability=ml_result["probability"]
        )

        # Step 3: Convert risk report to JSON
        result = report_to_dict(risk_report)

        # Include ML prediction details
        result["ml_prediction"] = ml_result["prediction"]
        result["ml_probability"] = ml_result["probability"]
        result["extracted_features"] = ml_result["extracted_features"]

        return jsonify(result)

    except ValueError as e:
        return jsonify({
            "error": str(e)
        }), 400

    except Exception as e:
        return jsonify({
            "error": "An error occurred while analyzing the URL.",
            "details": str(e)
        }), 500


if __name__ == "__main__":
    app.run(debug=True)