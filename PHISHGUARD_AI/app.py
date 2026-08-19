from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    return render_template("index.html")


# ============================================================
# LOGIN
# ============================================================

@app.route("/login")
def login():
    return render_template("login.html")


# ============================================================
# LOGIN PROCESS
# ============================================================

@app.route("/login", methods=["POST"])
def login_process():

    # Temporary frontend login
    # Real authentication can be added later.

    return redirect(url_for("dashboard"))


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# ============================================================
# ANALYZE URL
# ============================================================

@app.route("/analyze", methods=["POST"])
def analyze():

    url = request.form.get("url", "").strip()

    if not url:
        return redirect(url_for("dashboard"))

    # --------------------------------------------------------
    # TEMPORARY DEMO RESULT
    # --------------------------------------------------------
    #
    # Later this section will call your actual ML model.
    #

    result = {
        "url": url,
        "prediction": "Suspicious",
        "risk_score": 78,
        "confidence": 94,

        "risk_factors": [
            "Suspicious URL structure",
            "Unusual domain pattern",
            "Elevated risk signals"
        ],

        "recommendation":
            "Avoid entering passwords, OTPs, "
            "banking details, payment information, "
            "or other sensitive information until "
            "the website has been verified."
    }

    return render_template(
        "result.html",
        result=result
    )


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":
    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )