from database.db_operations import save_scan


def save_analysis_result(result):
    """
    Save a completed PhishGuard AI analysis result
    into the database.
    """

    scan_id = save_scan(
        url=result["url"],
        overall_risk=result["overall_risk"],
        risk_level=result["risk_level"],
        phishing_probability=result["phishing_probability"],
        source=result["source"]
    )

    return scan_id
