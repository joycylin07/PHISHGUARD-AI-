# PHISHGUARD-AI Database Integration

The database module provides functions for the Flask backend.

## Available Functions

- save_scan() - Saves a phishing scan.
- get_recent_scans() - Gets recent scan history.
- get_total_scans() - Gets total scan count.
- get_scan_statistics() - Gets risk-level statistics.
- get_threat_statistics() - Gets phishing probability statistics.

## Flask Integration

The existing Flask backend analyzes URLs using the ML model and risk analysis engine.

The database module can be connected to the Flask backend after URL analysis is completed.

The Flask backend should import:

from database.db_operations import save_scan

After the URL is analyzed, the backend can save the result using:

save_scan(
    url=result["url"],
    overall_risk=result["overall_risk"],
    risk_level=result["risk_level"],
    phishing_probability=result["phishing_probability"],
    source=result["source"]
)

The saved information is stored in the MySQL scan_history table.

## Database Fields

The scan_history table stores:

- URL
- Overall risk
- Risk level
- Phishing probability
- Source
- Scan time

## Dashboard

The dashboard can use the database functions to display:

- Total scans
- Recent scans
- Risk levels
- Phishing probability
- Threat statistics

## Dashboard Functions

Recent scan history:

get_recent_scans(10)

Total scans:

get_total_scans()

Risk statistics:

get_scan_statistics()

Threat statistics:

get_threat_statistics()

## Expected Workflow

User enters URL
↓
Flask Backend
↓
ML Prediction
↓
Risk Analysis
↓
Save scan result
↓
MySQL scan_history
↓
Dashboard statistics

## Security

Real database passwords must not be committed to GitHub.

Database credentials should be stored securely using environment variables or another secure configuration method.
