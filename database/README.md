# PHISHGUARD-AI Database Module

This folder contains the database layer for the PHISHGUARD-AI project.

## Files

### database_schema.sql
Creates the `phishguard_db` database and the `scan_history` table.

### db_connection.py
Provides the MySQL database connection used by the application.

### db_operations.py
Provides functions for storing and retrieving phishing scan information.

## Database Operations

- `save_scan()` - Stores a scan result.
- `get_recent_scans()` - Retrieves recent scan history.
- `get_total_scans()` - Returns the total number of scans.
- `get_scan_statistics()` - Returns scan counts grouped by risk level.
- `get_threat_statistics()` - Returns phishing probability statistics.

## Scan Data

Each scan can contain:

- URL
- Overall risk
- Risk level
- Phishing probability
- Source
- Scan time

## Backend Integration

The Flask backend can import the database operations and use them to store scan results and retrieve dashboard statistics.

Example:

```python
from database.db_operations import save_scan

scan_id = save_scan(
    url,
    overall_risk,
    risk_level,
    phishing_probability,
    source
)
