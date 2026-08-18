from .db_connection import get_connection


def save_scan(url, overall_risk, risk_level, phishing_probability, source=None):
    """Save a phishing scan result."""

    connection = get_connection()
    cursor = connection.cursor()

    query = """
        INSERT INTO scan_history
        (url, overall_risk, risk_level, phishing_probability, source)
        VALUES (%s, %s, %s, %s, %s)
    """

    values = (
        url,
        overall_risk,
        risk_level,
        phishing_probability,
        source
    )

    try:
        cursor.execute(query, values)
        connection.commit()
        return cursor.lastrowid

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


def get_recent_scans(limit=10):
    """Return the most recent scan records."""

    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        limit = int(limit)

        if limit <= 0:
            limit = 10

        query = f"""
            SELECT
                scan_id,
                url,
                overall_risk,
                risk_level,
                phishing_probability,
                source,
                scan_time
            FROM scan_history
            ORDER BY scan_time DESC
            LIMIT {limit}
        """

        cursor.execute(query)
        return cursor.fetchall()

    finally:
        cursor.close()
        connection.close()


def get_total_scans():
    """Return the total number of scans."""

    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT COUNT(*) FROM scan_history")
        result = cursor.fetchone()
        return result[0]

    finally:
        cursor.close()
        connection.close()


def get_scan_statistics():
    """Return scan counts grouped by risk level."""

    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        query = """
            SELECT
                risk_level,
                COUNT(*) AS count
            FROM scan_history
            GROUP BY risk_level
            ORDER BY count DESC
        """

        cursor.execute(query)
        return cursor.fetchall()

    finally:
        cursor.close()
        connection.close()


def get_threat_statistics():
    """Return phishing probability statistics."""

    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        query = """
            SELECT
                COUNT(*) AS total_scans,
                AVG(phishing_probability) AS average_probability,
                MAX(phishing_probability) AS highest_probability,
                MIN(phishing_probability) AS lowest_probability
            FROM scan_history
        """

        cursor.execute(query)
        return cursor.fetchone()

    finally:
        cursor.close()
        connection.close()

def get_dashboard_statistics():
    """Return summary statistics for the security dashboard."""

    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        query = """
            SELECT
                COUNT(*) AS total_scans,
                SUM(CASE WHEN risk_level = 'Safe' THEN 1 ELSE 0 END) AS safe_scans,
                SUM(CASE WHEN risk_level = 'Low' THEN 1 ELSE 0 END) AS low_risk_scans,
                SUM(CASE WHEN risk_level = 'Medium' THEN 1 ELSE 0 END) AS medium_risk_scans,
                SUM(CASE WHEN risk_level = 'High' THEN 1 ELSE 0 END) AS high_risk_scans
            FROM scan_history
        """

        cursor.execute(query)

        return cursor.fetchone()

    finally:
        cursor.close()
        connection.close()

def get_dashboard_recent_scans(limit=10):
    """Return recent scans for the security dashboard."""

    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        limit = int(limit)

        if limit <= 0:
            limit = 10

        query = f"""
            SELECT
                scan_id,
                url,
                overall_risk,
                risk_level,
                phishing_probability,
                source,
                scan_time
            FROM scan_history
            ORDER BY scan_time DESC
            LIMIT {limit}
        """

        cursor.execute(query)

        return cursor.fetchall()

    finally:
        cursor.close()
        connection.close()

def get_risk_distribution():
    """Return risk-level distribution for dashboard charts."""

    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        query = """
            SELECT
                risk_level,
                COUNT(*) AS scan_count
            FROM scan_history
            GROUP BY risk_level
            ORDER BY scan_count DESC
        """

        cursor.execute(query)

        return cursor.fetchall()

    finally:
        cursor.close()
        connection.close()
