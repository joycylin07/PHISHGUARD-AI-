from .db_connection import get_connection


def save_scan(url, overall_risk, risk_level, phishing_probability, source=None):
    """
    Save a phishing scan result into the scan_history table.
    """

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

    finally:
        cursor.close()
        connection.close()


def get_recent_scans(limit=10):
    """
    Get the most recent scan records.
    """

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
    """
    Return the total number of scans.
    """

    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            "SELECT COUNT(*) FROM scan_history"
        )

        result = cursor.fetchone()

        return result[0]

    finally:
        cursor.close()
        connection.close()


def get_scan_statistics():
    """
    Return scan counts grouped by risk level.
    """

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
    """
    Return phishing probability statistics.
    """

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