"""
Module 4: Security Monitoring and Risk History Management.
Monitors cybersecurity risk posture, calculates historical score deltas,
identifies trend changes, and provides analytics for visualization.
"""

from typing import List, Dict, Any, Optional
from database import get_db, log_event


def get_system_metrics() -> Dict[str, Any]:
    """
    Computes all core dashboard metrics directly from SQLite database:
    - Total Assets
    - Total Assessments
    - Total Vulnerabilities
    - Open Vulnerabilities
    - Pending Vulnerabilities
    - Resolved Vulnerabilities
    - High Risk Assets
    - Critical Risk Assets
    - Risk Distribution (Low, Medium, High, Critical)
    """
    conn = get_db()
    cursor = conn.cursor()

    # Total Assets
    cursor.execute("SELECT COUNT(*) as count FROM assets")
    total_assets = cursor.fetchone()["count"]

    # Total Assessments
    cursor.execute("SELECT COUNT(*) as count FROM assessments")
    total_assessments = cursor.fetchone()["count"]

    # Total Vulnerabilities
    cursor.execute("SELECT COUNT(*) as count FROM vulnerabilities")
    total_vulns = cursor.fetchone()["count"]

    # Vulnerabilities by Status
    cursor.execute("SELECT COUNT(*) as count FROM vulnerabilities WHERE status = 'Open'")
    open_vulns = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM vulnerabilities WHERE status = 'Pending'")
    pending_vulns = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM vulnerabilities WHERE status = 'Resolved'")
    resolved_vulns = cursor.fetchone()["count"]

    # Risk Distribution across all latest assessments per asset
    cursor.execute("""
        WITH LatestAssessments AS (
            SELECT asm.asset_id, asm.risk_score, asm.risk_level,
                   ROW_NUMBER() OVER(PARTITION BY asm.asset_id ORDER BY asm.assessment_date DESC, asm.id DESC) as rn
            FROM assessments asm
        )
        SELECT 
            SUM(CASE WHEN risk_level = 'Low' THEN 1 ELSE 0 END) as low_count,
            SUM(CASE WHEN risk_level = 'Medium' THEN 1 ELSE 0 END) as med_count,
            SUM(CASE WHEN risk_level = 'High' THEN 1 ELSE 0 END) as high_count,
            SUM(CASE WHEN risk_level = 'Critical' THEN 1 ELSE 0 END) as crit_count
        FROM LatestAssessments
        WHERE rn = 1
    """)
    dist_row = cursor.fetchone()
    low_assets = dist_row["low_count"] or 0
    med_assets = dist_row["med_count"] or 0
    high_assets = dist_row["high_count"] or 0
    crit_assets = dist_row["crit_count"] or 0

    # Unresolved High & Critical assets count
    unresolved_high_crit = high_assets + crit_assets

    conn.close()

    return {
        "total_assets": total_assets,
        "total_assessments": total_assessments,
        "total_vulnerabilities": total_vulns,
        "open_vulnerabilities": open_vulns,
        "pending_vulnerabilities": pending_vulns,
        "resolved_vulnerabilities": resolved_vulns,
        "high_risk_assets": high_assets,
        "critical_risk_assets": crit_assets,
        "unresolved_high_crit": unresolved_high_crit,
        "risk_distribution": {
            "Low": low_assets,
            "Medium": med_assets,
            "High": high_assets,
            "Critical": crit_assets
        }
    }


def get_unresolved_risks() -> List[Dict[str, Any]]:
    """
    Identifies unresolved High and Critical risks:
    Vulnerabilities with status != 'Resolved' linked to High or Critical assessments or severities.
    """
    conn = get_db()
    cursor = conn.cursor()

    sql = """
        SELECT v.id as vuln_id, v.name as vuln_name, v.severity as vuln_severity, v.status,
               a.id as asset_id, a.name as asset_name, a.asset_type, a.criticality as asset_criticality,
               asm.id as assessment_id, asm.risk_score, asm.risk_level, asm.assessment_date
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.id
        LEFT JOIN assessments asm ON asm.vulnerability_id = v.id
        WHERE v.status != 'Resolved'
          AND (v.severity >= 50.0 OR (asm.risk_score IS NOT NULL AND asm.risk_score >= 50.0))
        ORDER BY 
            CASE WHEN asm.risk_level = 'Critical' THEN 1
                 WHEN asm.risk_level = 'High' THEN 2
                 ELSE 3
            END,
            COALESCE(asm.risk_score, v.severity) DESC
    """
    cursor.execute(sql)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_risk_history_records(asset_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Retrieve historical risk records showing score comparison (previous vs current),
    difference, and trend (Increased, Decreased, Unchanged, Initial) for the same asset.
    """
    conn = get_db()
    cursor = conn.cursor()

    sql = """
        SELECT rh.id, rh.asset_id, rh.assessment_id, rh.previous_score, rh.current_score,
               rh.score_difference, rh.trend, rh.recorded_at,
               a.name as asset_name, a.asset_type,
               asm.risk_level, asm.vulnerability_severity, asm.exposure, asm.security_event_severity,
               v.name as vuln_name
        FROM risk_history rh
        JOIN assets a ON rh.asset_id = a.id
        JOIN assessments asm ON rh.assessment_id = asm.id
        LEFT JOIN vulnerabilities v ON asm.vulnerability_id = v.id
        WHERE 1=1
    """
    params = []

    if asset_id:
        sql += " AND rh.asset_id = ?"
        params.append(asset_id)

    sql += " ORDER BY rh.recorded_at DESC, rh.id DESC"

    cursor.execute(sql, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_trend_chart_data() -> Dict[str, Any]:
    """
    Generates time-series data for Chart.js historical risk trend line chart.
    """
    conn = get_db()
    cursor = conn.cursor()

    # Get chronological assessments (last 15 records)
    cursor.execute("""
        SELECT asm.id, asm.assessment_date, asm.risk_score, asm.risk_level,
               a.name as asset_name
        FROM assessments asm
        JOIN assets a ON asm.asset_id = a.id
        ORDER BY asm.assessment_date ASC, asm.id ASC
        LIMIT 20
    """)
    rows = cursor.fetchall()
    conn.close()

    labels = []
    scores = []
    asset_labels = []
    colors = []

    for r in rows:
        # Format label as "Asset (Date)"
        date_str = str(r["assessment_date"]).split(" ")[0]
        labels.append(f"{r['asset_name']} ({date_str})")
        scores.append(r["risk_score"])
        asset_labels.append(r["asset_name"])

        level = r["risk_level"]
        if level == "Critical":
            colors.append("#ef4444")
        elif level == "High":
            colors.append("#f97316")
        elif level == "Medium":
            colors.append("#f59e0b")
        else:
            colors.append("#10b981")

    return {
        "labels": labels,
        "scores": scores,
        "asset_labels": asset_labels,
        "colors": colors
    }


def get_monitoring_logs(limit: int = 25) -> List[Dict[str, Any]]:
    """
    Retrieve recent activity and security event monitoring logs.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM monitoring_logs
        ORDER BY timestamp DESC, id DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows
