"""
Module 2: Automated Risk Scoring and Classification Module.
Implements the core cybersecurity scoring engine, integrates with SQLite,
records risk history, and links recommendations.
"""

from typing import List, Dict, Any, Optional
from database import get_db, log_event
from risk_engine import (
    calculate_risk_score,
    classify_risk,
    evaluate_risk_delta,
    validate_score_input
)
from recommendations import generate_recommendations


def perform_assessment(
    asset_id: int,
    vulnerability_id: Optional[int],
    vulnerability_severity: float,
    asset_criticality: float,
    exposure: float,
    security_event_severity: float,
    notes: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes a complete assessment:
    1. Validates all inputs (0-100)
    2. Calculates overall risk score using: R = 0.40V + 0.25A + 0.20E + 0.15S
    3. Classifies risk tier (Low, Medium, High, Critical)
    4. Retrieves previous assessment for the same asset to compute trend & delta
    5. Stores new assessment in `assessments` (Never overwriting older assessments)
    6. Stores entry in `risk_history`
    7. Generates actionable recommendations and stores in `recommendations`
    8. Logs event in `monitoring_logs`
    """
    # 1. Validation
    v_sev = validate_score_input(vulnerability_severity, "Vulnerability Severity (V)")
    a_crit = validate_score_input(asset_criticality, "Asset Criticality (A)")
    exp = validate_score_input(exposure, "Exposure Level (E)")
    s_sev = validate_score_input(security_event_severity, "Security Event Severity (S)")

    # 2. Risk Calculation
    score = calculate_risk_score(v_sev, a_crit, exp, s_sev)
    classification = classify_risk(score)

    conn = get_db()
    cursor = conn.cursor()

    # Verify asset exists and get asset type and name
    cursor.execute("SELECT id, name, asset_type FROM assets WHERE id = ?", (asset_id,))
    asset = cursor.fetchone()
    if not asset:
        conn.close()
        raise ValueError(f"Asset ID #{asset_id} does not exist.")

    asset_name = asset["name"]
    asset_type = asset["asset_type"]

    # 3. Find previous assessment for this asset to compare scores
    cursor.execute("""
        SELECT id, risk_score 
        FROM assessments 
        WHERE asset_id = ? 
        ORDER BY assessment_date DESC, id DESC 
        LIMIT 1
    """, (asset_id,))
    prev_row = cursor.fetchone()

    previous_score = prev_row["risk_score"] if prev_row else None
    diff, trend = evaluate_risk_delta(previous_score, score)

    # 4. Insert new Assessment record
    cursor.execute("""
        INSERT INTO assessments (
            asset_id, vulnerability_id, vulnerability_severity, asset_criticality,
            exposure, security_event_severity, risk_score, risk_level, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        asset_id,
        vulnerability_id,
        v_sev,
        a_crit,
        exp,
        s_sev,
        score,
        classification,
        (notes or '').strip()
    ))
    assessment_id = cursor.lastrowid

    # 5. Insert Risk History record
    cursor.execute("""
        INSERT INTO risk_history (
            asset_id, assessment_id, previous_score, current_score, score_difference, trend
        ) VALUES (?, ?, ?, ?, ?, ?)
    """, (
        asset_id,
        assessment_id,
        previous_score,
        score,
        diff if previous_score is not None else None,
        trend
    ))

    # 6. Generate and save recommendations
    recs = generate_recommendations(score, classification, asset_type)
    for r in recs:
        cursor.execute("""
            INSERT INTO recommendations (assessment_id, risk_level, recommendation_text, priority, status)
            VALUES (?, ?, ?, ?, 'Pending')
        """, (assessment_id, classification, r["text"], r["priority"]))

    conn.commit()
    conn.close()

    # 7. Log event
    log_msg = f"Assessment #{assessment_id} for '{asset_name}': Risk Score {score}/100 ({classification} Risk)."
    if trend in ("Increased", "Decreased"):
        log_msg += f" Trend: Risk {trend} by {abs(diff):.1f} pts."
    log_severity = "CRITICAL" if classification == "Critical" else ("WARNING" if classification == "High" else "INFO")
    log_event("Risk Assessment Completed", log_msg, log_severity)

    return {
        "assessment_id": assessment_id,
        "asset_id": asset_id,
        "asset_name": asset_name,
        "asset_type": asset_type,
        "risk_score": score,
        "risk_level": classification,
        "vulnerability_severity": v_sev,
        "asset_criticality": a_crit,
        "exposure": exp,
        "security_event_severity": s_sev,
        "previous_score": previous_score,
        "score_difference": diff,
        "trend": trend,
        "recommendations": recs
    }


def get_all_assessments(
    risk_level: Optional[str] = None,
    asset_id: Optional[int] = None,
    sort_by: str = "date_desc"
) -> List[Dict[str, Any]]:
    """
    Retrieve all assessment records with linked asset and vulnerability details.
    Allows sorting by risk severity or assessment date, and filtering by category.
    """
    conn = get_db()
    cursor = conn.cursor()

    sql = """
        SELECT asm.*,
               a.name as asset_name, a.asset_type,
               v.name as vulnerability_name, v.status as vulnerability_status,
               rh.previous_score, rh.score_difference, rh.trend
        FROM assessments asm
        JOIN assets a ON asm.asset_id = a.id
        LEFT JOIN vulnerabilities v ON asm.vulnerability_id = v.id
        LEFT JOIN risk_history rh ON asm.id = rh.assessment_id
        WHERE 1=1
    """
    params = []

    if risk_level and risk_level in ('Low', 'Medium', 'High', 'Critical'):
        sql += " AND asm.risk_level = ?"
        params.append(risk_level)

    if asset_id:
        sql += " AND asm.asset_id = ?"
        params.append(asset_id)

    # Sorting
    if sort_by == "risk_desc":
        sql += " ORDER BY asm.risk_score DESC, asm.assessment_date DESC"
    elif sort_by == "risk_asc":
        sql += " ORDER BY asm.risk_score ASC, asm.assessment_date DESC"
    elif sort_by == "asset_name":
        sql += " ORDER BY a.name ASC, asm.assessment_date DESC"
    else:  # default date_desc
        sql += " ORDER BY asm.assessment_date DESC, asm.id DESC"

    cursor.execute(sql, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_assessment_by_id(assessment_id: int) -> Optional[Dict[str, Any]]:
    """
    Retrieve a comprehensive assessment report by its ID, including
    recommendations, formula breakdown, and historical trend.
    """
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT asm.*,
               a.name as asset_name, a.asset_type, a.description as asset_description,
               v.name as vulnerability_name, v.description as vulnerability_desc, v.status as vulnerability_status,
               rh.previous_score, rh.score_difference, rh.trend
        FROM assessments asm
        JOIN assets a ON asm.asset_id = a.id
        LEFT JOIN vulnerabilities v ON asm.vulnerability_id = v.id
        LEFT JOIN risk_history rh ON asm.id = rh.assessment_id
        WHERE asm.id = ?
    """, (assessment_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    assessment = dict(row)

    # Fetch recommendations
    cursor.execute("""
        SELECT * FROM recommendations 
        WHERE assessment_id = ? 
        ORDER BY 
            CASE priority 
                WHEN 'Critical' THEN 1 
                WHEN 'High' THEN 2 
                WHEN 'Medium' THEN 3 
                ELSE 4 
            END, id ASC
    """, (assessment_id,))
    assessment["recommendations"] = [dict(r) for r in cursor.fetchall()]

    # Detailed mathematical breakdown
    v = assessment["vulnerability_severity"]
    a = assessment["asset_criticality"]
    e = assessment["exposure"]
    s = assessment["security_event_severity"]

    assessment["formula_breakdown"] = {
        "v_weighted": round(0.40 * v, 2),
        "a_weighted": round(0.25 * a, 2),
        "e_weighted": round(0.20 * e, 2),
        "s_weighted": round(0.15 * s, 2),
        "formula_str": f"0.40({v}) + 0.25({a}) + 0.20({e}) + 0.15({s})",
        "result": assessment["risk_score"]
    }

    conn.close()
    return assessment
