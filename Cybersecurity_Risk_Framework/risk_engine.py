"""
Module 2: Automated Risk Scoring and Classification Engine.
Implements the exact weighted cybersecurity risk scoring formula:
    R = 0.40V + 0.25A + 0.20E + 0.15S
where:
    R = Overall Risk Score (0-100)
    V = Vulnerability Severity (0-100)
    A = Asset Criticality (0-100)
    E = Exposure Level (0-100)
    S = Security Event Severity (0-100)
"""

from typing import Tuple, Dict, Any


def validate_score_input(value: Any, field_name: str) -> float:
    """
    Validates that the input is a valid numerical float between 0 and 100.
    Raises ValueError with descriptive message if validation fails.
    """
    if value is None or str(value).strip() == "":
        raise ValueError(f"{field_name} is required.")
    
    try:
        num = float(value)
    except (ValueError, TypeError):
        raise ValueError(f"{field_name} must be a valid number.")

    if num < 0.0 or num > 100.0:
        raise ValueError(f"{field_name} must be between 0 and 100. Received: {num}")

    return round(num, 2)


def calculate_risk_score(
    vulnerability_severity: float,
    asset_criticality: float,
    exposure: float,
    security_event_severity: float
) -> float:
    """
    Calculate the overall risk score using the weighted formula:
    R = 0.40V + 0.25A + 0.20E + 0.15S
    Returns score rounded to 2 decimal places.
    """
    v = validate_score_input(vulnerability_severity, "Vulnerability Severity (V)")
    a = validate_score_input(asset_criticality, "Asset Criticality (A)")
    e = validate_score_input(exposure, "Exposure Level (E)")
    s = validate_score_input(security_event_severity, "Security Event Severity (S)")

    # Weighted formula calculation
    raw_score = (0.40 * v) + (0.25 * a) + (0.20 * e) + (0.15 * s)
    # Bound between 0.0 and 100.0
    bounded_score = max(0.0, min(100.0, raw_score))
    return round(bounded_score, 2)


def classify_risk(risk_score: float) -> str:
    """
    Classify risk score into one of four tiers:
    0–24   = Low Risk
    25–49  = Medium Risk
    50–74  = High Risk
    75–100 = Critical Risk
    """
    if risk_score < 25.0:
        return "Low"
    elif risk_score < 50.0:
        return "Medium"
    elif risk_score < 75.0:
        return "High"
    else:
        return "Critical"


def get_risk_meta(risk_level: str) -> Dict[str, str]:
    """
    Returns visual badge classes, hex colors, and descriptions for risk levels.
    """
    mapping = {
        "Low": {
            "color": "#10b981",       # Emerald green
            "badge_class": "bg-success text-white",
            "border_class": "border-success",
            "text_class": "text-success",
            "description": "Routine security baseline; low immediate operational threat.",
            "icon": "bi-shield-check"
        },
        "Medium": {
            "color": "#f59e0b",       # Amber yellow
            "badge_class": "bg-warning text-dark",
            "border_class": "border-warning",
            "text_class": "text-warning",
            "description": "Noticeable vulnerability; requires scheduled maintenance.",
            "icon": "bi-shield-exclamation"
        },
        "High": {
            "color": "#f97316",       # Bright orange
            "badge_class": "bg-orange text-white",
            "border_class": "border-orange",
            "text_class": "text-orange",
            "description": "Severe threat; proactive remediation required promptly.",
            "icon": "bi-exclamation-triangle"
        },
        "Critical": {
            "color": "#ef4444",       # Vivid red
            "badge_class": "bg-danger text-white",
            "border_class": "border-danger",
            "text_class": "text-danger",
            "description": "Immediate critical exposure; incident response action required.",
            "icon": "bi-radioactive"
        }
    }
    return mapping.get(risk_level, mapping["Low"])


def evaluate_risk_delta(previous_score: float, current_score: float) -> Tuple[float, str]:
    """
    Calculate difference and determine trend between assessments for the same asset.
    Difference = current_score - previous_score
    Returns (score_difference, trend_string):
      - diff > 0 => 'Increased' ('Risk Increased')
      - diff < 0 => 'Decreased' ('Risk Decreased')
      - diff == 0 => 'Unchanged' ('Risk Unchanged')
    """
    if previous_score is None:
        return 0.0, "Initial"
    
    diff = round(current_score - previous_score, 2)
    if diff > 0:
        trend = "Increased"
    elif diff < 0:
        trend = "Decreased"
    else:
        trend = "Unchanged"

    return diff, trend
