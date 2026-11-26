"""
Module 1: Asset and Vulnerability Assessment.
Handles asset registration, vulnerability tracking, input validation,
and database persistence in SQLite.
"""

from typing import List, Dict, Any, Optional
from database import get_db, log_event
from risk_engine import validate_score_input

VALID_ASSET_TYPES = ['Server', 'Computer', 'Network', 'Database', 'Application', 'Other']
VALID_VULN_STATUSES = ['Open', 'Pending', 'Resolved']


# ==========================================
# ASSET OPERATIONS
# ==========================================

def get_all_assets(search_query: Optional[str] = None, asset_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieve all assets with optional filtering and latest risk score.
    """
    conn = get_db()
    cursor = conn.cursor()

    sql = """
        SELECT a.id, a.name, a.asset_type, a.description, a.criticality, 
               a.created_at, a.updated_at,
               COUNT(DISTINCT v.id) as vuln_count,
               (
                   SELECT asm.risk_score 
                   FROM assessments asm 
                   WHERE asm.asset_id = a.id 
                   ORDER BY asm.assessment_date DESC, asm.id DESC 
                   LIMIT 1
               ) as latest_risk_score,
               (
                   SELECT asm.risk_level 
                   FROM assessments asm 
                   WHERE asm.asset_id = a.id 
                   ORDER BY asm.assessment_date DESC, asm.id DESC 
                   LIMIT 1
               ) as latest_risk_level
        FROM assets a
        LEFT JOIN vulnerabilities v ON a.id = v.asset_id
        WHERE 1=1
    """
    params = []

    if search_query:
        sql += " AND (a.name LIKE ? OR a.description LIKE ?)"
        q = f"%{search_query.strip()}%"
        params.extend([q, q])

    if asset_type and asset_type in VALID_ASSET_TYPES:
        sql += " AND a.asset_type = ?"
        params.append(asset_type)

    sql += " GROUP BY a.id ORDER BY a.name ASC"

    cursor.execute(sql, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_asset_by_id(asset_id: int) -> Optional[Dict[str, Any]]:
    """
    Retrieve a single asset by its ID, including its vulnerabilities and assessments.
    """
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM assets WHERE id = ?", (asset_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    asset = dict(row)

    # Fetch associated vulnerabilities
    cursor.execute("""
        SELECT * FROM vulnerabilities 
        WHERE asset_id = ? 
        ORDER BY severity DESC, created_at DESC
    """, (asset_id,))
    asset["vulnerabilities"] = [dict(r) for r in cursor.fetchall()]

    # Fetch associated assessments
    cursor.execute("""
        SELECT a.*, v.name as vuln_name 
        FROM assessments a
        LEFT JOIN vulnerabilities v ON a.vulnerability_id = v.id
        WHERE a.asset_id = ?
        ORDER BY a.assessment_date DESC, a.id DESC
    """, (asset_id,))
    asset["assessments"] = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return asset


def create_asset(name: str, asset_type: str, description: str, criticality: float) -> int:
    """
    Validate and insert a new asset into SQLite.
    """
    if not name or not name.strip():
        raise ValueError("Asset Name cannot be empty.")
    name = name.strip()

    if asset_type not in VALID_ASSET_TYPES:
        raise ValueError(f"Invalid Asset Type '{asset_type}'. Must be one of: {', '.join(VALID_ASSET_TYPES)}")

    crit = validate_score_input(criticality, "Asset Criticality")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO assets (name, asset_type, description, criticality)
        VALUES (?, ?, ?, ?)
    """, (name, asset_type, (description or '').strip(), crit))
    asset_id = cursor.lastrowid
    conn.commit()
    conn.close()

    log_event("Asset Created", f"New asset '{name}' ({asset_type}) registered with criticality {crit}.", "INFO")
    return asset_id


def update_asset(asset_id: int, name: str, asset_type: str, description: str, criticality: float) -> bool:
    """
    Validate and update an existing asset in SQLite.
    """
    if not name or not name.strip():
        raise ValueError("Asset Name cannot be empty.")
    name = name.strip()

    if asset_type not in VALID_ASSET_TYPES:
        raise ValueError(f"Invalid Asset Type '{asset_type}'. Must be one of: {', '.join(VALID_ASSET_TYPES)}")

    crit = validate_score_input(criticality, "Asset Criticality")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE assets
        SET name = ?, asset_type = ?, description = ?, criticality = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (name, asset_type, (description or '').strip(), crit, asset_id))
    affected = cursor.rowcount
    conn.commit()
    conn.close()

    if affected > 0:
        log_event("Asset Updated", f"Asset #{asset_id} '{name}' updated (Criticality: {crit}).", "INFO")
        return True
    return False


def delete_asset(asset_id: int) -> bool:
    """
    Delete an asset and cascade delete associated records.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM assets WHERE id = ?", (asset_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False
    asset_name = row["name"]

    cursor.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()

    if affected > 0:
        log_event("Asset Deleted", f"Asset '{asset_name}' (ID #{asset_id}) was removed from the system.", "WARNING")
        return True
    return False


# ==========================================
# VULNERABILITY OPERATIONS
# ==========================================

def get_all_vulnerabilities(status: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieve vulnerabilities with their associated asset name and type.
    """
    conn = get_db()
    cursor = conn.cursor()

    sql = """
        SELECT v.id, v.asset_id, v.name, v.description, v.severity, v.status,
               v.created_at, v.updated_at,
               a.name as asset_name, a.asset_type, a.criticality as asset_criticality
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.id
        WHERE 1=1
    """
    params = []

    if status and status in VALID_VULN_STATUSES:
        sql += " AND v.status = ?"
        params.append(status)

    if search:
        sql += " AND (v.name LIKE ? OR v.description LIKE ? OR a.name LIKE ?)"
        s = f"%{search.strip()}%"
        params.extend([s, s, s])

    sql += " ORDER BY v.severity DESC, v.created_at DESC"

    cursor.execute(sql, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_vulnerability_by_id(vuln_id: int) -> Optional[Dict[str, Any]]:
    """
    Get a single vulnerability by ID with asset details.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT v.*, a.name as asset_name, a.asset_type, a.criticality as asset_criticality
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.id
        WHERE v.id = ?
    """, (vuln_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def create_vulnerability(asset_id: int, name: str, description: str, severity: float, status: str = "Open") -> int:
    """
    Create a vulnerability linked to an asset.
    """
    if not name or not name.strip():
        raise ValueError("Vulnerability Name cannot be empty.")
    name = name.strip()

    sev = validate_score_input(severity, "Vulnerability Severity")

    if status not in VALID_VULN_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Must be one of: {', '.join(VALID_VULN_STATUSES)}")

    conn = get_db()
    cursor = conn.cursor()

    # Ensure asset exists
    cursor.execute("SELECT id, name FROM assets WHERE id = ?", (asset_id,))
    asset = cursor.fetchone()
    if not asset:
        conn.close()
        raise ValueError(f"Asset ID #{asset_id} does not exist.")

    cursor.execute("""
        INSERT INTO vulnerabilities (asset_id, name, description, severity, status)
        VALUES (?, ?, ?, ?, ?)
    """, (asset_id, name, (description or '').strip(), sev, status))
    vuln_id = cursor.lastrowid
    conn.commit()
    conn.close()

    log_event("Vulnerability Logged", 
              f"Vulnerability '{name}' (Severity: {sev}) recorded for asset '{asset['name']}'.",
              "WARNING" if sev >= 75 else "INFO")
    return vuln_id


def update_vulnerability(vuln_id: int, asset_id: int, name: str, description: str, severity: float, status: str) -> bool:
    """
    Update vulnerability details.
    """
    if not name or not name.strip():
        raise ValueError("Vulnerability Name cannot be empty.")
    name = name.strip()

    sev = validate_score_input(severity, "Vulnerability Severity")

    if status not in VALID_VULN_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Must be one of: {', '.join(VALID_VULN_STATUSES)}")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE vulnerabilities
        SET asset_id = ?, name = ?, description = ?, severity = ?, status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (asset_id, name, (description or '').strip(), sev, status, vuln_id))
    affected = cursor.rowcount
    conn.commit()
    conn.close()

    if affected > 0:
        log_event("Vulnerability Updated", f"Vulnerability #{vuln_id} updated: {name} (Status: {status}).", "INFO")
        return True
    return False


def update_vulnerability_status(vuln_id: int, status: str) -> bool:
    """
    Quick status update for vulnerability (e.g. Open -> Pending -> Resolved).
    """
    if status not in VALID_VULN_STATUSES:
        raise ValueError(f"Invalid status '{status}'.")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE vulnerabilities
        SET status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (status, vuln_id))
    affected = cursor.rowcount
    conn.commit()
    conn.close()

    if affected > 0:
        log_event("Vulnerability Status Changed", f"Vulnerability #{vuln_id} status changed to '{status}'.", 
                  "SUCCESS" if status == "Resolved" else "INFO")
        return True
    return False


def delete_vulnerability(vuln_id: int) -> bool:
    """
    Delete a vulnerability record.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM vulnerabilities WHERE id = ?", (vuln_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False
    vuln_name = row["name"]

    cursor.execute("DELETE FROM vulnerabilities WHERE id = ?", (vuln_id,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()

    if affected > 0:
        log_event("Vulnerability Deleted", f"Vulnerability '{vuln_name}' (ID #{vuln_id}) deleted.", "INFO")
        return True
    return False
