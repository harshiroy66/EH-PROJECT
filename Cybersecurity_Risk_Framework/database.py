"""
Database Module for Automated Cybersecurity Risk Scoring Framework.
Manages SQLite database connections, schema initialization, and sample data.
"""

import sqlite3
import os
from datetime import datetime

DATABASE_NAME = "cybersecurity.db"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, DATABASE_NAME)


def get_db():
    """
    Get a database connection configured with Row factory and foreign keys enabled.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """
    Initialize the database tables if they do not exist.
    """
    conn = get_db()
    cursor = conn.cursor()

    # 1. Assets Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        asset_type TEXT NOT NULL CHECK(asset_type IN ('Server', 'Computer', 'Network', 'Database', 'Application', 'Other')),
        description TEXT,
        criticality REAL NOT NULL CHECK(criticality >= 0 AND criticality <= 100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 2. Vulnerabilities Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        severity REAL NOT NULL CHECK(severity >= 0 AND severity <= 100),
        status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open', 'Pending', 'Resolved')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
    );
    """)

    # 3. Assessments Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS assessments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER NOT NULL,
        vulnerability_id INTEGER,
        vulnerability_severity REAL NOT NULL CHECK(vulnerability_severity >= 0 AND vulnerability_severity <= 100),
        asset_criticality REAL NOT NULL CHECK(asset_criticality >= 0 AND asset_criticality <= 100),
        exposure REAL NOT NULL CHECK(exposure >= 0 AND exposure <= 100),
        security_event_severity REAL NOT NULL CHECK(security_event_severity >= 0 AND security_event_severity <= 100),
        risk_score REAL NOT NULL CHECK(risk_score >= 0 AND risk_score <= 100),
        risk_level TEXT NOT NULL CHECK(risk_level IN ('Low', 'Medium', 'High', 'Critical')),
        notes TEXT,
        assessment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
        FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE SET NULL
    );
    """)

    # 4. Recommendations Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS recommendations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        assessment_id INTEGER NOT NULL,
        risk_level TEXT NOT NULL CHECK(risk_level IN ('Low', 'Medium', 'High', 'Critical')),
        recommendation_text TEXT NOT NULL,
        priority TEXT NOT NULL CHECK(priority IN ('Low', 'Medium', 'High', 'Critical')),
        status TEXT DEFAULT 'Pending' CHECK(status IN ('Pending', 'In Progress', 'Implemented')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
    );
    """)

    # 5. Risk History Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS risk_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER NOT NULL,
        assessment_id INTEGER NOT NULL,
        previous_score REAL,
        current_score REAL NOT NULL,
        score_difference REAL,
        trend TEXT NOT NULL CHECK(trend IN ('Increased', 'Decreased', 'Unchanged', 'Initial')),
        recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
        FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
    );
    """)

    # 6. Monitoring Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS monitoring_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'INFO' CHECK(severity IN ('INFO', 'WARNING', 'CRITICAL', 'SUCCESS')),
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()
    conn.close()


def log_event(event_type: str, description: str, severity: str = "INFO"):
    """
    Log an event into monitoring_logs.
    """
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO monitoring_logs (event_type, description, severity) VALUES (?, ?, ?)",
            (event_type, description, severity)
        )
        conn.commit()
    except Exception as e:
        print(f"Failed to log event: {e}")
    finally:
        conn.close()


def seed_sample_data():
    """
    Populate database with sample assets, vulnerabilities, assessments,
    and history records matching the specification (including Section 14 sample).
    """
    conn = get_db()
    cursor = conn.cursor()

    # Check if already seeded
    cursor.execute("SELECT COUNT(*) as count FROM assets")
    if cursor.fetchone()["count"] > 0:
        conn.close()
        return

    # Seed Sample Assets representing Low, Medium, High, and Critical scenarios
    sample_assets = [
        ("Server A", "Server", "Primary Production Application Server", 90.0),
        ("Firewall-01", "Network", "Perimeter Enterprise Firewall Router", 85.0),
        ("User-Workstation-12", "Computer", "Finance Dept Desktop Workstation", 40.0),
        ("Customer-DB-Primary", "Database", "Core Relational Database with PII", 95.0),
        ("Internal-Wiki", "Application", "Internal Knowledge Base Platform", 30.0),
        ("Backup-NAS-01", "Other", "Secondary Backup Storage Appliance", 60.0),
    ]

    for name, asset_type, desc, crit in sample_assets:
        cursor.execute(
            "INSERT INTO assets (name, asset_type, description, criticality) VALUES (?, ?, ?, ?)",
            (name, asset_type, desc, crit)
        )
    conn.commit()

    # Seed Sample Vulnerabilities
    # Fetch asset IDs
    cursor.execute("SELECT id, name FROM assets")
    asset_map = {row["name"]: row["id"] for row in cursor.fetchall()}

    sample_vulns = [
        # Server A (id from map)
        (asset_map["Server A"], "Remote Code Execution (CVE-2024-38077)", "Critical buffer overflow in Windows RPC runtime service", 80.0, "Open"),
        (asset_map["Server A"], "Outdated SSL/TLS Cipher Suites", "Server supports weak 3DES cipher suites", 45.0, "Pending"),
        # Firewall-01
        (asset_map["Firewall-01"], "Authentication Bypass on Management Interface", "Improper input handling in admin portal API", 88.0, "Open"),
        # User-Workstation-12
        (asset_map["User-Workstation-12"], "Unpatched PDF Reader Vulnerability", "Arbitrary memory corruption via crafted PDF document", 50.0, "Resolved"),
        # Customer-DB-Primary
        (asset_map["Customer-DB-Primary"], "SQL Injection in Reporting View", "Unsanitized user input concatenated into query string", 92.0, "Open"),
        # Internal-Wiki
        (asset_map["Internal-Wiki"], "Stored Cross-Site Scripting (XSS)", "User comment field does not sanitize HTML tags", 35.0, "Resolved"),
    ]

    for asset_id, name, desc, sev, status in sample_vulns:
        cursor.execute(
            "INSERT INTO vulnerabilities (asset_id, name, description, severity, status) VALUES (?, ?, ?, ?, ?)",
            (asset_id, name, desc, sev, status)
        )
    conn.commit()

    # Fetch vuln IDs
    cursor.execute("SELECT id, name, asset_id FROM vulnerabilities")
    vuln_rows = cursor.fetchall()
    server_a_vuln = next(v for v in vuln_rows if v["name"].startswith("Remote Code Execution"))

    # MODULE 2 & 4 Requirement:
    # Asset Name: Server A, Asset Type: Server, Asset Criticality: 90
    # Vulnerability Severity: 80, Exposure: 70, Security Event Severity: 60
    # Formula: R = 0.40(80) + 0.25(90) + 0.20(70) + 0.15(60) = 32 + 22.5 + 14 + 9 = 77.5
    # Category = Critical
    from risk_engine import calculate_risk_score, classify_risk
    from recommendations import generate_recommendations

    server_a_id = asset_map["Server A"]
    v_sev = 80.0
    a_crit = 90.0
    exp = 70.0
    s_sev = 60.0
    score_1 = calculate_risk_score(v_sev, a_crit, exp, s_sev) # 77.5
    level_1 = classify_risk(score_1) # Critical

    cursor.execute("""
        INSERT INTO assessments 
        (asset_id, vulnerability_id, vulnerability_severity, asset_criticality, exposure, security_event_severity, risk_score, risk_level, notes, assessment_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '-7 days'))
    """, (server_a_id, server_a_vuln["id"], v_sev, a_crit, exp, s_sev, score_1, level_1, "Initial baseline assessment during routine audit"))
    assessment_1_id = cursor.lastrowid

    # Record first history for Server A
    cursor.execute("""
        INSERT INTO risk_history (asset_id, assessment_id, previous_score, current_score, score_difference, trend, recorded_at)
        VALUES (?, ?, NULL, ?, NULL, 'Initial', datetime('now', '-7 days'))
    """, (server_a_id, assessment_1_id, score_1))

    # Add recommendations for Assessment 1
    recs_1 = generate_recommendations(score_1, level_1, "Server")
    for r in recs_1:
        cursor.execute("""
            INSERT INTO recommendations (assessment_id, risk_level, recommendation_text, priority, status)
            VALUES (?, ?, ?, ?, 'Pending')
        """, (assessment_1_id, level_1, r["text"], r["priority"]))

    # Specification Section 7 Example:
    # Asset: Server A
    # Previous Risk Score: 77.5
    # Current Risk Score: 45
    # Difference: -32.5
    # Display: Risk Decreased
    # Let's create this second assessment for Server A!
    # With V=40, A=90, E=30, S=10 -> R = 0.40(40) + 0.25(90) + 0.20(30) + 0.15(10) = 16 + 22.5 + 6 + 1.5 = 46.0
    # To get exact 45.0: V=40, A=90, E=25, S=10 -> 0.40*40 (16) + 0.25*90 (22.5) + 0.20*25 (5) + 0.15*10 (1.5) = 45.0!
    score_2 = calculate_risk_score(40.0, 90.0, 25.0, 10.0) # 45.0
    level_2 = classify_risk(score_2) # Medium
    diff_2 = round(score_2 - score_1, 2) # -32.5

    cursor.execute("""
        INSERT INTO assessments 
        (asset_id, vulnerability_id, vulnerability_severity, asset_criticality, exposure, security_event_severity, risk_score, risk_level, notes, assessment_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '-1 days'))
    """, (server_a_id, server_a_vuln["id"], 40.0, 90.0, 25.0, 10.0, score_2, level_2, "Follow-up assessment after patch deployment and port shielding"))
    assessment_2_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO risk_history (asset_id, assessment_id, previous_score, current_score, score_difference, trend, recorded_at)
        VALUES (?, ?, ?, ?, ?, 'Decreased', datetime('now', '-1 days'))
    """, (server_a_id, assessment_2_id, score_1, score_2, diff_2))

    recs_2 = generate_recommendations(score_2, level_2, "Server")
    for r in recs_2:
        cursor.execute("""
            INSERT INTO recommendations (assessment_id, risk_level, recommendation_text, priority, status)
            VALUES (?, ?, ?, ?, 'In Progress')
        """, (assessment_2_id, level_2, r["text"], r["priority"]))

    # Additional sample assessment for Database (Critical)
    db_vuln = next(v for v in vuln_rows if v["name"].startswith("SQL Injection"))
    score_db = calculate_risk_score(92.0, 95.0, 80.0, 75.0) # 0.40*92 (36.8) + 0.25*95 (23.75) + 0.20*80 (16) + 0.15*75 (11.25) = 87.8 -> Critical
    level_db = classify_risk(score_db)
    cursor.execute("""
        INSERT INTO assessments 
        (asset_id, vulnerability_id, vulnerability_severity, asset_criticality, exposure, security_event_severity, risk_score, risk_level, notes, assessment_date)
        VALUES (?, ?, 92.0, 95.0, 80.0, 75.0, ?, ?, 'Penetration test findings on web database queries', datetime('now', '-3 days'))
    """, (asset_map["Customer-DB-Primary"], db_vuln["id"], score_db, level_db))
    db_assess_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO risk_history (asset_id, assessment_id, previous_score, current_score, score_difference, trend, recorded_at)
        VALUES (?, ?, NULL, ?, NULL, 'Initial', datetime('now', '-3 days'))
    """, (asset_map["Customer-DB-Primary"], db_assess_id, score_db))

    recs_db = generate_recommendations(score_db, level_db, "Database")
    for r in recs_db:
        cursor.execute("""
            INSERT INTO recommendations (assessment_id, risk_level, recommendation_text, priority, status)
            VALUES (?, ?, ?, ?, 'Pending')
        """, (db_assess_id, level_db, r["text"], r["priority"]))

    # Additional sample assessment for Internal-Wiki (Low Risk)
    wiki_vuln = next(v for v in vuln_rows if v["name"].startswith("Stored Cross-Site"))
    score_wiki = calculate_risk_score(20.0, 30.0, 20.0, 15.0) # 0.4*20 (8) + 0.25*30 (7.5) + 0.2*20 (4) + 0.15*15 (2.25) = 21.75 -> Low
    level_wiki = classify_risk(score_wiki)
    cursor.execute("""
        INSERT INTO assessments 
        (asset_id, vulnerability_id, vulnerability_severity, asset_criticality, exposure, security_event_severity, risk_score, risk_level, notes, assessment_date)
        VALUES (?, ?, 20.0, 30.0, 20.0, 15.0, ?, ?, 'Annual hygiene check', datetime('now', '-2 days'))
    """, (asset_map["Internal-Wiki"], wiki_vuln["id"], score_wiki, level_wiki))
    wiki_assess_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO risk_history (asset_id, assessment_id, previous_score, current_score, score_difference, trend, recorded_at)
        VALUES (?, ?, NULL, ?, NULL, 'Initial', datetime('now', '-2 days'))
    """, (asset_map["Internal-Wiki"], wiki_assess_id, score_wiki))

    recs_wiki = generate_recommendations(score_wiki, level_wiki, "Application")
    for r in recs_wiki:
        cursor.execute("""
            INSERT INTO recommendations (assessment_id, risk_level, recommendation_text, priority, status)
            VALUES (?, ?, ?, ?, 'Implemented')
        """, (wiki_assess_id, level_wiki, r["text"], r["priority"]))

    # Add logs
    cursor.execute("INSERT INTO monitoring_logs (event_type, description, severity, timestamp) VALUES (?, ?, ?, datetime('now', '-7 days'))",
                   ("System Initialized", "Cybersecurity Risk Scoring database created and initialized.", "INFO"))
    cursor.execute("INSERT INTO monitoring_logs (event_type, description, severity, timestamp) VALUES (?, ?, ?, datetime('now', '-7 days'))",
                   ("Risk Assessment Completed", "Initial assessment for Server A flagged CRITICAL risk (77.5/100).", "CRITICAL"))
    cursor.execute("INSERT INTO monitoring_logs (event_type, description, severity, timestamp) VALUES (?, ?, ?, datetime('now', '-3 days'))",
                   ("Critical Alert", "Customer-DB-Primary flagged CRITICAL risk (87.8/100) due to SQLi vulnerability.", "CRITICAL"))
    cursor.execute("INSERT INTO monitoring_logs (event_type, description, severity, timestamp) VALUES (?, ?, ?, datetime('now', '-1 days'))",
                   ("Risk Decreased", "Server A risk score dropped from 77.5 to 45.0 (-32.5) after patch application.", "SUCCESS"))

    conn.commit()
    conn.close()
