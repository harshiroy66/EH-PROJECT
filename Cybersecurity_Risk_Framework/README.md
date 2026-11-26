# Design and Development of an Automated Cybersecurity Risk Scoring and Decision Support Framework

An academic-grade, production-ready, full-stack cybersecurity web application built with Python Flask, SQLite, Bootstrap 5, and Chart.js.

The framework automates quantitative cybersecurity risk scoring, multi-tier threat classification, decision support with prioritized remediation playbooks, and continuous longitudinal risk history monitoring.

---

## 1. Project Overview & Architecture

The application implements four tightly integrated modules communicating over a shared SQLite database (`cybersecurity.db`):

```
       [ MODULE 1: Asset & Vulnerability Assessment ]
         - Collects IT asset profiles & threat vectors
         - Enforces strict input validation (0 - 100)
                              │
                              ▼
       [ MODULE 2: Automated Risk Scoring & Classification ]
         - Computes: R = 0.40(V) + 0.25(A) + 0.20(E) + 0.15(S)
         - Classifies: Low, Medium, High, Critical
                              │
                              ▼
       [ MODULE 3: Decision Support & Security Recommendations ]
         - Triggers rule-based remediation playbooks
         - Generates downloadable compliance PDF reports
                              │
                              ▼
       [ MODULE 4: Security Monitoring & Risk History Management ]
         - Longitudinal trend delta: Δ = Current - Previous
         - Preserves complete immutable audit trail
                              │
                              ▼
            [ CENTRAL CYBERSECURITY EXECUTIVE DASHBOARD ]
         - High-level telemetry, Chart.js graphs, live alert feeds
```

---

## 2. Technology Stack

- **Frontend:** HTML5, CSS3, JavaScript (ES6+), Bootstrap 5.3, Bootstrap Icons
- **Backend:** Python 3, Flask 3.1
- **Database:** SQLite 3 (`cybersecurity.db`) with parameterized queries and foreign key constraints enabled
- **Data Visualization:** Chart.js 4.4 (Risk Distribution doughnut chart, Longitudinal Risk Trend line chart, Vulnerability Remediation bar chart)
- **PDF Generation:** Pure Python vector PDF generator (`%PDF-1.4`) with zero external binary dependencies

---

## 3. Mathematical Risk Engine Formulation

### Formula
$$R = 0.40V + 0.25A + 0.20E + 0.15S$$

Where:
- **$R$** = Overall Cybersecurity Risk Score ($0 \le R \le 100$)
- **$V$** = Vulnerability Severity ($0 \le V \le 100$, 40% weight)
- **$A$** = Asset Criticality ($0 \le A \le 100$, 25% weight)
- **$E$** = Exposure Level ($0 \le E \le 100$, 20% weight)
- **$S$** = Security Event Severity ($0 \le S \le 100$, 15% weight)

### Risk Classification Scale
| Risk Score Range | Classification | Action Threshold |
| :---: | :---: | :--- |
| **0 – 24** | **Low Risk** | Routine security monitoring, regular updates, periodic review |
| **25 – 49** | **Medium Risk** | Apply recommended patches, review permissions, harden configurations |
| **50 – 74** | **High Risk** | Prioritize remediation, apply patches promptly, review network & auth |
| **75 – 100** | **Critical Risk** | Escalate to administrator, immediate remediation, isolate affected asset |

### Sample Verification Benchmark (Section 14)
- **Asset Name:** Server A (Server)
- **Asset Criticality ($A$):** 90
- **Vulnerability Severity ($V$):** 80
- **Exposure ($E$):** 70
- **Security Event Severity ($S$):** 60

$$R = 0.40(80) + 0.25(90) + 0.20(70) + 0.15(60) = 32 + 22.5 + 14 + 9 = 77.5$$
$$\text{Classification: } \mathbf{CRITICAL\ RISK}$$

Follow-up assessment for Server A:
- Post-mitigation score: **45.0**
- Score Difference ($\Delta$): $45.0 - 77.5 = \mathbf{-32.5}$
- Longitudinal Trend: **Risk Decreased**

---

## 4. Database Design (`cybersecurity.db`)

1. **`assets`**: Stores registered systems (Server, Computer, Network, Database, Application, Other), description, criticality ($0–100$), timestamps.
2. **`vulnerabilities`**: Stores CVE identifiers, asset foreign key, severity ($0–100$), status (`Open`, `Pending`, `Resolved`).
3. **`assessments`**: Stores full quantitative assessments, input parameters ($V, A, E, S$), calculated score ($R$), risk level, audit notes, timestamp.
4. **`recommendations`**: Stores actionable remediation recommendations, priority (`Critical`, `High`, `Medium`, `Low`), status (`Pending`, `In Progress`, `Implemented`).
5. **`risk_history`**: Preserves previous score, current score, delta ($\Delta$), and trend (`Increased`, `Decreased`, `Unchanged`, `Initial`) for every assessment. Never overwrites older records.
6. **`monitoring_logs`**: System audit event log stream.

---

## 5. Folder Structure

```
Cybersecurity_Risk_Framework/
├── app.py                     # Main Flask application entry point & routing
├── database.py                # SQLite connection, schema init & sample seeder
├── risk_engine.py             # Mathematical scoring engine & classification rules
├── recommendations.py         # Decision support rules & remediation playbooks
├── requirements.txt           # Dependencies (Flask, Jinja2, Werkzeug)
├── test_framework.py          # 15-point automated verification test suite
├── test_server.py             # Full HTTP endpoint integration test suite
│
├── modules/
│   ├── __init__.py
│   ├── asset_assessment.py    # Module 1: Asset & Vulnerability CRUD
│   ├── risk_scoring.py        # Module 2: Automated Scoring & Persistence
│   ├── decision_support.py    # Module 3: Recommendations & Native PDF Generator
│   └── risk_monitoring.py     # Module 4: Metrics, Deltas & History Trends
│
├── templates/
│   ├── base.html              # Base layout with sidebar, navbar & flash alerts
│   ├── dashboard.html         # Executive cybersecurity command center
│   ├── assets.html            # Asset inventory management
│   ├── vulnerabilities.html   # Vulnerability tracking & status lifecycle
│   ├── risk_scoring.html      # Interactive scoring workbench & live calculator
│   ├── recommendations.html   # Decision support & actionable remediation cards
│   ├── monitoring.html        # Comprehensive posture monitoring & metrics
│   ├── history.html           # Longitudinal trend comparison & score deltas
│   ├── reports.html           # Formal reports catalog with PDF downloads
│   ├── report_detail.html     # Single assessment detailed audit report
│   ├── settings.html          # Engine utilities, formula reference & reseed tool
│   ├── 404.html               # 404 handler
│   └── 500.html               # 500 handler
│
└── static/
    ├── css/
    │   └── style.css          # Modern dark navy cybersecurity UI styling
    ├── js/
    │   └── dashboard.js       # Live preview math, Chart.js configs & filters
    └── images/
```

---

## 6. Installation & Execution Guide

### Step 1: Install Requirements
```bash
pip install -r requirements.txt
```

### Step 2: Run the Application
```bash
python app.py
```

### Step 3: Access the Web Application
Open your web browser and navigate to:
```
http://127.0.0.1:5000/
```

---

## 7. Running Verification Tests

Run the automated test suite to verify all 15 operational requirements:
```bash
python test_framework.py
python test_server.py
```
Both test suites will validate input sanitation, mathematical scoring precision ($77.5$), risk classification, delta tracking ($-32.5$), PDF report generation, and database integrity.
