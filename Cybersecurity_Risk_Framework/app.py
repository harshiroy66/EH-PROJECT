"""
Main Flask Web Application for:
Design and Development of an Automated Cybersecurity Risk Scoring and Decision Support Framework

Modules:
1. Asset and Vulnerability Assessment
2. Automated Risk Scoring and Classification
3. Decision Support and Security Recommendations
4. Security Monitoring and Risk History Management
"""

import os
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, send_file, Response
)
import io

from database import init_db, seed_sample_data, get_db, log_event
from risk_engine import (
    calculate_risk_score,
    classify_risk,
    get_risk_meta,
    validate_score_input
)
from modules.asset_assessment import (
    get_all_assets,
    get_asset_by_id,
    create_asset,
    update_asset,
    delete_asset,
    get_all_vulnerabilities,
    get_vulnerability_by_id,
    create_vulnerability,
    update_vulnerability,
    update_vulnerability_status,
    delete_vulnerability,
    VALID_ASSET_TYPES,
    VALID_VULN_STATUSES
)
from modules.risk_scoring import (
    perform_assessment,
    get_all_assessments,
    get_assessment_by_id
)
from modules.decision_support import (
    get_all_recommendations,
    update_recommendation_status,
    generate_assessment_pdf,
    generate_comprehensive_audit_pdf
)
from modules.risk_monitoring import (
    get_system_metrics,
    get_unresolved_risks,
    get_risk_history_records,
    get_trend_chart_data,
    get_monitoring_logs
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "cybersecurity_risk_secret_key_2026_antigravity")

# Initialize database schema and initial test data on startup
with app.app_context():
    init_db()
    seed_sample_data()


# -------------------------------------------------------------
# CONTEXT PROCESSORS (Inject system metrics into base layout)
# -------------------------------------------------------------
@app.context_processor
def inject_global_metrics():
    try:
        metrics = get_system_metrics()
        return {
            "global_metrics": metrics,
            "get_risk_meta": get_risk_meta
        }
    except Exception:
        return {
            "global_metrics": {},
            "get_risk_meta": get_risk_meta
        }


# -------------------------------------------------------------
# ROUTE 1: MAIN DASHBOARD
# -------------------------------------------------------------
@app.route("/")
@app.route("/dashboard")
def dashboard():
    """
    Main central executive dashboard.
    Displays metrics, risk distribution, trends, alerts, and recent activities.
    """
    metrics = get_system_metrics()
    recent_assessments = get_all_assessments(sort_by="date_desc")[:6]
    unresolved_risks = get_unresolved_risks()[:5]
    recent_logs = get_monitoring_logs(limit=8)

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        metrics=metrics,
        recent_assessments=recent_assessments,
        unresolved_risks=unresolved_risks,
        recent_logs=recent_logs
    )


# -------------------------------------------------------------
# ROUTE 2: MODULE 1 - ASSET MANAGEMENT
# -------------------------------------------------------------
@app.route("/assets")
def assets():
    """
    Asset Management page: lists registered assets, handles search/filter.
    """
    search = request.args.get("search", "").strip()
    asset_type = request.args.get("type", "").strip()
    all_assets = get_all_assets(search_query=search, asset_type=asset_type)
    
    return render_template(
        "assets.html",
        active_page="assets",
        assets=all_assets,
        asset_types=VALID_ASSET_TYPES,
        search=search,
        selected_type=asset_type
    )


@app.route("/assets/add", methods=["POST"])
def add_asset():
    name = request.form.get("name", "").strip()
    asset_type = request.form.get("asset_type", "").strip()
    description = request.form.get("description", "").strip()
    criticality = request.form.get("criticality")

    try:
        asset_id = create_asset(name, asset_type, description, criticality)
        flash(f"Asset '{name}' registered successfully with ID #{asset_id}!", "success")
    except ValueError as e:
        flash(str(e), "danger")
    except Exception as e:
        flash(f"Failed to register asset: {e}", "danger")

    return redirect(url_for("assets"))


@app.route("/assets/edit/<int:asset_id>", methods=["POST"])
def edit_asset(asset_id: int):
    name = request.form.get("name", "").strip()
    asset_type = request.form.get("asset_type", "").strip()
    description = request.form.get("description", "").strip()
    criticality = request.form.get("criticality")

    try:
        updated = update_asset(asset_id, name, asset_type, description, criticality)
        if updated:
            flash(f"Asset #{asset_id} updated successfully!", "success")
        else:
            flash(f"Asset #{asset_id} could not be updated.", "warning")
    except ValueError as e:
        flash(str(e), "danger")
    except Exception as e:
        flash(f"Error updating asset: {e}", "danger")

    return redirect(url_for("assets"))


@app.route("/assets/delete/<int:asset_id>", methods=["POST"])
def remove_asset(asset_id: int):
    try:
        deleted = delete_asset(asset_id)
        if deleted:
            flash(f"Asset #{asset_id} and all related assessments were deleted successfully.", "success")
        else:
            flash(f"Asset #{asset_id} was not found.", "warning")
    except Exception as e:
        flash(f"Error deleting asset: {e}", "danger")

    return redirect(url_for("assets"))


# -------------------------------------------------------------
# ROUTE 3: MODULE 1 - VULNERABILITY ASSESSMENT
# -------------------------------------------------------------
@app.route("/vulnerabilities")
def vulnerabilities():
    """
    Vulnerability Assessment page: tracks identified vulnerabilities and statuses.
    """
    status = request.args.get("status", "").strip()
    search = request.args.get("search", "").strip()
    vulns = get_all_vulnerabilities(status=status, search=search)
    all_assets = get_all_assets()

    return render_template(
        "vulnerabilities.html",
        active_page="vulnerabilities",
        vulnerabilities=vulns,
        assets=all_assets,
        statuses=VALID_VULN_STATUSES,
        selected_status=status,
        search=search
    )


@app.route("/vulnerabilities/add", methods=["POST"])
def add_vulnerability():
    asset_id = request.form.get("asset_id")
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    severity = request.form.get("severity")
    status = request.form.get("status", "Open")

    try:
        vuln_id = create_vulnerability(int(asset_id), name, description, severity, status)
        flash(f"Vulnerability '{name}' logged successfully with ID #{vuln_id}!", "success")
    except ValueError as e:
        flash(str(e), "danger")
    except Exception as e:
        flash(f"Failed to record vulnerability: {e}", "danger")

    return redirect(url_for("vulnerabilities"))


@app.route("/vulnerabilities/edit/<int:vuln_id>", methods=["POST"])
def edit_vulnerability(vuln_id: int):
    asset_id = request.form.get("asset_id")
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    severity = request.form.get("severity")
    status = request.form.get("status")

    try:
        updated = update_vulnerability(vuln_id, int(asset_id), name, description, severity, status)
        if updated:
            flash(f"Vulnerability #{vuln_id} updated successfully!", "success")
        else:
            flash(f"Vulnerability #{vuln_id} was not found.", "warning")
    except ValueError as e:
        flash(str(e), "danger")
    except Exception as e:
        flash(f"Error updating vulnerability: {e}", "danger")

    return redirect(url_for("vulnerabilities"))


@app.route("/vulnerabilities/status/<int:vuln_id>", methods=["POST"])
def toggle_vulnerability_status(vuln_id: int):
    status = request.form.get("status", "").strip()
    try:
        update_vulnerability_status(vuln_id, status)
        flash(f"Vulnerability #{vuln_id} status updated to '{status}'.", "success")
    except Exception as e:
        flash(f"Failed to change status: {e}", "danger")

    return redirect(request.referrer or url_for("vulnerabilities"))


@app.route("/vulnerabilities/delete/<int:vuln_id>", methods=["POST"])
def remove_vulnerability(vuln_id: int):
    try:
        deleted = delete_vulnerability(vuln_id)
        if deleted:
            flash(f"Vulnerability #{vuln_id} removed successfully.", "success")
        else:
            flash("Vulnerability not found.", "warning")
    except Exception as e:
        flash(f"Error deleting vulnerability: {e}", "danger")

    return redirect(url_for("vulnerabilities"))


# -------------------------------------------------------------
# ROUTE 4: MODULE 2 - AUTOMATED RISK SCORING AND CLASSIFICATION
# -------------------------------------------------------------
@app.route("/risk-scoring")
def risk_scoring():
    """
    Automated Risk Scoring module page:
    Interactive assessment form, formula details, and prioritized assessment table.
    """
    risk_level = request.args.get("risk_level", "").strip()
    sort_by = request.args.get("sort_by", "risk_desc")
    selected_asset = request.args.get("asset_id", type=int)

    assessments = get_all_assessments(
        risk_level=risk_level if risk_level in ('Low', 'Medium', 'High', 'Critical') else None,
        asset_id=selected_asset,
        sort_by=sort_by
    )
    all_assets = get_all_assets()
    all_vulns = get_all_vulnerabilities()

    return render_template(
        "risk_scoring.html",
        active_page="risk_scoring",
        assessments=assessments,
        assets=all_assets,
        vulnerabilities=all_vulns,
        selected_level=risk_level,
        selected_sort=sort_by,
        selected_asset=selected_asset
    )


@app.route("/risk-scoring/calculate", methods=["POST"])
def calculate_and_save_risk():
    """
    Submits a new risk assessment, calculates score via Python backend,
    classifies risk, creates history delta, and generates recommendations.
    """
    try:
        asset_id = int(request.form.get("asset_id"))
        vulnerability_id = request.form.get("vulnerability_id")
        vulnerability_id = int(vulnerability_id) if vulnerability_id and vulnerability_id.strip() else None

        vuln_severity = float(request.form.get("vulnerability_severity"))
        asset_criticality = float(request.form.get("asset_criticality"))
        exposure = float(request.form.get("exposure"))
        security_event_severity = float(request.form.get("security_event_severity"))
        notes = request.form.get("notes", "")

        result = perform_assessment(
            asset_id=asset_id,
            vulnerability_id=vulnerability_id,
            vulnerability_severity=vuln_severity,
            asset_criticality=asset_criticality,
            exposure=exposure,
            security_event_severity=security_event_severity,
            notes=notes
        )

        score = result["risk_score"]
        level = result["risk_level"]
        diff = result["score_difference"]
        trend = result["trend"]

        msg = f"Assessment #{result['assessment_id']} Completed! Score: {score}/100 ({level} Risk)."
        if trend != "Initial":
            msg += f" Trend: Risk {trend} ({'+' if diff > 0 else ''}{diff:.1f} pts)."

        flash(msg, "success" if level == "Low" else ("warning" if level == "Medium" else "danger"))
        return redirect(url_for("risk_scoring"))

    except ValueError as e:
        flash(f"Validation Error: {e}", "danger")
        return redirect(url_for("risk_scoring"))
    except Exception as e:
        flash(f"System Error: {e}", "danger")
        return redirect(url_for("risk_scoring"))


# -------------------------------------------------------------
# ROUTE 5: MODULE 3 - DECISION SUPPORT & RECOMMENDATIONS
# -------------------------------------------------------------
@app.route("/recommendations")
def recommendations():
    """
    Security Recommendations page: actionable decision support items,
    remediation priorities, and status tracking.
    """
    status_filter = request.args.get("status", "").strip()
    priority_filter = request.args.get("priority", "").strip()

    recs = get_all_recommendations(status_filter=status_filter, priority_filter=priority_filter)

    return render_template(
        "recommendations.html",
        active_page="recommendations",
        recommendations=recs,
        status_filter=status_filter,
        priority_filter=priority_filter
    )


@app.route("/recommendations/status/<int:rec_id>", methods=["POST"])
def change_recommendation_status(rec_id: int):
    new_status = request.form.get("status", "").strip()
    try:
        update_recommendation_status(rec_id, new_status)
        flash(f"Recommendation #{rec_id} status updated to '{new_status}'.", "success")
    except Exception as e:
        flash(f"Error updating recommendation: {e}", "danger")

    return redirect(request.referrer or url_for("recommendations"))


# -------------------------------------------------------------
# ROUTE 6: MODULE 4 - SECURITY MONITORING
# -------------------------------------------------------------
@app.route("/monitoring")
def monitoring():
    """
    Security Monitoring Dashboard:
    Real-time posture, unresolved vulnerabilities, logs, and trend analysis.
    """
    metrics = get_system_metrics()
    unresolved = get_unresolved_risks()
    logs = get_monitoring_logs(limit=20)
    all_vulns = get_all_vulnerabilities()

    return render_template(
        "monitoring.html",
        active_page="monitoring",
        metrics=metrics,
        unresolved=unresolved,
        logs=logs,
        vulnerabilities=all_vulns
    )


# -------------------------------------------------------------
# ROUTE 7: MODULE 4 - RISK HISTORY & TRENDS
# -------------------------------------------------------------
@app.route("/history")
def history():
    """
    Risk History page:
    Audit trail comparing previous vs current risk scores for the same asset.
    """
    selected_asset = request.args.get("asset_id", type=int)
    history_records = get_risk_history_records(asset_id=selected_asset)
    assets = get_all_assets()

    return render_template(
        "history.html",
        active_page="history",
        records=history_records,
        assets=assets,
        selected_asset=selected_asset
    )


# -------------------------------------------------------------
# ROUTE 8: REPORTS & EXPORT
# -------------------------------------------------------------
@app.route("/reports")
def reports():
    """
    Reports Catalog page:
    Browse all assessment reports, view detailed breakdowns, and download PDFs.
    """
    risk_level = request.args.get("risk_level", "").strip()
    selected_asset = request.args.get("asset_id", type=int)
    assessments = get_all_assessments(
        risk_level=risk_level if risk_level in ('Low', 'Medium', 'High', 'Critical') else None,
        asset_id=selected_asset,
        sort_by="date_desc"
    )
    assets = get_all_assets()

    return render_template(
        "reports.html",
        active_page="reports",
        assessments=assessments,
        assets=assets,
        selected_level=risk_level,
        selected_asset=selected_asset
    )


@app.route("/reports/view/<int:assessment_id>")
def report_view(assessment_id: int):
    """
    Detailed printable view of an individual assessment.
    """
    assessment = get_assessment_by_id(assessment_id)
    if not assessment:
        flash(f"Assessment #{assessment_id} not found.", "warning")
        return redirect(url_for("reports"))

    return render_template(
        "report_detail.html",
        active_page="reports",
        assessment=assessment
    )


@app.route("/reports/download/<int:assessment_id>")
def download_report_pdf(assessment_id: int):
    """
    Generates and downloads an individual assessment report in PDF format.
    """
    try:
        pdf_bytes = generate_assessment_pdf(assessment_id)
        filename = f"Risk_Assessment_Report_ASM_{assessment_id:04d}.pdf"
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        flash(f"Failed to generate PDF: {e}", "danger")
        return redirect(url_for("reports"))


@app.route("/reports/download-all")
def download_all_audit_pdf():
    """
    Generates and downloads a consolidated multi-asset risk audit PDF report.
    """
    try:
        pdf_bytes = generate_comprehensive_audit_pdf()
        filename = "Consolidated_Cybersecurity_Risk_Audit_Report.pdf"
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        flash(f"Failed to generate audit PDF: {e}", "danger")
        return redirect(url_for("reports"))


# -------------------------------------------------------------
# ROUTE 9: SETTINGS & SYSTEM UTILITIES
# -------------------------------------------------------------
@app.route("/settings")
def settings():
    """
    Settings and System Diagnostics page.
    """
    return render_template(
        "settings.html",
        active_page="settings"
    )


@app.route("/settings/reseed", methods=["POST"])
def reseed_demo_data():
    """
    Reset and re-seed sample database data (including Server A test cases).
    """
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS monitoring_logs")
        cursor.execute("DROP TABLE IF EXISTS risk_history")
        cursor.execute("DROP TABLE IF EXISTS recommendations")
        cursor.execute("DROP TABLE IF EXISTS assessments")
        cursor.execute("DROP TABLE IF EXISTS vulnerabilities")
        cursor.execute("DROP TABLE IF EXISTS assets")
        conn.commit()
        conn.close()

        init_db()
        seed_sample_data()
        flash("Database has been reset and seeded with standard sample test data!", "success")
    except Exception as e:
        flash(f"Error reseeding database: {e}", "danger")

    return redirect(url_for("settings"))


# -------------------------------------------------------------
# JSON API ENDPOINTS (For Dynamic Client Feedback & Chart.js)
# -------------------------------------------------------------
@app.route("/api/calculate-preview", methods=["POST"])
def api_calculate_preview():
    """
    Instant preview calculation API:
    R = 0.40V + 0.25A + 0.20E + 0.15S
    Returns score, classification, and visual meta.
    """
    data = request.get_json(silent=True) or request.form
    try:
        v = float(data.get("vulnerability_severity", 0))
        a = float(data.get("asset_criticality", 0))
        e = float(data.get("exposure", 0))
        s = float(data.get("security_event_severity", 0))

        score = calculate_risk_score(v, a, e, s)
        classification = classify_risk(score)
        meta = get_risk_meta(classification)

        return jsonify({
            "success": True,
            "risk_score": score,
            "risk_level": classification,
            "meta": meta,
            "formula_breakdown": {
                "v_weighted": round(0.40 * v, 2),
                "a_weighted": round(0.25 * a, 2),
                "e_weighted": round(0.20 * e, 2),
                "s_weighted": round(0.15 * s, 2)
            }
        })
    except Exception as err:
        return jsonify({"success": False, "error": str(err)}), 400


@app.route("/api/chart-data")
def api_chart_data():
    """
    Returns metrics and historical trend chart data for Chart.js.
    """
    metrics = get_system_metrics()
    trends = get_trend_chart_data()
    return jsonify({
        "metrics": metrics,
        "trends": trends
    })


# -------------------------------------------------------------
# ERROR HANDLERS
# -------------------------------------------------------------
@app.errorhandler(404)
def not_found_error(error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template("500.html"), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
