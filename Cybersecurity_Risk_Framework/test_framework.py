"""
Automated Test Suite for Cybersecurity Risk Scoring and Decision Support Framework.
Validates all 15 Testing Requirements specified in Section 16 and Section 14.
"""

import os
import unittest
import sqlite3
from database import get_db, init_db, seed_sample_data, DB_PATH
from risk_engine import (
    calculate_risk_score,
    classify_risk,
    evaluate_risk_delta,
    validate_score_input
)
from recommendations import generate_recommendations
from modules.asset_assessment import (
    create_asset,
    update_asset,
    delete_asset,
    get_all_assets,
    get_asset_by_id,
    create_vulnerability,
    update_vulnerability,
    update_vulnerability_status,
    delete_vulnerability,
    get_all_vulnerabilities
)
from modules.risk_scoring import (
    perform_assessment,
    get_all_assessments,
    get_assessment_by_id
)
from modules.decision_support import (
    generate_assessment_pdf,
    generate_comprehensive_audit_pdf,
    get_all_recommendations,
    update_recommendation_status
)
from modules.risk_monitoring import (
    get_system_metrics,
    get_unresolved_risks,
    get_risk_history_records
)


class TestCybersecurityFramework(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Initialize and seed database
        init_db()
        seed_sample_data()

    def test_01_add_asset(self):
        """Test 1: Add an asset and verify in database."""
        asset_id = create_asset(
            name="Test-Router-Alpha",
            asset_type="Network",
            description="Core test router",
            criticality=75.0
        )
        self.assertIsNotNone(asset_id)
        asset = get_asset_by_id(asset_id)
        self.assertEqual(asset["name"], "Test-Router-Alpha")
        self.assertEqual(asset["asset_type"], "Network")
        self.assertEqual(asset["criticality"], 75.0)
        print("✓ Test 1 Passed: Asset created successfully.")

    def test_02_edit_asset(self):
        """Test 2: Edit asset information."""
        asset_id = create_asset(
            name="Edit-Test-Host",
            asset_type="Computer",
            description="Pre-edit description",
            criticality=30.0
        )
        updated = update_asset(
            asset_id=asset_id,
            name="Edit-Test-Host-Updated",
            asset_type="Server",
            description="Post-edit description",
            criticality=55.0
        )
        self.assertTrue(updated)
        asset = get_asset_by_id(asset_id)
        self.assertEqual(asset["name"], "Edit-Test-Host-Updated")
        self.assertEqual(asset["asset_type"], "Server")
        self.assertEqual(asset["criticality"], 55.0)
        print("✓ Test 2 Passed: Asset updated successfully.")

    def test_03_delete_asset(self):
        """Test 3: Delete asset with confirmation and verify removal."""
        asset_id = create_asset(
            name="Delete-Target-Host",
            asset_type="Other",
            description="To be deleted",
            criticality=20.0
        )
        deleted = delete_asset(asset_id)
        self.assertTrue(deleted)
        asset = get_asset_by_id(asset_id)
        self.assertIsNone(asset)
        print("✓ Test 3 Passed: Asset deleted successfully.")

    def test_04_add_vulnerability(self):
        """Test 4: Add a vulnerability linked to an asset."""
        # Find Server A
        assets = get_all_assets(search_query="Server A")
        server_a = assets[0]
        vuln_id = create_vulnerability(
            asset_id=server_a["id"],
            name="Test Vulnerability CVE-2026-0001",
            description="Buffer leak test",
            severity=65.0,
            status="Open"
        )
        self.assertIsNotNone(vuln_id)
        vulns = get_all_vulnerabilities(search="CVE-2026-0001")
        self.assertTrue(len(vulns) >= 1)
        self.assertEqual(vulns[0]["severity"], 65.0)
        print("✓ Test 4 Passed: Vulnerability added successfully.")

    def test_05_validate_numerical_inputs(self):
        """Test 5: Validate numerical inputs are restricted to 0-100."""
        # Test valid inputs
        self.assertEqual(validate_score_input(0, "Test"), 0.0)
        self.assertEqual(validate_score_input(100, "Test"), 100.0)
        self.assertEqual(validate_score_input("77.5", "Test"), 77.5)

        # Test invalid values (negative, > 100, non-numeric, empty)
        with self.assertRaises(ValueError):
            validate_score_input(-5, "Test")
        with self.assertRaises(ValueError):
            validate_score_input(105, "Test")
        with self.assertRaises(ValueError):
            validate_score_input("invalid_string", "Test")
        with self.assertRaises(ValueError):
            validate_score_input("", "Test")
        print("✓ Test 5 Passed: Numerical input validation (0-100) strictly enforced.")

    def test_06_verify_exact_risk_formula(self):
        """
        Test 6: Calculate the correct risk score.
        Formula: R = 0.40V + 0.25A + 0.20E + 0.15S
        Section 14 verification:
        V = 80, A = 90, E = 70, S = 60
        Expected: 0.40(80) + 0.25(90) + 0.20(70) + 0.15(60) = 32 + 22.5 + 14 + 9 = 77.5
        """
        v = 80.0
        a = 90.0
        e = 70.0
        s = 60.0
        calculated_score = calculate_risk_score(v, a, e, s)
        expected_score = 77.5
        self.assertEqual(calculated_score, expected_score)
        print(f"✓ Test 6 Passed: Formula precision verified: R={calculated_score} (Expected: {expected_score}).")

    def test_07_verify_risk_classifications(self):
        """
        Test 7: Verify risk classification boundaries:
        0–24 = Low Risk
        25–49 = Medium Risk
        50–74 = High Risk
        75–100 = Critical Risk
        """
        self.assertEqual(classify_risk(0.0), "Low")
        self.assertEqual(classify_risk(24.0), "Low")
        self.assertEqual(classify_risk(25.0), "Medium")
        self.assertEqual(classify_risk(49.0), "Medium")
        self.assertEqual(classify_risk(50.0), "High")
        self.assertEqual(classify_risk(74.0), "High")
        self.assertEqual(classify_risk(75.0), "Critical")
        self.assertEqual(classify_risk(77.5), "Critical")
        self.assertEqual(classify_risk(100.0), "Critical")
        print("✓ Test 7 Passed: Risk classifications (Low, Medium, High, Critical) verified.")

    def test_08_generate_recommendations(self):
        """
        Test 8: Generate recommendations matching project rules:
        - LOW: Routine monitoring, regular updates, periodic review
        - CRITICAL: Escalate to security admin, immediate remediation, isolate, detailed investigation
        """
        crit_recs = generate_recommendations(77.5, "Critical", "Server")
        crit_texts = [r["text"] for r in crit_recs]
        self.assertTrue(any("Escalate the issue to the security administrator" in t for t in crit_texts))
        self.assertTrue(any("Prioritize immediate remediation" in t for t in crit_texts))
        self.assertTrue(any("Isolate affected assets" in t for t in crit_texts))
        self.assertTrue(any("detailed security investigation" in t for t in crit_texts))

        low_recs = generate_recommendations(15.0, "Low", "Application")
        low_texts = [r["text"] for r in low_recs]
        self.assertTrue(any("routine security monitoring" in t for t in low_texts))
        self.assertTrue(any("regular security updates" in t for t in low_texts))
        self.assertTrue(any("Review configurations periodically" in t for t in low_texts))
        print("✓ Test 8 Passed: Actionable recommendations match all rule specifications.")

    def test_09_save_assessment_records(self):
        """Test 9: Save assessment records into SQLite database."""
        assets = get_all_assets()
        asset = assets[0]
        result = perform_assessment(
            asset_id=asset["id"],
            vulnerability_id=None,
            vulnerability_severity=70.0,
            asset_criticality=80.0,
            exposure=50.0,
            security_event_severity=40.0,
            notes="Automated test assessment"
        )
        self.assertIsNotNone(result["assessment_id"])
        asm = get_assessment_by_id(result["assessment_id"])
        self.assertIsNotNone(asm)
        # R = 0.40(70) + 0.25(80) + 0.20(50) + 0.15(40) = 28 + 20 + 10 + 6 = 64.0 -> High
        self.assertEqual(asm["risk_score"], 64.0)
        self.assertEqual(asm["risk_level"], "High")
        self.assertTrue(len(asm["recommendations"]) >= 3)
        print("✓ Test 9 Passed: Assessment record and recommendations saved in SQLite.")

    def test_10_and_11_compare_historical_risk_scores(self):
        """
        Test 10 & 11: Create a second assessment for the same asset,
        compare historical scores, calculate difference, and detect trend.
        Section 7 example:
        Asset: Server A
        Previous Risk Score: 77.5
        Current Risk Score: 45
        Difference: -32.5
        Display: Risk Decreased
        """
        # Create dedicated test asset
        asset_id = create_asset("Comparative-Asset-X", "Server", "History tracking test asset", 90.0)

        # Assessment 1: Score 77.5 (Critical)
        res1 = perform_assessment(
            asset_id=asset_id,
            vulnerability_id=None,
            vulnerability_severity=80.0,
            asset_criticality=90.0,
            exposure=70.0,
            security_event_severity=60.0
        )
        self.assertEqual(res1["risk_score"], 77.5)
        self.assertEqual(res1["risk_level"], "Critical")
        self.assertEqual(res1["trend"], "Initial")

        # Assessment 2: Score 45.0 (Medium)
        # 0.40(40) + 0.25(90) + 0.20(25) + 0.15(10) = 16 + 22.5 + 5 + 1.5 = 45.0
        res2 = perform_assessment(
            asset_id=asset_id,
            vulnerability_id=None,
            vulnerability_severity=40.0,
            asset_criticality=90.0,
            exposure=25.0,
            security_event_severity=10.0
        )
        self.assertEqual(res2["risk_score"], 45.0)
        self.assertEqual(res2["risk_level"], "Medium")
        self.assertEqual(res2["previous_score"], 77.5)
        self.assertEqual(res2["score_difference"], -32.5)
        self.assertEqual(res2["trend"], "Decreased")

        # Check in risk_history table
        history = get_risk_history_records(asset_id=asset_id)
        self.assertEqual(len(history), 2)
        latest_history = history[0]
        self.assertEqual(latest_history["current_score"], 45.0)
        self.assertEqual(latest_history["previous_score"], 77.5)
        self.assertEqual(latest_history["score_difference"], -32.5)
        self.assertEqual(latest_history["trend"], "Decreased")

        print("✓ Test 10 & 11 Passed: Second assessment created, delta -32.5 verified, 'Risk Decreased' confirmed.")

    def test_12_update_vulnerability_status(self):
        """Test 12: Track and update vulnerability status (Open -> Pending -> Resolved)."""
        assets = get_all_assets()
        vuln_id = create_vulnerability(
            asset_id=assets[0]["id"],
            name="Status Lifecycle Vulnerability",
            description="Testing lifecycle transitions",
            severity=60.0,
            status="Open"
        )
        # Transition to Pending
        self.assertTrue(update_vulnerability_status(vuln_id, "Pending"))
        v = get_all_vulnerabilities(search="Status Lifecycle Vulnerability")[0]
        self.assertEqual(v["status"], "Pending")

        # Transition to Resolved
        self.assertTrue(update_vulnerability_status(vuln_id, "Resolved"))
        v = get_all_vulnerabilities(search="Status Lifecycle Vulnerability")[0]
        self.assertEqual(v["status"], "Resolved")
        print("✓ Test 12 Passed: Vulnerability status lifecycle (Open -> Pending -> Resolved) verified.")

    def test_13_monitoring_charts_and_metrics(self):
        """Test 13: Display monitoring metrics and unresolved risks."""
        metrics = get_system_metrics()
        self.assertIn("total_assets", metrics)
        self.assertIn("total_assessments", metrics)
        self.assertIn("total_vulnerabilities", metrics)
        self.assertIn("open_vulnerabilities", metrics)
        self.assertIn("pending_vulnerabilities", metrics)
        self.assertIn("resolved_vulnerabilities", metrics)
        self.assertIn("high_risk_assets", metrics)
        self.assertIn("critical_risk_assets", metrics)
        self.assertIn("risk_distribution", metrics)
        self.assertTrue(metrics["total_assets"] > 0)

        unresolved = get_unresolved_risks()
        self.assertIsInstance(unresolved, list)
        print("✓ Test 13 Passed: System monitoring metrics and risk distribution data verified.")

    def test_14_pdf_report_generation(self):
        """Test 14: Generate downloadable assessment reports in PDF format."""
        assessments = get_all_assessments()
        self.assertTrue(len(assessments) > 0)
        first_asm_id = assessments[0]["id"]

        # Single assessment PDF
        pdf_bytes = generate_assessment_pdf(first_asm_id)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))
        self.assertTrue(len(pdf_bytes) > 500)

        # Full executive audit PDF
        audit_pdf = generate_comprehensive_audit_pdf()
        self.assertIsInstance(audit_pdf, bytes)
        self.assertTrue(audit_pdf.startswith(b"%PDF-1.4"))
        self.assertTrue(len(audit_pdf) > 500)
        print("✓ Test 14 Passed: Binary PDF reports generated and validated (%PDF-1.4 spec).")

    def test_15_database_persistence_and_schema_integrity(self):
        """Test 15: Verify database persistence and relational integrity."""
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r["name"] for r in cursor.fetchall()]

        required_tables = [
            "assets", "vulnerabilities", "assessments",
            "recommendations", "risk_history", "monitoring_logs"
        ]
        for tbl in required_tables:
            self.assertIn(tbl, tables, f"Missing required table '{tbl}' in cybersecurity.db")

        # Foreign keys check
        cursor.execute("PRAGMA foreign_key_check")
        fk_errors = cursor.fetchall()
        self.assertEqual(len(fk_errors), 0, "Foreign key integrity violation detected.")
        conn.close()
        print("✓ Test 15 Passed: Database persistence, schema integrity, and zero foreign key violations verified.")


if __name__ == "__main__":
    unittest.main()
