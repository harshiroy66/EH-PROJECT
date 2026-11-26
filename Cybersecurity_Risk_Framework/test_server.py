"""
Web Endpoint & Integration Test for Flask App Routes.
Tests all application views, APIs, and PDF responses via Flask test client.
"""

import unittest
from app import app


class TestFlaskEndpoints(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_01_dashboard(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Executive Cybersecurity Dashboard", res.data)
        self.assertIn(b"Total Registered Assets", res.data)
        print("✓ Route '/' (Dashboard) OK")

    def test_02_assets_page(self):
        res = self.client.get("/assets")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Module 1: Asset Inventory", res.data)
        self.assertIn(b"Register New Asset", res.data)
        print("✓ Route '/assets' OK")

    def test_03_vulnerabilities_page(self):
        res = self.client.get("/vulnerabilities")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Module 1: Vulnerability Tracking", res.data)
        self.assertIn(b"Log Vulnerability", res.data)
        print("✓ Route '/vulnerabilities' OK")

    def test_04_risk_scoring_page(self):
        res = self.client.get("/risk-scoring")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Module 2: Automated Risk Scoring", res.data)
        self.assertIn(b"R = 0.40(V) + 0.25(A) + 0.20(E) + 0.15(S)", res.data)
        print("✓ Route '/risk-scoring' OK")

    def test_05_recommendations_page(self):
        res = self.client.get("/recommendations")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Module 3: Decision Support", res.data)
        print("✓ Route '/recommendations' OK")

    def test_06_monitoring_page(self):
        res = self.client.get("/monitoring")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Module 4: Security Monitoring", res.data)
        self.assertIn(b"Open Vulnerabilities", res.data)
        self.assertIn(b"Critical Risk Assets", res.data)
        print("✓ Route '/monitoring' OK")

    def test_07_history_page(self):
        res = self.client.get("/history")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Module 4: Risk History", res.data)
        self.assertIn(b"Longitudinal Asset Risk Progression", res.data)
        print("✓ Route '/history' OK")

    def test_08_reports_page(self):
        res = self.client.get("/reports")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Security Reports & Compliance Audits", res.data)
        print("✓ Route '/reports' OK")

    def test_09_settings_page(self):
        res = self.client.get("/settings")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Settings & Risk Engine Architecture", res.data)
        self.assertIn(b"cybersecurity.db", res.data)
        print("✓ Route '/settings' OK")

    def test_10_api_calculate_preview(self):
        payload = {
            "vulnerability_severity": 80,
            "asset_criticality": 90,
            "exposure": 70,
            "security_event_severity": 60
        }
        res = self.client.post("/api/calculate-preview", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["risk_score"], 77.5)
        self.assertEqual(data["risk_level"], "Critical")
        print("✓ API '/api/calculate-preview' (77.5 Critical) OK")

    def test_11_api_chart_data(self):
        res = self.client.get("/api/chart-data")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("metrics", data)
        self.assertIn("trends", data)
        print("✓ API '/api/chart-data' OK")

    def test_12_download_report_pdf(self):
        res = self.client.get("/reports/download/1")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "application/pdf")
        self.assertTrue(res.data.startswith(b"%PDF-1.4"))
        print("✓ Route '/reports/download/1' (Binary PDF) OK")

    def test_13_download_audit_pdf(self):
        res = self.client.get("/reports/download-all")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "application/pdf")
        self.assertTrue(res.data.startswith(b"%PDF-1.4"))
        print("✓ Route '/reports/download-all' (Full Executive Audit PDF) OK")


if __name__ == "__main__":
    unittest.main()
