"""
Module 3: Decision Support and Security Recommendations.
Provides remediation prioritization, recommendation management, and
downloadable PDF security assessment report generation.
"""

from typing import List, Dict, Any, Optional
from database import get_db, log_event
from modules.risk_scoring import get_assessment_by_id
from risk_engine import get_risk_meta


def get_all_recommendations(status_filter: Optional[str] = None, priority_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieve all recommendations across all assessments, sorted by priority.
    """
    conn = get_db()
    cursor = conn.cursor()

    sql = """
        SELECT r.id, r.assessment_id, r.risk_level, r.recommendation_text, 
               r.priority, r.status, r.created_at,
               asm.risk_score, asm.assessment_date,
               a.name as asset_name, a.asset_type,
               v.name as vulnerability_name, v.status as vuln_status
        FROM recommendations r
        JOIN assessments asm ON r.assessment_id = asm.id
        JOIN assets a ON asm.asset_id = a.id
        LEFT JOIN vulnerabilities v ON asm.vulnerability_id = v.id
        WHERE 1=1
    """
    params = []

    if status_filter and status_filter in ('Pending', 'In Progress', 'Implemented'):
        sql += " AND r.status = ?"
        params.append(status_filter)

    if priority_filter and priority_filter in ('Critical', 'High', 'Medium', 'Low'):
        sql += " AND r.priority = ?"
        params.append(priority_filter)

    sql += """
        ORDER BY 
            CASE r.priority 
                WHEN 'Critical' THEN 1 
                WHEN 'High' THEN 2 
                WHEN 'Medium' THEN 3 
                ELSE 4 
            END,
            r.created_at DESC
    """

    cursor.execute(sql, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def update_recommendation_status(rec_id: int, new_status: str) -> bool:
    """
    Update the implementation status of a recommendation.
    """
    if new_status not in ('Pending', 'In Progress', 'Implemented'):
        raise ValueError(f"Invalid recommendation status '{new_status}'.")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE recommendations 
        SET status = ? 
        WHERE id = ?
    """, (new_status, rec_id))
    affected = cursor.rowcount
    conn.commit()
    conn.close()

    if affected > 0:
        log_event("Recommendation Updated", f"Recommendation #{rec_id} status changed to '{new_status}'.", "INFO")
        return True
    return False


# =========================================================================
# PURE PYTHON PDF GENERATOR (Zero external dependencies, 100% reliable)
# =========================================================================

class MinimalPDF:
    """
    Generates standard PDF 1.4 documents natively in Python.
    Supports text blocks, lines, colored rectangles, and multi-page layouts.
    """
    def __init__(self, page_width=595.28, page_height=841.89):  # A4 standard
        self.width = page_width
        self.height = page_height
        self.pages = []
        self.current_stream = []

    def add_page(self):
        if self.current_stream:
            self.pages.append("".join(self.current_stream))
            self.current_stream = []

    def set_fill_rgb(self, r: float, g: float, b: float):
        self.current_stream.append(f"{r:.3f} {g:.3f} {b:.3f} rg\n")

    def set_stroke_rgb(self, r: float, g: float, b: float):
        self.current_stream.append(f"{r:.3f} {g:.3f} {b:.3f} RG\n")

    def draw_rect(self, x: float, y: float, w: float, h: float, fill=True, stroke=False):
        self.current_stream.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re\n")
        if fill and stroke:
            self.current_stream.append("B\n")
        elif fill:
            self.current_stream.append("f\n")
        elif stroke:
            self.current_stream.append("S\n")

    def draw_line(self, x1: float, y1: float, x2: float, y2: float, line_width: float = 1.0):
        self.current_stream.append(f"{line_width:.2f} w\n")
        self.current_stream.append(f"{x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S\n")

    def draw_text(self, text: str, x: float, y: float, font="F1", size=10, r=0.0, g=0.0, b=0.0):
        # Escape special PDF characters: (, ), \
        safe_text = (
            text.replace("\\", "\\\\")
                .replace("(", "\\(")
                .replace(")", "\\)")
                .encode('latin1', 'replace')
                .decode('latin1')
        )
        self.set_fill_rgb(r, g, b)
        self.current_stream.append(
            f"BT /{font} {size} Tf {x:.2f} {y:.2f} Td ({safe_text}) Tj ET\n"
        )

    def build_pdf_bytes(self) -> bytes:
        if self.current_stream:
            self.pages.append("".join(self.current_stream))

        objects = []
        # Object 1: Catalog
        objects.append("<< /Type /Catalog /Pages 2 0 R >>")
        # Object 2: Pages placeholder
        objects.append(None)
        # Object 3: Font Helvetica
        objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        # Object 4: Font Helvetica-Bold
        objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

        page_refs = []
        obj_num = 5

        for page_stream in self.pages:
            content_obj_num = obj_num
            length = len(page_stream.encode('latin1'))
            stream_obj = f"<< /Length {length} >>\nstream\n{page_stream}endstream"
            objects.append(stream_obj)
            obj_num += 1

            page_obj_num = obj_num
            page_obj = (
                f"<< /Type /Page /Parent 2 0 R "
                f"/MediaBox [0 0 {self.width:.2f} {self.height:.2f}] "
                f"/Contents {content_obj_num} 0 R "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> >>"
            )
            objects.append(page_obj)
            page_refs.append(f"{page_obj_num} 0 R")
            obj_num += 1

        # Populate Pages Object (Object 2)
        objects[1] = f"<< /Type /Pages /Kids [{' '.join(page_refs)}] /Count {len(self.pages)} >>"

        # Build xref table
        header = "%PDF-1.4\n%âãÏÓ\n"
        body = bytearray(header.encode('latin1'))
        xref_offsets = [0]

        for i, obj in enumerate(objects, 1):
            xref_offsets.append(len(body))
            body.extend(f"{i} 0 obj\n{obj}\nendobj\n".encode('latin1'))

        xref_pos = len(body)
        xref = f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n"
        for offset in xref_offsets[1:]:
            xref += f"{offset:010d} 00000 n \n"

        trailer = (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n"
        )
        body.extend(xref.encode('latin1'))
        body.extend(trailer.encode('latin1'))
        return bytes(body)


def generate_assessment_pdf(assessment_id: int) -> bytes:
    """
    Generate an official, professional PDF Cybersecurity Risk Assessment Report
    conforming to all Section 6 and Section 10 requirements.
    """
    assessment = get_assessment_by_id(assessment_id)
    if not assessment:
        raise ValueError(f"Assessment #{assessment_id} not found.")

    pdf = MinimalPDF()

    # Page 1 Background & Header Banner (Deep Navy Theme)
    pdf.set_fill_rgb(0.043, 0.075, 0.169) # #0b132b
    pdf.draw_rect(0, 750, 595.28, 91.89, fill=True)

    # Accent Cyan Line
    pdf.set_stroke_rgb(0.0, 0.96, 0.83) # #00f5d4
    pdf.draw_line(0, 750, 595.28, 750, line_width=3)

    # Header Titles
    pdf.draw_text("AUTOMATED CYBERSECURITY RISK SCORING FRAMEWORK", 36, 805, font="F2", size=13, r=0.0, g=0.96, b=0.83)
    pdf.draw_text("Official Cybersecurity Risk Assessment & Decision Support Report", 36, 785, font="F2", size=16, r=1.0, g=1.0, b=1.0)
    pdf.draw_text("Generated by Antigravity Cybersecurity Decision Support Engine", 36, 768, font="F1", size=9, r=0.7, g=0.8, b=0.9)

    # Metadata Strip
    pdf.set_fill_rgb(0.94, 0.96, 0.98)
    pdf.draw_rect(36, 705, 523.28, 30, fill=True)
    pdf.draw_text(f"Report ID: SEC-ASM-{assessment['id']:04d}", 46, 716, font="F2", size=9, r=0.1, g=0.15, b=0.3)
    pdf.draw_text(f"Assessment Date: {assessment['assessment_date']}", 200, 716, font="F1", size=9, r=0.2, g=0.2, b=0.2)
    pdf.draw_text("Confidentiality: Internal Security Audit", 400, 716, font="F2", size=9, r=0.8, g=0.2, b=0.2)

    # Asset Information Box
    pdf.draw_text("1. ASSET PROFILE", 36, 680, font="F2", size=12, r=0.07, g=0.15, b=0.3)
    pdf.set_stroke_rgb(0.8, 0.85, 0.9)
    pdf.draw_line(36, 674, 559.28, 674, line_width=1)

    pdf.set_fill_rgb(0.97, 0.98, 1.0)
    pdf.draw_rect(36, 605, 523.28, 62, fill=True, stroke=True)

    pdf.draw_text(f"Asset Name:  {assessment['asset_name']}", 46, 648, font="F2", size=10, r=0.1, g=0.1, b=0.1)
    pdf.draw_text(f"Asset Type:  {assessment['asset_type']}", 240, 648, font="F1", size=10, r=0.2, g=0.2, b=0.2)
    pdf.draw_text(f"Criticality (A):  {assessment['asset_criticality']:.1f} / 100", 420, 648, font="F2", size=10, r=0.8, g=0.3, b=0.1)

    desc = assessment['asset_description'] or 'No additional description provided.'
    if len(desc) > 85:
        desc = desc[:82] + "..."
    pdf.draw_text(f"Description: {desc}", 46, 625, font="F1", size=9, r=0.3, g=0.3, b=0.3)

    # Vulnerability Information Box
    pdf.draw_text("2. VULNERABILITY & EXPOSURE DETAILS", 36, 580, font="F2", size=12, r=0.07, g=0.15, b=0.3)
    pdf.set_stroke_rgb(0.8, 0.85, 0.9)
    pdf.draw_line(36, 574, 559.28, 574, line_width=1)

    pdf.set_fill_rgb(0.97, 0.98, 1.0)
    pdf.draw_rect(36, 505, 523.28, 62, fill=True, stroke=True)

    vuln_name = assessment['vulnerability_name'] or 'General Asset Vulnerability Assessment'
    if len(vuln_name) > 40:
        vuln_name = vuln_name[:37] + "..."
    pdf.draw_text(f"Vulnerability: {vuln_name}", 46, 548, font="F2", size=10, r=0.1, g=0.1, b=0.1)
    pdf.draw_text(f"Severity (V): {assessment['vulnerability_severity']:.1f} / 100", 300, 548, font="F2", size=10, r=0.8, g=0.2, b=0.2)
    pdf.draw_text(f"Status: {assessment.get('vulnerability_status') or 'Open'}", 460, 548, font="F1", size=10, r=0.2, g=0.5, b=0.2)

    pdf.draw_text(f"Exposure Level (E): {assessment['exposure']:.1f} / 100", 46, 525, font="F1", size=9.5, r=0.2, g=0.2, b=0.2)
    pdf.draw_text(f"Security Event Severity (S): {assessment['security_event_severity']:.1f} / 100", 250, 525, font="F1", size=9.5, r=0.2, g=0.2, b=0.2)

    # Risk Calculation & Score Section
    pdf.draw_text("3. AUTOMATED RISK SCORING & CLASSIFICATION", 36, 480, font="F2", size=12, r=0.07, g=0.15, b=0.3)
    pdf.set_stroke_rgb(0.8, 0.85, 0.9)
    pdf.draw_line(36, 474, 559.28, 474, line_width=1)

    # Formula Box
    pdf.set_fill_rgb(0.92, 0.94, 0.98)
    pdf.draw_rect(36, 420, 310, 48, fill=True)
    pdf.draw_text("Applied Mathematical Risk Formula:", 46, 452, font="F2", size=9, r=0.1, g=0.2, b=0.4)
    pdf.draw_text("R = 0.40(V) + 0.25(A) + 0.20(E) + 0.15(S)", 46, 437, font="F1", size=9, r=0.2, g=0.3, b=0.5)
    f_str = assessment['formula_breakdown']['formula_str']
    pdf.draw_text(f"= {f_str} = {assessment['risk_score']:.2f}", 46, 424, font="F2", size=8.5, r=0.05, g=0.1, b=0.3)

    # Risk Score Big Badge
    risk_level = assessment['risk_level']
    if risk_level == "Critical":
        badge_r, badge_g, badge_b = 0.93, 0.26, 0.26 # Red
    elif risk_level == "High":
        badge_r, badge_g, badge_b = 0.97, 0.45, 0.08 # Orange
    elif risk_level == "Medium":
        badge_r, badge_g, badge_b = 0.96, 0.62, 0.04 # Yellow/Amber
    else:
        badge_r, badge_g, badge_b = 0.06, 0.72, 0.50 # Green

    pdf.set_fill_rgb(badge_r, badge_g, badge_b)
    pdf.draw_rect(360, 420, 199.28, 48, fill=True)
    pdf.draw_text("OVERALL RISK SCORE", 375, 454, font="F2", size=8.5, r=1.0, g=1.0, b=1.0)
    pdf.draw_text(f"{assessment['risk_score']:.1f} / 100", 375, 432, font="F2", size=18, r=1.0, g=1.0, b=1.0)
    pdf.draw_text(f"[{risk_level.upper()} RISK]", 465, 434, font="F2", size=11, r=1.0, g=1.0, b=1.0)

    # Risk History Delta Callout
    if assessment.get('previous_score') is not None:
        diff = assessment.get('score_difference', 0.0)
        trend = assessment.get('trend', 'Unchanged')
        pdf.set_fill_rgb(0.95, 0.95, 0.95)
        pdf.draw_rect(36, 395, 523.28, 18, fill=True)
        sign = "+" if diff > 0 else ""
        delta_text = f"Historical Comparison: Previous Score: {assessment['previous_score']:.1f} | Current: {assessment['risk_score']:.1f} | Difference: {sign}{diff:.1f} pts ({trend})"
        pdf.draw_text(delta_text, 46, 401, font="F2", size=8.5, r=0.2, g=0.2, b=0.2)

    # Section 4: Security Recommendations
    pdf.draw_text("4. DECISION SUPPORT & SECURITY RECOMMENDATIONS", 36, 370, font="F2", size=12, r=0.07, g=0.15, b=0.3)
    pdf.set_stroke_rgb(0.8, 0.85, 0.9)
    pdf.draw_line(36, 364, 559.28, 364, line_width=1)

    y_cursor = 345
    recommendations = assessment.get("recommendations", [])
    if not recommendations:
        pdf.draw_text("No specific remediation items generated for this score.", 46, y_cursor, font="F1", size=10, r=0.4, g=0.4, b=0.4)
        y_cursor -= 20
    else:
        for idx, rec in enumerate(recommendations, 1):
            if y_cursor < 120:
                break # Keep within single clean page

            # Recommendation Box
            pdf.set_fill_rgb(0.98, 0.98, 0.99)
            pdf.set_stroke_rgb(0.88, 0.90, 0.94)
            pdf.draw_rect(36, y_cursor - 30, 523.28, 40, fill=True, stroke=True)

            # Priority Tag
            p = rec.get("priority", "Medium")
            pr, pg, pb = (0.9, 0.2, 0.2) if p == "Critical" else ((0.9, 0.4, 0.1) if p == "High" else (0.2, 0.6, 0.3))
            pdf.set_fill_rgb(pr, pg, pb)
            pdf.draw_rect(42, y_cursor - 2, 55, 12, fill=True)
            pdf.draw_text(p.upper(), 46, y_cursor + 1, font="F2", size=7.5, r=1.0, g=1.0, b=1.0)

            # Rec Text
            rec_text = rec.get("recommendation_text", "")
            if len(rec_text) > 80:
                rec_text = rec_text[:77] + "..."
            pdf.draw_text(f"{idx}. {rec_text}", 105, y_cursor + 1, font="F2", size=9, r=0.1, g=0.1, b=0.1)

            # Status and Meta
            status = rec.get("status", "Pending")
            pdf.draw_text(f"Remediation Status: {status}  |  Compliance Priority: {p}", 105, y_cursor - 15, font="F1", size=8, r=0.4, g=0.4, b=0.4)

            y_cursor -= 46

    # Sign-off & Verification Footer Block
    pdf.set_stroke_rgb(0.85, 0.85, 0.85)
    pdf.draw_line(36, 95, 559.28, 95, line_width=1)

    pdf.draw_text("Security Analyst Sign-off:", 36, 80, font="F2", size=8.5, r=0.3, g=0.3, b=0.3)
    pdf.draw_line(150, 78, 280, 78, line_width=0.8)
    pdf.draw_text("Chief Information Security Officer (CISO):", 310, 80, font="F2", size=8.5, r=0.3, g=0.3, b=0.3)
    pdf.draw_line(490, 78, 559, 78, line_width=0.8)

    pdf.draw_text("Automated Cybersecurity Risk Scoring and Decision Support Framework - Academic Evaluation Edition", 36, 45, font="F1", size=8, r=0.5, g=0.5, b=0.5)
    pdf.draw_text("Design and Development of an Automated Cybersecurity Risk Scoring and Decision Support Framework", 36, 32, font="F1", size=7.5, r=0.6, g=0.6, b=0.6)

    return pdf.build_pdf_bytes()


def generate_comprehensive_audit_pdf() -> bytes:
    """
    Generate an executive-level summary audit PDF containing all registered assets,
    assessments, and current security posture.
    """
    from modules.asset_assessment import get_all_assets
    from modules.risk_scoring import get_all_assessments

    assets = get_all_assets()
    assessments = get_all_assessments(sort_by="risk_desc")

    pdf = MinimalPDF()

    # Header
    pdf.set_fill_rgb(0.043, 0.075, 0.169)
    pdf.draw_rect(0, 750, 595.28, 91.89, fill=True)
    pdf.set_stroke_rgb(0.0, 0.96, 0.83)
    pdf.draw_line(0, 750, 595.28, 750, line_width=3)

    pdf.draw_text("CYBERSECURITY RISK MANAGEMENT & DECISION SUPPORT", 36, 805, font="F2", size=13, r=0.0, g=0.96, b=0.83)
    pdf.draw_text("Executive Comprehensive Risk Audit & Inventory Report", 36, 785, font="F2", size=16, r=1.0, g=1.0, b=1.0)
    pdf.draw_text("Consolidated Multi-Asset Risk Evaluation & Remediation Dashboard", 36, 768, font="F1", size=9, r=0.7, g=0.8, b=0.9)

    # Summary Statistics Bar
    crit_count = sum(1 for a in assessments if a['risk_level'] == 'Critical')
    high_count = sum(1 for a in assessments if a['risk_level'] == 'High')
    med_count = sum(1 for a in assessments if a['risk_level'] == 'Medium')
    low_count = sum(1 for a in assessments if a['risk_level'] == 'Low')

    pdf.set_fill_rgb(0.93, 0.95, 0.98)
    pdf.draw_rect(36, 700, 523.28, 35, fill=True)
    pdf.draw_text(f"Total Assets: {len(assets)}   |   Total Assessments: {len(assessments)}", 46, 713, font="F2", size=10, r=0.1, g=0.15, b=0.3)
    pdf.draw_text(f"Critical: {crit_count}   High: {high_count}   Medium: {med_count}   Low: {low_count}", 320, 713, font="F2", size=10, r=0.8, g=0.2, b=0.2)

    # Table Header
    pdf.draw_text("CURRENT RISK ASSESSMENTS (PRIORITIZED BY SEVERITY)", 36, 670, font="F2", size=11, r=0.1, g=0.2, b=0.4)
    pdf.set_stroke_rgb(0.8, 0.85, 0.9)
    pdf.draw_line(36, 664, 559.28, 664, line_width=1)

    pdf.set_fill_rgb(0.88, 0.91, 0.96)
    pdf.draw_rect(36, 642, 523.28, 20, fill=True)
    pdf.draw_text("Asset Name", 42, 648, font="F2", size=8.5, r=0.1, g=0.1, b=0.2)
    pdf.draw_text("Type", 160, 648, font="F2", size=8.5, r=0.1, g=0.1, b=0.2)
    pdf.draw_text("Vulnerability", 240, 648, font="F2", size=8.5, r=0.1, g=0.1, b=0.2)
    pdf.draw_text("Score", 390, 648, font="F2", size=8.5, r=0.1, g=0.1, b=0.2)
    pdf.draw_text("Classification", 440, 648, font="F2", size=8.5, r=0.1, g=0.1, b=0.2)
    pdf.draw_text("Trend", 515, 648, font="F2", size=8.5, r=0.1, g=0.1, b=0.2)

    y = 620
    for asm in assessments[:18]:  # Fit neatly on page
        pdf.set_fill_rgb(0.98, 0.98, 0.99)
        pdf.draw_rect(36, y - 4, 523.28, 18, fill=True)

        a_name = asm['asset_name'][:18]
        v_name = (asm.get('vulnerability_name') or 'General')[:24]
        pdf.draw_text(a_name, 42, y, font="F1", size=8, r=0.1, g=0.1, b=0.1)
        pdf.draw_text(asm['asset_type'], 160, y, font="F1", size=8, r=0.2, g=0.2, b=0.2)
        pdf.draw_text(v_name, 240, y, font="F1", size=8, r=0.2, g=0.2, b=0.2)
        pdf.draw_text(f"{asm['risk_score']:.1f}", 390, y, font="F2", size=8.5, r=0.1, g=0.1, b=0.1)

        level = asm['risk_level']
        lr, lg, lb = (0.85, 0.1, 0.1) if level == "Critical" else ((0.9, 0.4, 0.1) if level == "High" else (0.1, 0.5, 0.2))
        pdf.draw_text(level, 440, y, font="F2", size=8.5, r=lr, g=lg, b=lb)

        trend = asm.get('trend') or 'Initial'
        pdf.draw_text(trend, 515, y, font="F1", size=8, r=0.3, g=0.3, b=0.3)

        y -= 22

    # Footer
    pdf.draw_line(36, 60, 559.28, 60, line_width=1)
    pdf.draw_text("Cybersecurity Risk Scoring and Decision Support Framework - Comprehensive Audit", 36, 45, font="F1", size=8, r=0.5, g=0.5, b=0.5)

    return pdf.build_pdf_bytes()
