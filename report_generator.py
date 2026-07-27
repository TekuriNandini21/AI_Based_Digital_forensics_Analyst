"""
report_generator.py
------------------------------------------------------------
Generates a professional PDF forensic investigation report
using ReportLab.

Sections:
    * Cover Page
    * Case Information
    * Evidence Summary
    * Timeline
    * Charts (severity distribution bar summary rendered as a
      simple table since ReportLab has no native chart widget
      -- Plotly charts are shown live in the web dashboard)
    * AI Summary
    * MITRE ATT&CK Mapping (extracted from the AI Markdown)
    * Risk Score
    * Recommendations
    * Conclusion
------------------------------------------------------------
"""

import os
import re
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")


def _risk_color(risk_level):
    return {
        "Safe": colors.HexColor("#2ecc71"),
        "Low": colors.HexColor("#3498db"),
        "Medium": colors.HexColor("#f1c40f"),
        "High": colors.HexColor("#e67e22"),
        "Critical": colors.HexColor("#e74c3c"),
    }.get(risk_level, colors.grey)


def _split_ai_sections(ai_markdown):
    """
    Splits the Gemini-generated Markdown into a dict keyed by
    section header, based on the '## Header' convention used in
    ai_analyzer.py's prompt.
    """
    sections = {}
    current_header = "Summary"
    buffer = []
    for line in ai_markdown.splitlines():
        m = re.match(r"^##\s+(.*)", line.strip())
        if m:
            if buffer:
                sections[current_header] = "\n".join(buffer).strip()
            current_header = m.group(1).strip()
            buffer = []
        else:
            buffer.append(line)
    if buffer:
        sections[current_header] = "\n".join(buffer).strip()
    return sections


def _clean_markdown_inline(text):
    """Strips simple markdown emphasis so ReportLab paragraphs render cleanly."""
    text = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"\*(.*?)\*", r"<i>\1</i>", text)
    text = text.replace("&", "&amp;")
    text = text.replace("<b>", "\x01B").replace("</b>", "\x02B")
    text = text.replace("<i>", "\x01I").replace("</i>", "\x02I")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("\x01B", "<b>").replace("\x02B", "</b>")
    text = text.replace("\x01I", "<i>").replace("\x02I", "</i>")
    return text


def generate_pdf_report(investigation, evidence_list, incidents, summary,
                         ai_summary_markdown, output_path=None):
    """
    Builds the full PDF report and writes it to output_path
    (or a default path inside uploads/). Returns the final path.
    """
    if output_path is None:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        output_path = os.path.join(
            REPORTS_DIR, f"forensic_report_case_{investigation['id']}.pdf"
        )

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm,
        leftMargin=2 * cm, rightMargin=2 * cm,
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="CoverTitle", fontSize=26, leading=32, alignment=TA_CENTER,
        textColor=colors.HexColor("#0b1f3a"), spaceAfter=12, fontName="Helvetica-Bold"
    ))
    styles.add(ParagraphStyle(
        name="CoverSubtitle", fontSize=14, alignment=TA_CENTER,
        textColor=colors.HexColor("#333333"), spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        name="SectionHeader", fontSize=15, leading=18, spaceBefore=16, spaceAfter=8,
        textColor=colors.white, backColor=colors.HexColor("#0b1f3a"),
        fontName="Helvetica-Bold", alignment=TA_LEFT, leftIndent=4, borderPadding=6
    ))
    styles.add(ParagraphStyle(
        name="Body", fontSize=10.5, leading=15, alignment=TA_LEFT, spaceAfter=6
    ))

    elements = []

    # ---------------- Cover Page ----------------
    elements.append(Spacer(1, 4 * cm))
    elements.append(Paragraph("AI-Powered Digital Forensics Assistant", styles["CoverTitle"]))
    elements.append(Paragraph("Digital Forensic Investigation Report", styles["CoverSubtitle"]))
    elements.append(Spacer(1, 1.5 * cm))
    elements.append(HRFlowable(width="80%", color=colors.HexColor("#0b1f3a"), thickness=1))
    elements.append(Spacer(1, 1 * cm))
    elements.append(Paragraph(f"<b>Case Name:</b> {investigation['case_name']}", styles["Body"]))
    elements.append(Paragraph(f"<b>Investigator:</b> {investigation.get('investigator') or 'N/A'}", styles["Body"]))
    elements.append(Paragraph(f"<b>Case ID:</b> {investigation['id']}", styles["Body"]))
    elements.append(Paragraph(f"<b>Report Generated:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["Body"]))
    elements.append(Paragraph(f"<b>Status:</b> {investigation.get('status', 'N/A')}", styles["Body"]))
    elements.append(PageBreak())

    # ---------------- Case Information ----------------
    elements.append(Paragraph("Case Information", styles["SectionHeader"]))
    case_table_data = [
        ["Case Name", investigation["case_name"]],
        ["Investigator", investigation.get("investigator") or "N/A"],
        ["Created At", investigation.get("created_at", "N/A")],
        ["Status", investigation.get("status", "N/A")],
        ["Total Evidence Files", str(len(evidence_list))],
        ["Total Incidents Detected", str(len(incidents))],
    ]
    t = Table(case_table_data, colWidths=[5 * cm, 10 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2f7")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(t)

    # ---------------- Risk Score ----------------
    elements.append(Paragraph("Risk Score", styles["SectionHeader"]))
    risk_table = Table([[
        f"{investigation.get('risk_score', 0)} / 100",
        investigation.get("risk_level", "N/A"),
    ]], colWidths=[7.5 * cm, 7.5 * cm])
    risk_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("FONTSIZE", (0, 0), (-1, -1), 14),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("BACKGROUND", (1, 0), (1, 0), _risk_color(investigation.get("risk_level", "Safe"))),
        ("TEXTCOLOR", (1, 0), (1, 0), colors.white),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    elements.append(risk_table)

    # ---------------- Evidence Summary ----------------
    elements.append(Paragraph("Evidence Summary", styles["SectionHeader"]))
    if evidence_list:
        ev_data = [["Filename", "Type", "Size (bytes)", "Uploaded At"]]
        for ev in evidence_list:
            ev_data.append([
                ev.get("filename", ""), ev.get("file_type", ""),
                str(ev.get("file_size", "")), ev.get("uploaded_at", "")
            ])
        ev_table = Table(ev_data, colWidths=[5 * cm, 2.5 * cm, 3 * cm, 4.5 * cm])
        ev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1f3a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ]))
        elements.append(ev_table)
    else:
        elements.append(Paragraph("No evidence files recorded.", styles["Body"]))

    # ---------------- Severity Distribution (as table) ----------------
    elements.append(Paragraph("Severity Distribution", styles["SectionHeader"]))
    sev_counts = summary.get("severity_counts", {})
    sev_data = [["Severity", "Count"]] + [[k, str(v)] for k, v in sev_counts.items()] or [["No data", "0"]]
    sev_table = Table(sev_data, colWidths=[7.5 * cm, 7.5 * cm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1f3a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    elements.append(sev_table)
    elements.append(PageBreak())

    # ---------------- Timeline ----------------
    elements.append(Paragraph("Investigation Timeline", styles["SectionHeader"]))
    timeline = incidents[:40]  # cap for report length
    if timeline:
        tl_data = [["Timestamp", "Category", "Severity", "Description"]]
        for i in timeline:
            tl_data.append([
                str(i.get("timestamp", ""))[:19], i.get("category", ""),
                i.get("severity", ""), (i.get("description", "") or "")[:60]
            ])
        tl_table = Table(tl_data, colWidths=[3.3 * cm, 4 * cm, 2.2 * cm, 5.5 * cm])
        tl_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1f3a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(tl_table)
        if len(incidents) > 40:
            elements.append(Paragraph(
                f"...and {len(incidents) - 40} more incidents (see dashboard for full list).",
                styles["Body"]
            ))
    else:
        elements.append(Paragraph("No timeline events recorded.", styles["Body"]))
    elements.append(PageBreak())

    # ---------------- AI Summary Sections ----------------
    ai_sections = _split_ai_sections(ai_summary_markdown or "")
    section_order = [
        "Executive Summary", "Evidence Analysis", "Suspicious Findings",
        "Attack Pattern", "Investigation Timeline Summary",
        "Possible MITRE ATT&CK Techniques", "Threat Assessment",
        "Recommended Investigation Steps", "Recommended Mitigation",
        "Final Conclusion",
    ]
    for header in section_order:
        content = ai_sections.get(header)
        if not content:
            continue
        elements.append(Paragraph(header, styles["SectionHeader"]))
        for para in content.split("\n\n"):
            para = para.strip()
            if para:
                elements.append(Paragraph(_clean_markdown_inline(para), styles["Body"]))
        elements.append(Spacer(1, 0.2 * cm))

    doc.build(elements)
    return output_path
