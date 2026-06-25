"""Generate professional forensic PDF reports using ReportLab."""
from __future__ import annotations
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)

STUDENT = {
    "name":       "Muhammad Abdullah Arif",
    "degree":     "BS Computer Science (Session 2022-2026)",
    "university": "Government College University Faisalabad",
    "department": "Department of Computer Science, "
                  "Government Graduate College Jhang",
}


def _styles():
    base = getSampleStyleSheet()
    base.add(ParagraphStyle("PWDSTitle", parent=base["Title"],
                            textColor=colors.HexColor("#0b3d91"),
                            fontSize=22, spaceAfter=10))
    base.add(ParagraphStyle("PWDSH2", parent=base["Heading2"],
                            textColor=colors.HexColor("#0b3d91"),
                            spaceBefore=14, spaceAfter=6))
    return base


def build_report(scan, output_path: str | Path) -> str:
    """Render a PDF for the given URLScan instance. Returns absolute path."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    styles = _styles()
    doc = SimpleDocTemplate(
        str(output_path), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"PWDS Report — {scan.url}",
        author=STUDENT["name"],
    )

    story = []
    story.append(Paragraph("Phishing Website Detection System", styles["PWDSTitle"]))
    story.append(Paragraph("Forensic Threat Report", styles["Heading3"]))
    story.append(Spacer(1, 6))

    meta = [
        ["Student",     STUDENT["name"]],
        ["Degree",      STUDENT["degree"]],
        ["University",  STUDENT["university"]],
        ["Department",  STUDENT["department"]],
        ["Generated",   datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Analyst",     scan.user.username],
    ]
    t = Table(meta, colWidths=[40 * mm, 130 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2fb")),
        ("TEXTCOLOR",  (0, 0), (0, -1), colors.HexColor("#0b3d91")),
        ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)

    # ------------------------------------------------------------------
    story.append(Paragraph("1. Target URL & Verdict", styles["PWDSH2"]))
    verdict_color = {"SAFE": "#1a7f37", "SUSPICIOUS": "#b86e00",
                     "PHISHING": "#c4302b"}.get(scan.verdict, "#000")
    story.append(Paragraph(f"<b>URL:</b> {scan.url}", styles["BodyText"]))
    story.append(Paragraph(
        f"<b>Verdict:</b> <font color='{verdict_color}'>{scan.verdict}</font> "
        f"&nbsp;&nbsp;<b>Threat Score:</b> {scan.threat_score:.2f}%",
        styles["BodyText"],
    ))

    # ------------------------------------------------------------------
    story.append(Paragraph("2. Lexical & Behavioural Features", styles["PWDSH2"]))
    rows = [["Feature", "Value"]]
    for k, v in (scan.features or {}).items():
        rows.append([k.replace("_", " ").title(), str(v)])
    ft = Table(rows, colWidths=[80 * mm, 90 * mm])
    ft.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d91")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f4f6fb")]),
    ]))
    story.append(ft)

    # ------------------------------------------------------------------
    story.append(Paragraph("3. Network Intelligence", styles["PWDSH2"]))
    net = scan.network or {}
    whois = net.get("whois", {})
    dns = net.get("dns", {})
    net_rows = [
        ["WHOIS Registrar",    whois.get("registrar")   or "n/a"],
        ["WHOIS Country",      whois.get("country")     or "n/a"],
        ["Domain Created",     whois.get("creation")    or "n/a"],
        ["Domain Expires",     whois.get("expiration")  or "n/a"],
        ["Domain Age (days)",  whois.get("age_days")    if whois.get("age_days") is not None else "n/a"],
        ["DNS A Records",      ", ".join(dns.get("A", []))  or "n/a"],
        ["DNS MX Records",     ", ".join(dns.get("MX", [])) or "n/a"],
        ["DNS NS Records",     ", ".join(dns.get("NS", [])) or "n/a"],
    ]
    nt = Table(net_rows, colWidths=[55 * mm, 115 * mm])
    nt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2fb")),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.grey),
        ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
    ]))
    story.append(nt)

    # ------------------------------------------------------------------
    story.append(Paragraph("4. Recommended Defensive Actions", styles["PWDSH2"]))
    recs = list(scan.recommendations.all())
    if not recs:
        story.append(Paragraph("No specific recommendations.", styles["BodyText"]))
    else:
        for r in recs:
            story.append(Paragraph(
                f"<b>[{r.get_severity_display()}]</b> {r.text}",
                styles["BodyText"],
            ))

    # ------------------------------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("Appendix A — Passive Packet Trace", styles["PWDSH2"]))
    trace_rows = [["Hop", "TTL", "Source", "Destination", "Proto", "Latency (ms)"]]
    for hop in net.get("trace", []):
        trace_rows.append([hop["hop"], hop["ttl"], hop["src"],
                           hop["dst"], hop["proto"], hop["latency_ms"]])
    tr = Table(trace_rows, colWidths=[15 * mm, 15 * mm, 40 * mm, 40 * mm,
                                      20 * mm, 30 * mm])
    tr.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d91")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.grey),
    ]))
    story.append(tr)

    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "<i>This report is generated automatically by the Phishing Website "
        "Detection System (PWDS) developed by Muhammad Abdullah Arif as part "
        "of the BS Computer Science Final Year Project at Government College "
        "University Faisalabad.</i>",
        styles["Italic"],
    ))

    doc.build(story)
    return str(output_path.resolve())
