"""
CSIDS PDF Report Generator
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER
from datetime import datetime
import io

# colors
BG_BLUE  = HexColor("#0f3460")
ACCENT   = HexColor("#00d4ff")
RED      = HexColor("#ff3864")
ORANGE   = HexColor("#ff8c00")
GREEN    = HexColor("#00c97a")
GRAY     = HexColor("#5a7a9a")
LIGHT_BG = HexColor("#f4f7fb")
WHITE    = white


def risk_color(score):
    if score >= 6:
        return RED
    elif score >= 3:
        return ORANGE
    return GREEN


def generate_pdf_report(user, alerts, stats=None):
    """
    Generate a styled PDF report.
    Returns raw bytes of the PDF.
    """
    buffer = io.BytesIO()
    doc    = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm,   bottomMargin=2*cm
    )

    styles  = getSampleStyleSheet()
    story   = []

    # ── styles ──
    title_style = ParagraphStyle(
        "Title", parent=styles["Normal"],
        fontSize=22, textColor=ACCENT,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER, spaceAfter=4
    )
    sub_style = ParagraphStyle(
        "Sub", parent=styles["Normal"],
        fontSize=10, textColor=GRAY,
        alignment=TA_CENTER, spaceAfter=4
    )
    h2_style = ParagraphStyle(
        "H2", parent=styles["Normal"],
        fontSize=13, textColor=BG_BLUE,
        fontName="Helvetica-Bold",
        spaceBefore=16, spaceAfter=6
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=9, textColor=black, spaceAfter=3
    )
    mono_style = ParagraphStyle(
        "Mono", parent=styles["Normal"],
        fontSize=8, fontName="Courier",
        textColor=HexColor("#1a1a2e")
    )
    footer_style = ParagraphStyle(
        "Footer", parent=styles["Normal"],
        fontSize=8, textColor=GRAY,
        alignment=TA_CENTER
    )

    # ── HEADER ──
    story.append(Paragraph("CSIDS INTRUSION DETECTION REPORT", title_style))
    story.append(Paragraph(
        f"Command Sequence Intrusion Detection System &nbsp;|&nbsp; "
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        sub_style
    ))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT))
    story.append(Spacer(1, 0.4*cm))

    # ── SUMMARY TABLE ──
    story.append(Paragraph("Executive Summary", h2_style))

    high_count   = sum(1 for a in alerts if a.get("risk_score", 0) >= 6)
    medium_count = sum(1 for a in alerts if 3 <= a.get("risk_score", 0) < 6)
    low_count    = sum(1 for a in alerts if a.get("risk_score", 0) < 3)

    summary_data = [
        ["Field", "Value"],
        ["User",          user],
        ["Report Date",   datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Total Alerts",  str(len(alerts))],
        ["High Risk (≥6)",    str(high_count)],
        ["Medium Risk (3–6)", str(medium_count)],
        ["Low Risk (<3)",     str(low_count)],
    ]
    if stats:
        summary_data += [
            ["Trained Sequences", str(stats.get("total_sequences", "N/A"))],
            ["Total Observations", str(stats.get("total_observations", "N/A"))],
        ]

    summary_table = Table(summary_data, colWidths=[6*cm, 10*cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), BG_BLUE),
        ("TEXTCOLOR",   (0, 0), (-1, 0), WHITE),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_BG]),
        ("GRID",        (0, 0), (-1, -1), 0.4, HexColor("#cccccc")),
        ("PADDING",     (0, 0), (-1, -1), 6),
        ("FONTNAME",    (0, 1), (0, -1), "Helvetica-Bold"),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.5*cm))

    # ── ALERTS TABLE ──
    story.append(Paragraph(f"Detected Alerts ({len(alerts)})", h2_style))

    if not alerts:
        story.append(Paragraph("✅ No intrusions detected.", body_style))
    else:
        alert_data = [["#", "Sequence", "Reason", "Risk", "Risky Cmds"]]

        for i, a in enumerate(alerts, 1):
            seq = a.get("sequence", "")
            if len(seq) > 55:
                seq = seq[:52] + "..."

            alert_data.append([
                str(i),
                Paragraph(seq, mono_style),
                Paragraph(a.get("reason", ""), body_style),
                f"{a.get('risk_score', 0)}/10",
                Paragraph(", ".join(a.get("risky", [])), body_style),
            ])

        col_widths = [0.8*cm, 6.5*cm, 4.5*cm, 1.5*cm, 3.5*cm]
        alert_table = Table(alert_data, colWidths=col_widths, repeatRows=1)

        row_styles = [
            ("BACKGROUND", (0, 0), (-1, 0), BG_BLUE),
            ("TEXTCOLOR",  (0, 0), (-1, 0), WHITE),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ("GRID",       (0, 0), (-1, -1), 0.4, HexColor("#cccccc")),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ("PADDING",    (0, 0), (-1, -1), 5),
        ]

        # color rows by risk
        for i, a in enumerate(alerts, 1):
            score = a.get("risk_score", 0)
            if score >= 6:
                bg = HexColor("#fff0f0")
            elif score >= 3:
                bg = HexColor("#fff8ee")
            else:
                bg = WHITE
            row_styles.append(("BACKGROUND", (0, i), (-1, i), bg))

        alert_table.setStyle(TableStyle(row_styles))
        story.append(alert_table)

    # ── FOOTER ──
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=GRAY))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "CSIDS — Command Sequence Intrusion Detection System &nbsp;|&nbsp; Confidential",
        footer_style
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()