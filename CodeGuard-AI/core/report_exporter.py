"""
CodeGuard AI 2.0 - Multi-Format Report Exporter
Generates structured JSON, CSV, and formal Academic PDF audit reports.
"""
from __future__ import annotations
import json
import io
import pandas as pd
from typing import Optional
from core.schemas import ReviewResult


def export_as_json(result: ReviewResult) -> str:
    """Export the review result as formatted JSON."""
    return json.dumps(result.model_dump(), indent=2)


def export_as_csv(result: ReviewResult) -> str:
    """Export the detected issues list as a CSV table."""
    records = []
    for issue in result.issues:
        records.append({
            "issue_id": issue.issue_id,
            "issue_type": issue.issue_type,
            "category": issue.category,
            "severity": issue.severity,
            "line_number": issue.line_number,
            "title": issue.title,
            "description": issue.description,
            "evidence": issue.evidence,
            "suggested_fix": issue.suggested_fix,
            "confidence": issue.confidence,
            "detection_sources": ";".join(issue.detection_sources),
            "status": issue.status,
        })
    if not records:
        return "issue_id,issue_type,category,severity,line_number,title,description,evidence,suggested_fix,confidence,detection_sources,status\n"
    df = pd.DataFrame(records)
    return df.to_csv(index=False)


def export_as_pdf(result: ReviewResult, filename: Optional[str] = None) -> bytes:
    """
    Generate an academic-grade formal PDF code review report using ReportLab.
    """
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "SubTitleStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=12,
    )
    h2_style = ParagraphStyle(
        "H2Style",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        textColor=colors.HexColor("#334155"),
        spaceAfter=4,
    )
    code_style = ParagraphStyle(
        "CodeStyle",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("🛡️ CodeGuard AI 2.0 - Code Audit & Review Report", title_style))
    story.append(Paragraph(
        f"<b>Review ID:</b> {result.review_id} &nbsp;|&nbsp; "
        f"<b>Language:</b> {result.language} &nbsp;|&nbsp; "
        f"<b>Overall Quality:</b> {result.overall_quality} &nbsp;|&nbsp; "
        f"<b>File:</b> {filename or 'source_snippet'} &nbsp;|&nbsp; "
        f"<b>Duration:</b> {result.analysis_duration_sec}s",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=10))

    # Executive Summary
    story.append(Paragraph("Executive Summary", h2_style))
    story.append(Paragraph(result.summary, body_style))
    story.append(Spacer(1, 8))

    # Issues Table
    story.append(Paragraph(f"Detected Issues ({len(result.issues)})", h2_style))
    if not result.issues:
        story.append(Paragraph("No security flaws or code quality issues detected.", body_style))
    else:
        table_data = [["Severity", "Line", "Category", "Issue Title", "Sources"]]
        for issue in result.issues[:30]:  # Limit for PDF readability
            line_str = str(issue.line_number) if issue.line_number else "-"
            sources_str = ", ".join(issue.detection_sources)
            table_data.append([
                issue.severity,
                line_str,
                issue.category,
                Paragraph(f"<b>{issue.title}</b><br/>{issue.description[:120]}...", body_style),
                sources_str,
            ])

        col_widths = [65, 35, 65, 260, 115]
        t = Table(table_data, colWidths=col_widths, repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(t)

    # Recommendations
    if result.recommendations:
        story.append(Spacer(1, 10))
        story.append(Paragraph("Strategic Recommendations", h2_style))
        for rec in result.recommendations:
            story.append(Paragraph(f"• {rec}", body_style))

    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
