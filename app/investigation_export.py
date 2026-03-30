# app/investigation_export.py
"""
Export helpers for Investigation reports.
Supports: JSON, CSV, PDF (via reportlab)
"""
import io
import csv
import json
from datetime import datetime

# ──────────────────────────────────────────────────────────────────────────────
# Shared builder
# ──────────────────────────────────────────────────────────────────────────────

def build_report_payload(inv, linked_scans):
    """
    Build a unified dict that represents the full investigation report.
    Used by both JSON and PDF exporters.
    """
    severity_map = {
        'low': 'Low', 'medium': 'Medium', 'high': 'High', 'critical': 'Critical'
    }
    status_map = {
        'open': 'Open', 'in_progress': 'In Progress',
        'resolved': 'Resolved', 'closed': 'Closed'
    }

    # Threat summary counts
    counts = {'Malicious': 0, 'Suspicious': 0, 'Benign': 0,
              'Zero-Day': 0, 'Unknown': 0}
    for s in linked_scans:
        cls = (s.get('classification') or 'Unknown').strip()
        cls_lower = cls.lower()
        if 'malicious' in cls_lower:
            counts['Malicious'] += 1
        elif 'suspicious' in cls_lower:
            counts['Suspicious'] += 1
        elif 'benign' in cls_lower:
            counts['Benign'] += 1
        elif 'zero' in cls_lower:
            counts['Zero-Day'] += 1
        else:
            counts['Unknown'] += 1

    return {
        'report_generated_at': datetime.utcnow().isoformat() + 'Z',
        'investigation': {
            'id': inv['id'],
            'title': inv['title'],
            'description': inv.get('description', ''),
            'status': status_map.get(inv['status'], inv['status']),
            'severity': severity_map.get(inv['severity'], inv['severity']),
            'tags': inv.get('tags', []),
            'created_at': inv.get('created_at', ''),
            'updated_at': inv.get('updated_at', ''),
        },
        'summary': {
            'total_iocs': len(linked_scans),
            **counts,
        },
        'iocs': [
            {
                'ioc': s.get('input_value', ''),
                'type': s.get('type', '').upper(),
                'classification': s.get('classification', 'Unknown'),
                'vt_score': s.get('vt_report', {}).get('threat_score', 'N/A'),
                'otx_pulses': s.get('otx_report', {}).get('source_count', 'N/A'),
                'scanned_at': (s.get('timestamp') or '')[:19],
            }
            for s in linked_scans
        ],
        'analyst_notes': [
            {
                'author': n['author'],
                'content': n['content'],
                'created_at': (n.get('created_at') or '')[:19],
            }
            for n in inv.get('notes', [])
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# JSON export
# ──────────────────────────────────────────────────────────────────────────────

def export_json(inv, linked_scans):
    """Return (bytes, filename) for a JSON export."""
    payload = build_report_payload(inv, linked_scans)
    data = json.dumps(payload, indent=2, ensure_ascii=False).encode('utf-8')
    safe_title = "".join(c if c.isalnum() or c in '-_' else '_' for c in inv['title'])[:40]
    filename = f"investigation_{safe_title}_{datetime.utcnow().strftime('%Y%m%d')}.json"
    return data, filename


# ──────────────────────────────────────────────────────────────────────────────
# CSV export
# ──────────────────────────────────────────────────────────────────────────────

def export_csv(inv, linked_scans):
    """Return (bytes, filename) for a CSV export (IOC table only)."""
    payload = build_report_payload(inv, linked_scans)
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL)

    # Header metadata block
    writer.writerow(['# Investigation Report'])
    writer.writerow(['Title', payload['investigation']['title']])
    writer.writerow(['Status', payload['investigation']['status']])
    writer.writerow(['Severity', payload['investigation']['severity']])
    writer.writerow(['Generated', payload['report_generated_at']])
    writer.writerow([])

    # Summary
    writer.writerow(['# Threat Summary'])
    s = payload['summary']
    writer.writerow(['Total IOCs', s['total_iocs']])
    writer.writerow(['Malicious', s['Malicious']])
    writer.writerow(['Suspicious', s['Suspicious']])
    writer.writerow(['Benign', s['Benign']])
    writer.writerow(['Unknown', s['Unknown']])
    writer.writerow([])

    # IOC table
    writer.writerow(['# IOC Details'])
    writer.writerow(['IOC', 'Type', 'Classification', 'VT Threat Score', 'OTX Pulses', 'Scanned At'])
    for ioc in payload['iocs']:
        writer.writerow([
            ioc['ioc'], ioc['type'], ioc['classification'],
            ioc['vt_score'], ioc['otx_pulses'], ioc['scanned_at']
        ])
    writer.writerow([])

    # Notes
    if payload['analyst_notes']:
        writer.writerow(['# Analyst Notes'])
        writer.writerow(['Author', 'Content', 'Created At'])
        for n in payload['analyst_notes']:
            writer.writerow([n['author'], n['content'], n['created_at']])

    data = buf.getvalue().encode('utf-8-sig')  # BOM for Excel compatibility
    safe_title = "".join(c if c.isalnum() or c in '-_' else '_' for c in inv['title'])[:40]
    filename = f"investigation_{safe_title}_{datetime.utcnow().strftime('%Y%m%d')}.csv"
    return data, filename


# ──────────────────────────────────────────────────────────────────────────────
# PDF export
# ──────────────────────────────────────────────────────────────────────────────

def export_pdf(inv, linked_scans):
    """Return (bytes, filename) for a styled PDF report."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, KeepTogether
        )
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    except ImportError:
        raise RuntimeError("reportlab is not installed. Run: pip install reportlab")

    payload = build_report_payload(inv, linked_scans)
    inv_data = payload['investigation']
    summary  = payload['summary']

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.5*cm, bottomMargin=2.5*cm,
        title=f"Investigation: {inv_data['title']}"
    )

    # ── Colour palette ──────────────────────────────────────────────────────
    DARK_BG      = colors.HexColor('#0f172a')
    HEADER_BG    = colors.HexColor('#1e293b')
    ACCENT       = colors.HexColor('#4361ee')
    ACCENT2      = colors.HexColor('#4cc9f0')
    TEXT_LIGHT   = colors.HexColor('#e2e8f0')
    TEXT_MUTED   = colors.HexColor('#94a3b8')
    RED          = colors.HexColor('#e74c3c')
    AMBER        = colors.HexColor('#f59e0b')
    GREEN        = colors.HexColor('#2ecc71')
    PURPLE       = colors.HexColor('#7c3aed')
    ROW_ALT      = colors.HexColor('#1e293b')

    SEV_COLORS = {
        'Low': colors.HexColor('#3498db'),
        'Medium': AMBER,
        'High': RED,
        'Critical': PURPLE,
    }
    CLS_COLORS = {
        'malicious': RED, 'suspicious': AMBER,
        'benign': GREEN, 'zero-day': PURPLE,
    }

    sev_color = SEV_COLORS.get(inv_data['severity'], ACCENT)

    # ── Styles ───────────────────────────────────────────────────────────────
    base = getSampleStyleSheet()

    def S(name, **kw):
        return ParagraphStyle(name, **kw)

    style_title = S('InvTitle', fontSize=22, fontName='Helvetica-Bold',
                    textColor=TEXT_LIGHT, spaceAfter=4, leading=28)
    style_subtitle = S('InvSubtitle', fontSize=10, fontName='Helvetica',
                       textColor=TEXT_MUTED, spaceAfter=2)
    style_section = S('Section', fontSize=13, fontName='Helvetica-Bold',
                       textColor=ACCENT2, spaceBefore=14, spaceAfter=6)
    style_body = S('Body', fontSize=9, fontName='Helvetica',
                   textColor=TEXT_LIGHT, leading=14, spaceAfter=4)
    style_note = S('Note', fontSize=9, fontName='Helvetica',
                   textColor=TEXT_LIGHT, leading=14, spaceAfter=2,
                   leftIndent=8)
    style_note_meta = S('NoteMeta', fontSize=8, fontName='Helvetica',
                        textColor=TEXT_MUTED, spaceAfter=8, leftIndent=8)
    style_tag = S('Tag', fontSize=8, fontName='Helvetica',
                  textColor=ACCENT2, spaceAfter=10)

    story = []

    # ── Cover block ──────────────────────────────────────────────────────────
    # Top accent bar via coloured table cell
    header_data = [[Paragraph(
        f'<font color="#4cc9f0">THREAT INTELLIGENCE</font> &nbsp;'
        f'<font color="#94a3b8">/ Investigation Report</font>',
        S('Cover', fontSize=9, fontName='Helvetica', textColor=TEXT_LIGHT)
    )]]
    header_tbl = Table(header_data, colWidths=[17*cm])
    header_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), HEADER_BG),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 14),
        ('LINEBELOW', (0,0), (-1,-1), 3, sev_color),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph(inv_data['title'], style_title))
    if inv_data['description']:
        story.append(Paragraph(inv_data['description'], style_body))

    # Meta row
    meta_items = [
        f"Status: <b>{inv_data['status']}</b>",
        f"Severity: <b><font color='#{_hex_from_color(sev_color)}'>{inv_data['severity']}</font></b>",
        f"Created: <b>{(inv_data['created_at'] or '')[:10]}</b>",
        f"Generated: <b>{payload['report_generated_at'][:10]}</b>",
    ]
    story.append(Paragraph("  ·  ".join(meta_items),
                 S('Meta', fontSize=9, fontName='Helvetica', textColor=TEXT_MUTED, spaceAfter=4)))

    if inv_data['tags']:
        story.append(Paragraph(
            "  ".join(f"[{t}]" for t in inv_data['tags']), style_tag
        ))

    story.append(HRFlowable(width='100%', thickness=1, color=ACCENT, spaceAfter=10))

    # ── Summary cards ────────────────────────────────────────────────────────
    story.append(Paragraph("Threat Summary", style_section))

    sum_data = [[
        _sum_cell("Total IOCs", str(summary['total_iocs']), ACCENT2),
        _sum_cell("Malicious",  str(summary['Malicious']),  RED),
        _sum_cell("Suspicious", str(summary['Suspicious']), AMBER),
        _sum_cell("Benign",     str(summary['Benign']),     GREEN),
        _sum_cell("Unknown",    str(summary['Unknown']),    TEXT_MUTED),
    ]]
    sum_tbl = Table(sum_data, colWidths=[3.4*cm]*5)
    sum_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), HEADER_BG),
        ('BOX', (0,0), (-1,-1), 0.5, ACCENT),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#334155')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(sum_tbl)
    story.append(Spacer(1, 0.5*cm))

    # ── IOC Table ────────────────────────────────────────────────────────────
    if payload['iocs']:
        story.append(Paragraph(f"Linked IOCs ({len(payload['iocs'])})", style_section))

        tbl_header = ['IOC / Indicator', 'Type', 'Classification', 'VT Score', 'OTX Pulses', 'Scanned']
        tbl_rows = [tbl_header]
        for idx, ioc in enumerate(payload['iocs']):
            cls_lower = (ioc['classification'] or '').lower()
            cls_col = CLS_COLORS.get(cls_lower, TEXT_MUTED)
            tbl_rows.append([
                Paragraph(f'<font name="Courier" size="8">{ioc["ioc"][:55]}</font>',
                          S(f'IOC{idx}', fontSize=8, textColor=TEXT_LIGHT)),
                ioc['type'],
                Paragraph(f'<font color="#{_hex_from_color(cls_col)}"><b>{ioc["classification"]}</b></font>',
                          S(f'CLS{idx}', fontSize=8, textColor=cls_col)),
                str(ioc['vt_score']),
                str(ioc['otx_pulses']),
                ioc['scanned_at'][:10],
            ])

        ioc_tbl = Table(tbl_rows, colWidths=[6.5*cm, 1.4*cm, 2.4*cm, 1.5*cm, 1.6*cm, 2*cm],
                        repeatRows=1)
        ts = [
            ('BACKGROUND', (0,0), (-1,0), ACCENT),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 8),
            ('FONTSIZE', (0,1), (-1,-1), 8),
            ('TEXTCOLOR', (0,1), (-1,-1), TEXT_LIGHT),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [DARK_BG, ROW_ALT]),
            ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#334155')),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]
        ioc_tbl.setStyle(TableStyle(ts))
        story.append(ioc_tbl)
        story.append(Spacer(1, 0.5*cm))

    # ── Analyst Notes ─────────────────────────────────────────────────────────
    if payload['analyst_notes']:
        story.append(Paragraph(f"Analyst Notes ({len(payload['analyst_notes'])})", style_section))
        for note in payload['analyst_notes']:
            block = [
                Paragraph(note['content'], style_note),
                Paragraph(
                    f"— {note['author']}  ·  {note['created_at'][:16]}",
                    style_note_meta
                ),
                HRFlowable(width='100%', thickness=0.5,
                           color=colors.HexColor('#334155'), spaceAfter=6),
            ]
            story.append(KeepTogether(block))

    # ── Footer note ───────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.8*cm))
    story.append(HRFlowable(width='100%', thickness=0.5, color=TEXT_MUTED))
    story.append(Paragraph(
        f"Confidential · ThreatIntel Platform · {payload['report_generated_at'][:19]} UTC",
        S('Footer', fontSize=7, fontName='Helvetica', textColor=TEXT_MUTED,
          alignment=TA_CENTER, spaceBefore=4)
    ))

    doc.build(story, onFirstPage=_add_page_bg, onLaterPages=_add_page_bg)

    data = buf.getvalue()
    safe_title = "".join(c if c.isalnum() or c in '-_' else '_' for c in inv_data['title'])[:40]
    filename = f"investigation_{safe_title}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    return data, filename


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hex_from_color(color):
    """Convert a reportlab Color to a 6-char hex string (no #)."""
    try:
        r = int(color.red * 255)
        g = int(color.green * 255)
        b = int(color.blue * 255)
        return f"{r:02x}{g:02x}{b:02x}"
    except Exception:
        return "e2e8f0"


def _sum_cell(label, value, color):
    """Build a summary stat cell for the summary table."""
    from reportlab.platypus import Paragraph
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib import colors

    TEXT_LIGHT = colors.HexColor('#e2e8f0')
    TEXT_MUTED = colors.HexColor('#94a3b8')

    val_style = ParagraphStyle('V', fontSize=18, fontName='Helvetica-Bold',
                               textColor=color, alignment=TA_CENTER, leading=22)
    lbl_style = ParagraphStyle('L', fontSize=7, fontName='Helvetica',
                               textColor=TEXT_MUTED, alignment=TA_CENTER, leading=10)
    from reportlab.platypus import KeepInFrame
    return [Paragraph(value, val_style), Paragraph(label, lbl_style)]


def _add_page_bg(canvas, doc):
    """Draw a dark background on every page."""
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.pagesizes import A4
    canvas.saveState()
    canvas.setFillColor(rl_colors.HexColor('#0f172a'))
    canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
    canvas.restoreState()
