"""
Copyright Documentation PDF Generator
Strips comments from source files and produces a styled multi-page PDF
for copyright registration as proof of original work.
"""

import re
import os
import ast
import textwrap
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak,
    Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.platypus.flowables import Flowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Preformatted

# ─── Project metadata ────────────────────────────────────────────────────────
PROJECT_NAME    = "Web Scraper for Data Extraction and Threat Intelligence"
AUTHORS         = [
    "Najam Gul",
    "Rajput Kalyani Indrasing",
    "Namboodiri Megha A K Sathyan",
    "Mohite Dnyanesh Bharat",
]
MENTOR          = "Ms. Neha Ashok"
AUTHOR          = AUTHORS[0]          # primary author for footer/meta
YEAR            = "2025"
REPO            = "github.com/najamgul/Web-Scraper"
OUTPUT_PATH     = r"d:\documents\GitHub\Web-Scraper\IPR\Copyright_Source_Code_Proof_v2.pdf"

# ─── Files to include ────────────────────────────────────────────────────────
BASE = r"d:\documents\GitHub\Web-Scraper\app"

FILE_GROUPS = [
    {
        "section": "API Integration Layer",
        "files": [
            (os.path.join(BASE, "abuseipdb_api.py"),          "AbuseIPDB API"),
            (os.path.join(BASE, "otx_api.py"),                "OTX (AlienVault) API"),
            (os.path.join(BASE, "vt_shodan_api.py"),          "VirusTotal & Shodan API"),
        ]
    },
    {
        "section": "Bulk Investigation Module",
        "files": [
            (os.path.join(BASE, "bulk_investigation_routes.py"), "Bulk Investigation Routes"),
        ]
    },
    {
        "section": "Machine Learning Pipeline",
        "files": [
            (os.path.join(BASE, "ml_model_improved.py"),      "Improved ML Model (Multi-Model Pipeline)"),
        ]
    },
    {
        "section": "Core Orchestration & Routing",
        "files": [
            (os.path.join(BASE, "orchestrator.py"),           "Orchestrator"),
            (os.path.join(BASE, "routes.py"),                 "Routes"),
            (os.path.join(BASE, "scraper.py"),                "Scraper"),
        ]
    },
    {
        "section": "Analytics & Intelligence Enrichment",
        "files": [
            (os.path.join(BASE, "analytics.py"),              "Analytics"),
            (os.path.join(BASE, "enrichment.py"),             "Enrichment"),
            (os.path.join(BASE, "llm_service.py"),            "LLM Services"),
        ]
    },
]

# ─── Comment stripping ───────────────────────────────────────────────────────

def clean_source(source: str) -> str:
    """
    Remove comments and docstrings from Python source while perfectly
    preserving indentation and line structure.
    """
    cleaned = _strip_comments_line_safe(source)
    # Collapse 3+ consecutive blank lines down to 2
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
    # Remove trailing whitespace per line
    cleaned = '\n'.join(line.rstrip() for line in cleaned.splitlines())
    return cleaned.strip()


def _strip_comments_line_safe(source: str) -> str:
    """
    Line-by-line comment & docstring stripper that preserves indentation.

    Strategy:
      1. Walk every line.
      2. Remove ``# …`` comments (respecting string literals on the same line).
      3. Track triple-quote docstring regions and blank those lines entirely.
      4. Leave everything else — including leading whitespace — untouched.
    """
    import tokenize, io

    src_lines = source.splitlines(keepends=True)
    num_lines = len(src_lines)

    # ---------- Phase 1: use tokenize to find removable spans ----------
    comment_lines = set()          # line numbers (1-based) with inline comments
    comment_col   = {}             # line_no -> column where # starts
    docstring_ranges = []          # [(start_line, end_line), …]  1-based inclusive

    try:
        readline = io.StringIO(source).readline
        tokens = list(tokenize.generate_tokens(readline))

        for idx, (ttype, tstr, tstart, tend, tline) in enumerate(tokens):
            if ttype == tokenize.COMMENT:
                comment_lines.add(tstart[0])
                comment_col[tstart[0]] = tstart[1]

            elif ttype == tokenize.STRING and tstr.startswith(('"""', "'''")):
                # Decide if this string is a docstring (= statement-level string
                # right after a colon / module-level / class-level).
                is_docstring = False

                # Look backwards for the nearest meaningful token
                for j in range(idx - 1, -1, -1):
                    pt = tokens[j][0]
                    if pt in (tokenize.NEWLINE, tokenize.NL,
                              tokenize.INDENT, tokenize.DEDENT,
                              tokenize.ENCODING, tokenize.COMMENT):
                        continue
                    if pt == tokenize.OP and tokens[j][1] == ':':
                        is_docstring = True
                    break

                # Module-level docstring (appears right at the top)
                if idx < 4:
                    is_docstring = True

                if is_docstring:
                    docstring_ranges.append((tstart[0], tend[0]))

    except tokenize.TokenError:
        pass  # on syntax error fall back to regex below

    # ---------- Phase 2: build set of lines inside docstrings ----------
    docstring_lines = set()
    for ds_start, ds_end in docstring_ranges:
        for ln in range(ds_start, ds_end + 1):
            docstring_lines.add(ln)

    # ---------- Phase 3: rebuild source line by line ----------
    out = []
    for line_no_0, line in enumerate(src_lines):
        line_no = line_no_0 + 1          # tokenize uses 1-based

        # Lines entirely inside a docstring → skip
        if line_no in docstring_lines:
            continue

        # Lines with an inline comment → trim comment portion
        if line_no in comment_lines:
            col = comment_col[line_no]
            if col == 0:
                # Whole line is a comment → skip
                continue
            # Keep everything *before* the #, but strip trailing whitespace
            line = line[:col].rstrip() + '\n'

        out.append(line)

    result = ''.join(out)

    # ---------- Phase 4 (fallback): if tokenize gave us nothing, use regex ---
    if not comment_lines and not docstring_ranges:
        result = re.sub(r'(?m)^\s*#.*$', '', source)          # full-line comments
        result = re.sub(r'(?m)[ \t]+#[^\n]*', '', result)    # inline comments
        result = re.sub(r'"""[\s\S]*?"""', '', result)        # triple-double
        result = re.sub(r"'''[\s\S]*?'''", '', result)        # triple-single

    return result


# ─── PDF generation ──────────────────────────────────────────────────────────

PAGE_W, PAGE_H = A4
MARGIN = 2 * cm

# Colors
COLOR_NAVY      = colors.HexColor("#0A1628")
COLOR_BLUE      = colors.HexColor("#1E3A5F")
COLOR_ACCENT    = colors.HexColor("#2563EB")
COLOR_GOLD      = colors.HexColor("#D97706")
COLOR_LIGHT_BG  = colors.HexColor("#F0F4FF")
COLOR_CODE_BG   = colors.HexColor("#1E293B")
COLOR_CODE_FG   = colors.HexColor("#E2E8F0")
COLOR_GRAY      = colors.HexColor("#64748B")
COLOR_WHITE     = colors.white
COLOR_DIVIDER   = colors.HexColor("#CBD5E1")


def make_styles():
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CopyrightTitle',
        fontName='Helvetica-Bold',
        fontSize=28,
        textColor=COLOR_WHITE,
        alignment=TA_CENTER,
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        'Subtitle',
        fontName='Helvetica',
        fontSize=13,
        textColor=colors.HexColor("#93C5FD"),
        alignment=TA_CENTER,
        spaceAfter=4,
    )
    meta_style = ParagraphStyle(
        'Meta',
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor("#CBD5E1"),
        alignment=TA_CENTER,
        spaceAfter=2,
    )
    section_style = ParagraphStyle(
        'SectionHeader',
        fontName='Helvetica-Bold',
        fontSize=16,
        textColor=COLOR_WHITE,
        spaceAfter=8,
        spaceBefore=6,
    )
    file_header_style = ParagraphStyle(
        'FileHeader',
        fontName='Helvetica-Bold',
        fontSize=12,
        textColor=COLOR_ACCENT,
        spaceAfter=4,
        spaceBefore=8,
        leftIndent=0,
    )
    body_style = ParagraphStyle(
        'Body',
        fontName='Helvetica',
        fontSize=9,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=4,
    )
    toc_item_style = ParagraphStyle(
        'TOCItem',
        fontName='Helvetica',
        fontSize=10,
        textColor=COLOR_BLUE,
        spaceAfter=3,
        leftIndent=10,
    )
    toc_section_style = ParagraphStyle(
        'TOCSectionItem',
        fontName='Helvetica-Bold',
        fontSize=11,
        textColor=COLOR_NAVY,
        spaceAfter=2,
        spaceBefore=6,
    )
    note_style = ParagraphStyle(
        'Note',
        fontName='Helvetica-Oblique',
        fontSize=8,
        textColor=COLOR_GRAY,
        spaceAfter=2,
    )
    return {
        'title': title_style,
        'subtitle': subtitle_style,
        'meta': meta_style,
        'section': section_style,
        'file_header': file_header_style,
        'body': body_style,
        'toc_item': toc_item_style,
        'toc_section': toc_section_style,
        'note': note_style,
    }


class ColorBox(Flowable):
    """A filled rounded rectangle for header background."""
    def __init__(self, width, height, color, radius=4):
        Flowable.__init__(self)
        self.width = width
        self.height = height
        self.color = color
        self.radius = radius

    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.roundRect(0, 0, self.width, self.height,
                            self.radius, fill=1, stroke=0)


def header_footer(canvas, doc):
    """Draw page header, footer, and 5-person signature strip on every page except the cover."""
    canvas.saveState()
    page_num = doc.page
    
    if page_num == 1:
        canvas.restoreState()
        return
    
    w = PAGE_W
    
    # Top bar
    canvas.setFillColor(COLOR_NAVY)
    canvas.rect(0, PAGE_H - 1.2*cm, w, 1.2*cm, fill=1, stroke=0)
    
    canvas.setFont("Helvetica-Bold", 7)
    canvas.setFillColor(COLOR_WHITE)
    canvas.drawString(MARGIN, PAGE_H - 0.7*cm, PROJECT_NAME)
    
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#93C5FD"))
    right_text = "COPYRIGHT DOCUMENTATION — PROOF OF ORIGINAL WORK"
    canvas.drawRightString(w - MARGIN, PAGE_H - 0.7*cm, right_text)
    
    # ── 5-person signature strip (above footer bar) ──────────────────────────
    signers = AUTHORS + [MENTOR]
    num_signers = len(signers)
    roles = ["Author"] * len(AUTHORS) + ["Mentor"]
    usable = w - 2 * MARGIN
    col_w = usable / num_signers
    
    sig_base_y = 1.2 * cm       # just above the footer bar
    line_y     = sig_base_y + 1.4 * cm
    name_y     = sig_base_y + 0.9 * cm
    role_y     = sig_base_y + 0.5 * cm
    line_len   = col_w * 0.8
    
    for idx, (signer, role) in enumerate(zip(signers, roles)):
        x_center = MARGIN + col_w * idx + col_w / 2
        x_start  = x_center - line_len / 2
        
        # Signature line
        canvas.setStrokeColor(COLOR_DIVIDER)
        canvas.setLineWidth(0.5)
        canvas.line(x_start, line_y, x_start + line_len, line_y)
        
        # Name
        canvas.setFont("Helvetica-Bold", 5.5)
        canvas.setFillColor(COLOR_NAVY)
        canvas.drawCentredString(x_center, name_y, signer)
        
        # Role
        canvas.setFont("Helvetica", 5)
        canvas.setFillColor(COLOR_GRAY)
        canvas.drawCentredString(x_center, role_y, role)
    
    # Bottom bar
    canvas.setFillColor(COLOR_BLUE)
    canvas.rect(0, 0, w, 0.9*cm, fill=1, stroke=0)
    
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#93C5FD"))
    canvas.drawString(MARGIN, 0.3*cm, f"© {YEAR} {', '.join(AUTHORS)}  |  {REPO}")
    
    canvas.setFillColor(COLOR_GOLD)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawRightString(w - MARGIN, 0.3*cm, f"Page {page_num}")
    
    canvas.restoreState()


def build_cover(styles):
    elements = []
    usable_w = PAGE_W - 2 * MARGIN
    
    # ── Big cover background stripe ──────────────────────────────────────────
    # We can't draw rect before content easily, so use a Table as a colored block
    
    # Top decorative block
    top_data = [[
        Paragraph(
            f'<font size="9" color="#93C5FD">INTELLECTUAL PROPERTY REGISTRATION</font>',
            styles['meta']
        )
    ]]
    top_table = Table(top_data, colWidths=[usable_w])
    top_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), COLOR_NAVY),
        ('TOPPADDING', (0,0), (-1,-1), 18),
        ('BOTTOMPADDING', (0,0), (-1,-1), 18),
        ('LEFTPADDING', (0,0), (-1,-1), 20),
        ('RIGHTPADDING', (0,0), (-1,-1), 20),
        ('ROUNDEDCORNERS', [8, 8, 0, 0]),
    ]))
    
    # Hero block
    hero_data = [[
        Paragraph(PROJECT_NAME, styles['title'])
    ]]
    hero_table = Table(hero_data, colWidths=[usable_w])
    hero_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), COLOR_BLUE),
        ('TOPPADDING', (0,0), (-1,-1), 30),
        ('BOTTOMPADDING', (0,0), (-1,-1), 30),
        ('LEFTPADDING', (0,0), (-1,-1), 20),
        ('RIGHTPADDING', (0,0), (-1,-1), 20),
    ]))
    
    sub_data = [[
        Paragraph(
            "Source Code Copyright Document &mdash; Proof of Original Work",
            styles['subtitle']
        )
    ]]
    sub_table = Table(sub_data, colWidths=[usable_w])
    sub_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), COLOR_BLUE),
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 30),
        ('LEFTPADDING', (0,0), (-1,-1), 20),
        ('RIGHTPADDING', (0,0), (-1,-1), 20),
    ]))
    
    elements.append(Spacer(1, 60))
    elements.append(top_table)
    elements.append(hero_table)
    elements.append(sub_table)
    elements.append(Spacer(1, 20))
    
    # ── Info cards ───────────────────────────────────────────────────────────
    authors_display = ', '.join(AUTHORS)
    info_rows = [
        ["AUTHORS / APPLICANTS", authors_display],
        ["MENTOR",              MENTOR],
        ["PROJECT",             PROJECT_NAME],
        ["YEAR OF CREATION",    YEAR],
        ["REPOSITORY",          REPO],
        ["DOCUMENT DATE",       datetime.now().strftime("%B %d, %Y")],
        ["DOCUMENT PURPOSE",    "Copyright Registration — Proof of Original Source Code"],
    ]
    
    info_table = Table(
        [[Paragraph(f'<b><font color="#2563EB">{k}</font></b>',
                    ParagraphStyle('k', fontName='Helvetica-Bold', fontSize=8)),
          Paragraph(v, ParagraphStyle('v', fontName='Helvetica', fontSize=9,
                                      textColor=COLOR_NAVY))]
         for k, v in info_rows],
        colWidths=[6*cm, usable_w - 6*cm],
        hAlign='LEFT'
    )
    info_table.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), COLOR_LIGHT_BG),
        ('BACKGROUND',    (0, 0), (0, -1), colors.HexColor("#DBEAFE")),
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING',   (0, 0), (-1, -1), 12),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 12),
        ('ROWBACKGROUNDS',(0, 0), (-1, -1), [COLOR_LIGHT_BG, colors.HexColor("#E0EAFF")]),
        ('LINEBELOW',     (0, 0), (-1, -2), 0.5, COLOR_DIVIDER),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 20))
    
    # ── File list ────────────────────────────────────────────────────────────
    note_data = [[
        Paragraph(
            "This document contains the complete, comment-stripped source code of the files listed below, "
            "presented as evidence of original authorship for copyright registration purposes. "
            "Each module is presented in clean form to demonstrate the original creative work.",
            ParagraphStyle('n', fontName='Helvetica', fontSize=9,
                           textColor=colors.HexColor("#1E3A5F"), alignment=TA_JUSTIFY)
        )
    ]]
    note_table = Table(note_data, colWidths=[usable_w])
    note_table.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), colors.HexColor("#FFF7ED")),
        ('TOPPADDING',    (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('LEFTPADDING',   (0,0), (-1,-1), 14),
        ('RIGHTPADDING',  (0,0), (-1,-1), 14),
        ('LINEBEFOREBEFORE', (0,0), (0,0), 3, COLOR_GOLD),
    ]))
    elements.append(note_table)
    elements.append(Spacer(1, 16))
    
    # Files covered
    all_files = []
    for grp in FILE_GROUPS:
        for path, label in grp['files']:
            all_files.append((grp['section'], label, os.path.basename(path)))
    
    file_rows = [["Section", "Module Name", "Filename"]]
    for section, label, fname in all_files:
        file_rows.append([
            Paragraph(f'<font size="8">{section}</font>',
                      ParagraphStyle('s', fontName='Helvetica', fontSize=8, textColor=COLOR_GRAY)),
            Paragraph(f'<b><font size="9">{label}</font></b>',
                      ParagraphStyle('l', fontName='Helvetica-Bold', fontSize=9, textColor=COLOR_NAVY)),
            Paragraph(f'<font size="8" color="#1E3A5F">{fname}</font>',
                      ParagraphStyle('f', fontName='Courier', fontSize=8)),
        ])
    
    col_w = [5.5*cm, 8*cm, usable_w - 13.5*cm]
    ftable = Table(file_rows, colWidths=col_w)
    ftable.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0), COLOR_NAVY),
        ('TEXTCOLOR',     (0, 0), (-1, 0), COLOR_WHITE),
        ('FONTNAME',      (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, 0), 9),
        ('TOPPADDING',    (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('ALIGN',         (0, 0), (-1, -1), 'LEFT'),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_BG]),
        ('LINEBELOW',     (0, 0), (-1, -2), 0.3, COLOR_DIVIDER),
        ('TOPPADDING',    (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ('LEFTPADDING',   (0, 0), (-1, -1), 10),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(ftable)
    elements.append(PageBreak())
    return elements


def build_section_header(section_title, styles):
    """Build a full-width colored section divider page element."""
    usable_w = PAGE_W - 2 * MARGIN
    data = [[
        Paragraph(
            f'<font color="white" size="14"><b>{section_title}</b></font>',
            ParagraphStyle('sh', fontName='Helvetica-Bold', fontSize=14,
                           textColor=COLOR_WHITE, alignment=TA_LEFT)
        )
    ]]
    table = Table(data, colWidths=[usable_w])
    table.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), COLOR_BLUE),
        ('TOPPADDING',    (0,0), (-1,-1), 14),
        ('BOTTOMPADDING', (0,0), (-1,-1), 14),
        ('LEFTPADDING',   (0,0), (-1,-1), 16),
        ('RIGHTPADDING',  (0,0), (-1,-1), 16),
    ]))
    return table


def build_file_block(filepath, label, styles):
    """Build the display block for one source file."""
    elements = []
    usable_w = PAGE_W - 2 * MARGIN
    fname = os.path.basename(filepath)
    
    # Read and clean source
    if not os.path.exists(filepath):
        elements.append(Paragraph(f"⚠ File not found: {filepath}", styles['note']))
        return elements
    
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        raw = f.read()
    
    cleaned = clean_source(raw)
    orig_lines  = len(raw.splitlines())
    clean_lines = len(cleaned.splitlines())
    
    # File header card (clean — no line-count stats)
    header_data = [[
        Paragraph(
            f'<b><font size="12" color="#2563EB">{label}</font></b><br/>'
            f'<font size="8" color="#64748B">{fname}</font>',
            ParagraphStyle('fh', fontName='Helvetica', fontSize=10, leading=16)
        ),
    ]]
    header_table = Table(header_data, colWidths=[usable_w])
    header_table.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), COLOR_LIGHT_BG),
        ('TOPPADDING',    (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING',   (0,0), (-1,-1), 14),
        ('RIGHTPADDING',  (0,0), (-1,-1), 14),
        ('LINEBELOW',     (0,0), (-1,-1), 2, COLOR_ACCENT),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elements.append(Spacer(1, 10))
    elements.append(header_table)
    elements.append(Spacer(1, 4))
    
    # Code block — use Preformatted to PRESERVE indentation exactly
    code_style = ParagraphStyle(
        'Code',
        fontName='Courier',
        fontSize=6.5,
        textColor=COLOR_CODE_FG,
        backColor=COLOR_CODE_BG,
        leftIndent=0,
        rightIndent=0,
        spaceBefore=0,
        spaceAfter=0,
        leading=9,
    )
    
    # Split code into chunks to avoid very large single flowables
    code_lines = cleaned.splitlines()
    CHUNK = 60  # lines per block
    
    for i in range(0, len(code_lines), CHUNK):
        chunk_lines = code_lines[i:i+CHUNK]
        chunk_text = '\n'.join(chunk_lines)
        
        # Use Preformatted — it preserves ALL whitespace (spaces, tabs, newlines)
        # exactly as-is, like an HTML <pre> block.
        pre = Preformatted(chunk_text, code_style)
        
        # Wrap in a dark-background table cell for styling
        code_data = [[pre]]
        code_table = Table(code_data, colWidths=[usable_w])
        code_table.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,-1), COLOR_CODE_BG),
            ('TOPPADDING',    (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING',   (0,0), (-1,-1), 10),
            ('RIGHTPADDING',  (0,0), (-1,-1), 10),
        ]))
        elements.append(code_table)
        elements.append(Spacer(1, 1))
    
    elements.append(Spacer(1, 12))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=COLOR_DIVIDER))
    return elements


def generate_pdf():
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    
    doc = SimpleDocTemplate(
        OUTPUT_PATH,
        pagesize=A4,
        topMargin=1.5*cm,
        bottomMargin=3.5*cm,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        title=f"Copyright Documentation — {PROJECT_NAME}",
        author=AUTHOR,
        subject="Source Code Copyright Proof",
        creator="Antigravity Copyright Generator",
    )
    
    styles = make_styles()
    elements = []
    
    # ── Cover page ───────────────────────────────────────────────────────────
    elements += build_cover(styles)
    
    # ── Source code sections ─────────────────────────────────────────────────
    for grp in FILE_GROUPS:
        # Section header
        elements.append(build_section_header(grp['section'], styles))
        elements.append(Spacer(1, 10))
        
        for filepath, label in grp['files']:
            print(f"  Processing: {label} ({os.path.basename(filepath)})")
            file_elements = build_file_block(filepath, label, styles)
            elements.extend(file_elements)
    
    # ── Closing declaration ───────────────────────────────────────────────────
    elements.append(PageBreak())
    usable_w = PAGE_W - 2 * MARGIN
    
    decl_header = Table([
        [Paragraph('<b><font size="16" color="white">Declaration of Original Authorship</font></b>',
                   ParagraphStyle('d', fontName='Helvetica-Bold', fontSize=16,
                                  textColor=COLOR_WHITE, alignment=TA_CENTER))]
    ], colWidths=[usable_w])
    decl_header.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), COLOR_NAVY),
        ('TOPPADDING', (0,0), (-1,-1), 20),
        ('BOTTOMPADDING', (0,0), (-1,-1), 20),
    ]))
    elements.append(decl_header)
    elements.append(Spacer(1, 20))
    
    authors_bold = ', '.join(f'<b>{a}</b>' for a in AUTHORS)
    declaration_text = (
        f"We, {authors_bold}, hereby declare that the source code presented in this document "
        f"is our original work, created collaboratively during the year {YEAR} "
        f"under the mentorship of <b>{MENTOR}</b>. "
        f"The code constitutes an original literary work eligible for copyright protection "
        f"under applicable intellectual property law.<br/><br/>"
        f"The files presented include the core modules of the <b>{PROJECT_NAME}</b>, "
        f"encompassing API integration, machine learning classification, bulk investigation "
        f"management, threat intelligence orchestration, analytics, and AI-powered enrichment. "
        f"Each file represents substantial creative and technical effort in its design, "
        f"algorithm selection, and implementation.<br/><br/>"
        f"This document is produced for the purpose of copyright registration and serves as "
        f"proof of the original creative expression contained within the listed source files."
    )
    
    elements.append(Paragraph(declaration_text,
                              ParagraphStyle('decl', fontName='Helvetica', fontSize=10,
                                            leading=16, textColor=COLOR_NAVY,
                                            alignment=TA_JUSTIFY)))
    elements.append(Spacer(1, 30))
    
    # Signature lines — one per author + mentor
    sig_style = ParagraphStyle('sig', fontName='Helvetica', fontSize=10)
    sig_bold  = ParagraphStyle('sb',  fontName='Helvetica-Bold', fontSize=10)
    sig_role  = ParagraphStyle('sr',  fontName='Helvetica', fontSize=8, textColor=COLOR_GRAY)
    
    sig_data = []
    for author in AUTHORS:
        sig_data.append([
            Paragraph('_' * 40, sig_style),
            Paragraph('_' * 25, sig_style),
        ])
        sig_data.append([
            Paragraph(f'<b>{author}</b>', sig_bold),
            Paragraph(f'<b>Date:</b> {datetime.now().strftime("%B %d, %Y")}', sig_style),
        ])
        sig_data.append([
            Paragraph('Author & Copyright Holder', sig_role),
            Paragraph('', sig_role),
        ])
        sig_data.append([Spacer(1, 12), Spacer(1, 12)])
    
    # Mentor signature
    sig_data.append([
        Paragraph('_' * 40, sig_style),
        Paragraph('_' * 25, sig_style),
    ])
    sig_data.append([
        Paragraph(f'<b>{MENTOR}</b>', sig_bold),
        Paragraph(f'<b>Date:</b> {datetime.now().strftime("%B %d, %Y")}', sig_style),
    ])
    sig_data.append([
        Paragraph('Project Mentor', sig_role),
        Paragraph('', sig_role),
    ])
    
    sig_table = Table(sig_data, colWidths=[usable_w*0.6, usable_w*0.4])
    sig_table.setStyle(TableStyle([
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('VALIGN', (0,0), (-1,-1), 'BOTTOM'),
    ]))
    elements.append(sig_table)
    
    # ── Build ─────────────────────────────────────────────────────────────────
    print(f"\nBuilding PDF: {OUTPUT_PATH}")
    doc.build(elements, onFirstPage=header_footer, onLaterPages=header_footer)
    print(f"✅ PDF generated successfully!")
    size_kb = os.path.getsize(OUTPUT_PATH) / 1024
    print(f"   File size: {size_kb:.1f} KB")
    print(f"   Location: {OUTPUT_PATH}")


if __name__ == "__main__":
    print("=" * 60)
    print("  Copyright Documentation PDF Generator")
    print(f"  Project: {PROJECT_NAME}")
    print(f"  Author:  {AUTHOR}")
    print("=" * 60)
    print()
    
    total_files = sum(len(g['files']) for g in FILE_GROUPS)
    print(f"Processing {total_files} source files across {len(FILE_GROUPS)} sections...")
    print()
    
    generate_pdf()
