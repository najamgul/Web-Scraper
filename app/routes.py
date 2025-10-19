# routes.py
import os
import re
import json
import csv
import io
from app.enrichment import enrich_threat_intelligence
from flask import session, Blueprint, render_template, request, jsonify, send_file, redirect, url_for, flash
import pandas as pd
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from bson import ObjectId
from app.analytics import (
    get_dashboard_stats,
    get_top_malicious_ips,
    get_top_malicious_domains,
    get_geolocation_data,
    get_threat_timeline,
    get_recent_threats,
    get_classification_breakdown,
    get_top_threat_tags
)

from app.scraper import google_cse_search
from app.vt_shodan_api import vt_lookup_domain, vt_lookup_ip, vt_lookup_url, shodan_lookup
from app.otx_api import otx_lookup
from app.ml_model import classify_threat
from app.forms import InputForm, LoginForm, SignupForm
from app.models import User, IOCResult, Feedback
from app.decorators import login_required

from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill

# Add to routes.py after imports

def format_otx_for_display(otx_data):
    """
    Format OTX data for template display
    """
    if not otx_data or 'error' in otx_data:
        return None
    
    details = otx_data.get('details', {})
    
    # Extract key information
    formatted = {
        'threat_score': otx_data.get('threat_score', 0),
        'classification': otx_data.get('classification', 'Unknown'),
        'source_count': otx_data.get('source_count', 0),
        'summary': details.get('summary', 'No summary available'),
        'risk_level': details.get('risk_level', 'Unknown'),
        
        # Lists and counts
        'pulses': details.get('pulses', 0),
        'malicious_indicators': details.get('malicious_indicators', 0),
        'malicious_reports': details.get('malicious_reports', 0),
        
        # Arrays
        'malware_families': details.get('malware_families', []),
        'attack_techniques': details.get('attack_techniques', []),
        'top_tags': details.get('top_tags', []),
        'adversaries': details.get('adversaries', []),
        'top_pulses': details.get('top_pulses', []),
        
        # Location (for IPs)
        'country': details.get('country', ''),
        'city': details.get('city', ''),
        'asn': details.get('asn', ''),
        
        # Other
        'reputation': details.get('reputation', 0),
        'vulnerabilities': details.get('vulnerabilities', 0),
        
        # Raw data
        'raw': otx_data
    }
    
    return formatted
main_bp = Blueprint("main", __name__)


def detect_ioc_type(ioc):
    """Detect the type of IOC: IP, URL, domain, hash, or keyword."""
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    url_pattern = r"^https?://[^\s/$.?#].[^\s]*$"
    domain_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.[A-Za-z]{2,})+$"
    hash_pattern = r"^[a-fA-F0-9]{32,128}$"

    if re.match(ip_pattern, ioc):
        return "ip"
    elif re.match(url_pattern, ioc):
        return "url"
    elif re.match(domain_pattern, ioc):
        return "domain"
    elif re.match(hash_pattern, ioc):
        return "hash"
    else:
        return "keyword"


# ---- LANDING PAGE (Public - No login required) ----
@main_bp.route("/")
def landing():
    """Public landing page"""
    if 'user_id' in session:
        return redirect(url_for('main.index'))
    return render_template("landing.html")


# ---- INDEX PAGE (Protected - Login required) ----
@main_bp.route("/index", methods=["GET", "POST"])
@login_required
def index():
    form = InputForm()
    if form.validate_on_submit():
        user_input = form.input_data.data.strip()
        if not user_input:
            flash("Please enter a keyword, IP, URL, domain, or hash.", "warning")
            return redirect(url_for("main.index"))

        ioc_type = detect_ioc_type(user_input)

        # Initialize data
        vt_data = {}
        shodan_data = {}
        otx_data = {}
        scraped_data = []

        # --- Query APIs for threat intelligence ---
        otx_data = otx_lookup(user_input, ioc_type) or {}

        if ioc_type == "ip":
            vt_data = vt_lookup_ip(user_input) or {}
            shodan_data = shodan_lookup(user_input) or {}
            
            print("=" * 60)
            print(f"DEBUG - Input: {user_input}")
            print(f"DEBUG - VT Data: {vt_data}")
            print(f"DEBUG - Shodan Data: {shodan_data}")
            print("=" * 60)

        elif ioc_type == "url":
            vt_data = vt_lookup_url(user_input) or {}

        elif ioc_type == "domain":
            vt_data = vt_lookup_domain(user_input) or {}

        elif ioc_type == "hash":
            vt_data = vt_lookup_domain(user_input) or {}
        
        if ioc_type == "keyword":
            scraped_data = google_cse_search(user_input)
        
        classification = classify_threat(
            vt_data=vt_data,
            shodan_data=shodan_data,
            otx_data=otx_data,
            ioc_type=ioc_type,
            user_input=user_input
        )
        # ✅ NEW: Generate AI enrichment
        enrichment = enrich_threat_intelligence(
            ioc_value=user_input,
            ioc_type=ioc_type,
            vt_data=vt_data,
            shodan_data=shodan_data,
            otx_data=otx_data,
            classification=classification
            )

        # --- Save to MongoDB ---
        user_ref = None
        if session.get("user_id"):
            try:
                user_ref = User.objects.get(id=session.get("user_id"))
            except:
                pass

        ioc_result = IOCResult(
            input_value=user_input,
            type=ioc_type,
            vt_report=vt_data,
            shodan_report=shodan_data,
            otx_report=otx_data,
            scraped_data=scraped_data,
            classification=classification,
            enrichment_context=enrichment,
            user_id=user_ref,
            timestamp=datetime.utcnow()
        )
        ioc_result.save()

        # --- Chart Data (MongoDB aggregation) ---
        chart_data = {
            "labels": ["Malicious", "Benign", "Informational", "Unknown"],
            "values": [
                IOCResult.objects(classification="Malicious").count(),
                IOCResult.objects(classification="Benign").count(),
                IOCResult.objects(classification="Informational").count(),
                IOCResult.objects(classification="Unknown").count(),
            ]
        }

        return render_template(
            "results.html", 
            results={
                "ioc_id": str(ioc_result.id),
                "input": user_input,
                "type": ioc_type,
                "vt": vt_data,
                "shodan": shodan_data,
                "otx": otx_data,
                "otx_formatted": format_otx_for_display(otx_data),
                "scraped": scraped_data,
                "classification": classification,
                "enrichment": enrichment 
            }, 
            chart_data=json.dumps(chart_data)
        )
    return render_template("index.html", form=form)

# ---- FEEDBACK (Protected) ----
@main_bp.route("/feedback/<ioc_id>", methods=["POST"])
@login_required
def feedback(ioc_id):
    feedback_value = request.form.get("feedback")
    if feedback_value not in ["Malicious", "Benign", "Informational"]:
        return jsonify({"error": "Invalid feedback"}), 400

    try:
        ioc = IOCResult.objects.get(id=ioc_id)
        new_feedback = Feedback(ioc_id=ioc, correct_classification=feedback_value)
        new_feedback.save()
        return jsonify({"message": "Feedback saved"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ---- EXPORT ROUTES (Protected) ----
# ---- EXPORT ROUTES (Updated) ----
@main_bp.route("/export/<format>/<ioc_id>")
@login_required
def export(format, ioc_id):
    """Export single result in multiple formats"""
    try:
        result = IOCResult.objects.get(id=ioc_id)
    except Exception as e:
        return jsonify({"error": f"Result not found: {str(e)}"}), 404
    
    # JSON Export
    if format == "json":
        return jsonify({
            "id": str(result.id),
            "input": result.input_value,
            "type": result.type,
            "classification": result.classification,
            "timestamp": result.timestamp.isoformat() if result.timestamp else None,
            "vt_report": result.vt_report,
            "shodan_report": result.shodan_report,
            "otx_report": result.otx_report,
            "scraped_data": result.scraped_data
        })
    
    # CSV Export
    elif format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(["Field", "Value"])
        writer.writerow(["ID", str(result.id)])
        writer.writerow(["Input", result.input_value])
        writer.writerow(["Type", result.type])
        writer.writerow(["Classification", result.classification])
        writer.writerow(["Timestamp", result.timestamp.strftime("%Y-%m-%d %H:%M:%S") if result.timestamp else "N/A"])
        writer.writerow([])
        
        # VirusTotal Report
        writer.writerow(["VirusTotal Report"])
        if result.vt_report:
            for key, value in result.vt_report.items():
                writer.writerow([key, str(value)])
        else:
            writer.writerow(["No data"])
        writer.writerow([])
        
        # Shodan Report
        writer.writerow(["Shodan Report"])
        if result.shodan_report:
            for key, value in result.shodan_report.items():
                writer.writerow([key, str(value)])
        else:
            writer.writerow(["No data"])
        writer.writerow([])
        
        # OTX Report
        writer.writerow(["AlienVault OTX Report"])
        if result.otx_report:
            for key, value in result.otx_report.items():
                writer.writerow([key, str(value)])
        else:
            writer.writerow(["No data"])
        
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"threat_report_{result.input_value}_{datetime.now().strftime('%Y%m%d')}.csv"
        )
    
    # Excel Export
    elif format == "excel":
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Threat Report"
        
        # Styling
        header_fill = PatternFill(start_color="4361ee", end_color="4361ee", fill_type="solid")
        header_font = Font(color="FFFFFF", bold=True, size=12)
        
        # Main Info
        ws['A1'] = "Threat Intelligence Report"
        ws['A1'].font = Font(bold=True, size=16)
        ws.merge_cells('A1:B1')
        
        row = 3
        ws[f'A{row}'] = "Field"
        ws[f'B{row}'] = "Value"
        ws[f'A{row}'].fill = header_fill
        ws[f'B{row}'].fill = header_fill
        ws[f'A{row}'].font = header_font
        ws[f'B{row}'].font = header_font
        
        row += 1
        data = [
            ["ID", str(result.id)],
            ["Input", result.input_value],
            ["Type", result.type],
            ["Classification", result.classification],
            ["Timestamp", result.timestamp.strftime("%Y-%m-%d %H:%M:%S") if result.timestamp else "N/A"]
        ]
        
        for item in data:
            ws[f'A{row}'] = item[0]
            ws[f'B{row}'] = item[1]
            row += 1
        
        # VirusTotal Section
        row += 2
        ws[f'A{row}'] = "VirusTotal Report"
        ws[f'A{row}'].font = Font(bold=True, size=14)
        row += 1
        if result.vt_report:
            for key, value in result.vt_report.items():
                ws[f'A{row}'] = str(key)
                ws[f'B{row}'] = str(value)
                row += 1
        else:
            ws[f'A{row}'] = "No data"
            row += 1
        
        # Shodan Section
        row += 2
        ws[f'A{row}'] = "Shodan Report"
        ws[f'A{row}'].font = Font(bold=True, size=14)
        row += 1
        if result.shodan_report:
            for key, value in result.shodan_report.items():
                ws[f'A{row}'] = str(key)
                ws[f'B{row}'] = str(value)
                row += 1
        else:
            ws[f'A{row}'] = "No data"
            row += 1
        
        # OTX Section
        row += 2
        ws[f'A{row}'] = "AlienVault OTX Report"
        ws[f'A{row}'].font = Font(bold=True, size=14)
        row += 1
        if result.otx_report:
            for key, value in result.otx_report.items():
                ws[f'A{row}'] = str(key)
                ws[f'B{row}'] = str(value)
                row += 1
        else:
            ws[f'A{row}'] = "No data"
            row += 1
        
        # Adjust column widths
        ws.column_dimensions['A'].width = 30
        ws.column_dimensions['B'].width = 50
        
        # Save to BytesIO
        excel_file = io.BytesIO()
        wb.save(excel_file)
        excel_file.seek(0)
        
        return send_file(
            excel_file,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name=f"threat_report_{result.input_value}_{datetime.now().strftime('%Y%m%d')}.xlsx"
        )
    
    # PDF Export
    elif format == "pdf":
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#4361ee'),
            spaceAfter=30,
            alignment=1  # Center
        )
        story.append(Paragraph("Threat Intelligence Report", title_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Basic Info Table
        basic_data = [
            ['Field', 'Value'],
            ['Input', result.input_value],
            ['Type', result.type],
            ['Classification', result.classification],
            ['Timestamp', result.timestamp.strftime("%Y-%m-%d %H:%M:%S") if result.timestamp else "N/A"]
        ]
        
        basic_table = Table(basic_data, colWidths=[2*inch, 4*inch])
        basic_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4361ee')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(basic_table)
        story.append(Spacer(1, 0.3*inch))
        
        # VirusTotal Report
        story.append(Paragraph("VirusTotal Report", styles['Heading2']))
        story.append(Spacer(1, 0.1*inch))
        if result.vt_report and isinstance(result.vt_report, dict):
            vt_data = [['Field', 'Value']] + [[str(k), str(v)] for k, v in list(result.vt_report.items())[:10]]
            vt_table = Table(vt_data, colWidths=[2*inch, 4*inch])
            vt_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4cc9f0')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(vt_table)
        else:
            story.append(Paragraph("No VirusTotal data available", styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Shodan Report
        story.append(Paragraph("Shodan Report", styles['Heading2']))
        story.append(Spacer(1, 0.1*inch))
        if result.shodan_report and isinstance(result.shodan_report, dict):
            shodan_data = [['Field', 'Value']] + [[str(k), str(v)] for k, v in list(result.shodan_report.items())[:10]]
            shodan_table = Table(shodan_data, colWidths=[2*inch, 4*inch])
            shodan_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4cc9f0')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(shodan_table)
        else:
            story.append(Paragraph("No Shodan data available", styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # OTX Report
        story.append(Paragraph("AlienVault OTX Report", styles['Heading2']))
        story.append(Spacer(1, 0.1*inch))
        if result.otx_report and isinstance(result.otx_report, dict):
            otx_data = [['Field', 'Value']] + [[str(k), str(v)] for k, v in list(result.otx_report.items())[:10]]
            otx_table = Table(otx_data, colWidths=[2*inch, 4*inch])
            otx_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4cc9f0')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(otx_table)
        else:
            story.append(Paragraph("No OTX data available", styles['Normal']))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"threat_report_{result.input_value}_{datetime.now().strftime('%Y%m%d')}.pdf"
        )
    
    else:
        return jsonify({
            "error": "Invalid format. Supported formats: json, csv, excel, pdf"
        }), 400

# ---- HISTORY (Protected) ----
@main_bp.route("/history")
@login_required
def history():
    """View search history"""
    user_id = session.get("user_id")
    try:
        user = User.objects.get(id=user_id)
        results = IOCResult.objects(user_id=user).order_by('-timestamp')
    except:
        results = []
    
    return render_template("history.html", results=results)


# ---- LOGIN PAGE ----
@main_bp.route("/login", methods=["GET", "POST"])
def login():
    if 'user_id' in session:
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        try:
            # ✅ Changed from form.username.data to form.email.data
            user = User.objects.get(email=form.email.data)
            if check_password_hash(user.password, form.password.data):
                session["user_id"] = str(user.id)
                session["username"] = user.email
                flash("Login successful!", "success")
                
                # Redirect to original page if stored
                next_page = session.pop('next', None)
                return redirect(next_page or url_for('main.index'))
            else:
                flash("Invalid email or password", "danger")
        except User.DoesNotExist:
            flash("Invalid email or password", "danger")
    
    return render_template("login.html", form=form)


# ---- SIGNUP PAGE ----
@main_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if 'user_id' in session:
        return redirect(url_for('main.index'))
    
    form = SignupForm()
    if form.validate_on_submit():
        # ✅ Email validation is handled by form validator
        # No need to check here, form.validate_email() does it
        hashed_pw = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(email=form.email.data, password=hashed_pw)
        new_user.save()
        flash("Account created successfully! Please login.", "success")
        return redirect(url_for("main.login"))
    
    return render_template("signup.html", form=form)

# ---- DASHBOARD (Protected) ----
@main_bp.route("/dashboard")
@login_required
def dashboard():
    """
    Threat Correlation Dashboard
    """
    try:
        # Get all dashboard data
        stats = get_dashboard_stats()
        top_ips = get_top_malicious_ips(limit=10)
        top_domains = get_top_malicious_domains(limit=10)
        geo_data = get_geolocation_data()
        timeline = get_threat_timeline(days=30)
        recent_threats = get_recent_threats(limit=20)
        classification_breakdown = get_classification_breakdown()
        top_tags = get_top_threat_tags(limit=15)
        
        return render_template(
            'dashboard.html',
            stats=stats,
            top_ips=top_ips,
            top_domains=top_domains,
            geo_data=json.dumps(geo_data),
            timeline=json.dumps(timeline),
            recent_threats=recent_threats,
            classification_breakdown=classification_breakdown,
            top_tags=top_tags
        )
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash("Error loading dashboard", "danger")
        return redirect(url_for('main.index'))


# ---- API ENDPOINT: Real-time Threat Feed ----
@main_bp.route("/api/threats/recent")
@login_required
def api_recent_threats():
    """
    API endpoint for real-time threat feed updates
    """
    try:
        limit = request.args.get('limit', 20, type=int)
        recent = get_recent_threats(limit=limit)
        return jsonify(recent)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
# ---- LOGOUT ----
@main_bp.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for("main.landing"))