import os
import re
import json
import csv
import io
from flask import session
from flask import Blueprint, render_template, request, jsonify, send_file, redirect, url_for, flash
from flask import send_file
import pandas as pd
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO
from app.scraper import scrape_and_enrich, google_cse_search, scrape_otx_indicator
from app.vt_shodan_api import vt_lookup_domain, vt_lookup_ip, vt_lookup_url, shodan_lookup
from app.ml_model import classify_threat
from app.forms import LoginForm, SignupForm
from app.models import User
from app.models import IOCResult, Feedback
from werkzeug.security import generate_password_hash, check_password_hash
from app.forms import InputForm
from app import db

main_bp = Blueprint("main", __name__)


def detect_ioc_type(ioc):
    """Detect the type of IOC: IP, URL, domain, hash, or keyword."""
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    url_pattern = r"^https?://[^\s/$.?#].[^\s]*$"
    domain_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.[A-Za-z]{2,})+$"
    hash_pattern = r"^[a-fA-F0-9]{32,128}$"  # MD5/SHA1/SHA256 hashes

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


@main_bp.route("/index", methods=["GET", "POST"])
def index():
    form = InputForm()
    if form.validate_on_submit():
        user_input = form.input_data.data.strip()
        if not user_input:
            flash("Please enter a keyword, IP, URL, domain, or hash.", "warning")
            return redirect(url_for("main.index"))

        ioc_type = detect_ioc_type(user_input)
        vt_data = None
        shodan_data = None
        scraped_data = None

        if ioc_type == "keyword":
            scraped_data = scrape_and_enrich(user_input)
            vt_data = {}
            shodan_data = {}
        elif ioc_type == "domain":
            vt_data = vt_lookup_domain(user_input) or {}
            scraped_data = scrape_otx_indicator(user_input, "domain")
        elif ioc_type == "ip":
            vt_data = vt_lookup_ip(user_input) or {}
            shodan_data = shodan_lookup(user_input) or {}
            scraped_data = scrape_otx_indicator(user_input, "ip")
        elif ioc_type == "url":
            vt_data = vt_lookup_url(user_input) or {}
            scraped_data = scrape_otx_indicator(user_input, "url")
        elif ioc_type == "hash":
            # Implement ThreatFox or other hash enrichment if available
            scraped_data = scrape_otx_indicator(user_input, "hash")
            vt_data = {}
            shodan_data = {}

        if not scraped_data:
            scraped_data = [{"title": "No scraped data found", "context": ""}]

        classification = classify_threat(vt_data, shodan_data, scraped_data, ioc_type, user_input)

        ioc_result = IOCResult(
            input_value=user_input,
            type=ioc_type,
            vt_report=vt_data,
            shodan_report=shodan_data,
            scraped_data=scraped_data,
            classification=classification,
            user_id=session.get("user_id")  # NEW: link to logged-in user
            )

        db.session.add(ioc_result)
        db.session.commit()

        chart_data = {
            "labels": ["Malicious", "Benign", "Informational", "Unknown"],
            "values": [
                IOCResult.query.filter_by(classification="Malicious").count(),
                IOCResult.query.filter_by(classification="Benign").count(),
                IOCResult.query.filter_by(classification="Informational").count(),
                IOCResult.query.filter_by(classification="Unknown").count(),
            ]
        }

        return render_template("results.html", results={
            "input": user_input,
            "type": ioc_type,
            "vt": vt_data,
            "shodan": shodan_data,
            "scraped": scraped_data,
            "classification": classification
        }, chart_data=json.dumps(chart_data))

    return render_template("index.html", form=form)


@main_bp.route("/feedback/<int:ioc_id>", methods=["POST"])
def feedback(ioc_id):
    feedback_value = request.form.get("feedback")
    if feedback_value not in ["Malicious", "Benign", "Informational"]:
        return jsonify({"error": "Invalid feedback"}), 400

    db.session.add(Feedback(ioc_id=ioc_id, correct_classification=feedback_value))
    db.session.commit()
    return jsonify({"message": "Feedback saved"})




@main_bp.route("/export/<fmt>")
def export_results(fmt):
    user_id = session.get("user_id")
    if not user_id:
        flash("You must be logged in to export results.", "warning")
        return redirect(url_for("main.login"))

    results = IOCResult.query.filter_by(user_id=user_id).all()

    export_data = []
    for r in results:
        export_data.append({
            "user": r.user.email if r.user else "unknown",
            "input": r.input_value,
            "input_type": r.type,
            "classification": r.classification,
            "virustotal": r.vt_report,
            "shodan": r.shodan_report,
            "scraped_data": r.scraped_data,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None
        })

    # ---- JSON ----
    if fmt == "json":
        return jsonify(export_data)

    # ---- CSV ---- (already working)
    if fmt == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=export_data[0].keys())
        writer.writeheader()
        writer.writerows(export_data)
        output.seek(0)
        return send_file(io.BytesIO(output.getvalue().encode()), mimetype="text/csv",
                         as_attachment=True, download_name="ioc_results.csv")

    # ---- Excel ----
    if fmt == "xlsx":
        df = pd.DataFrame(export_data)
        output = BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Results")
        output.seek(0)
        return send_file(output, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                         as_attachment=True, download_name="ioc_results.xlsx")

    # ---- PDF ----
    if fmt == "pdf":
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer)
        styles = getSampleStyleSheet()
        elements = []
        for item in export_data:
            elements.append(Paragraph(f"<b>User:</b> {item['user']}", styles["Normal"]))
            elements.append(Paragraph(f"<b>Input:</b> {item['input']} ({item['input_type']})", styles["Normal"]))
            elements.append(Paragraph(f"<b>Classification:</b> {item['classification']}", styles["Normal"]))
            elements.append(Paragraph(f"<b>Timestamp:</b> {item['timestamp']}", styles["Normal"]))
            elements.append(Paragraph(f"<b>VirusTotal:</b> {item['virustotal']}", styles["Normal"]))
            elements.append(Paragraph(f"<b>Shodan:</b> {item['shodan']}", styles["Normal"]))
            elements.append(Paragraph(f"<b>Scraped Data:</b> {item['scraped_data']}", styles["Normal"]))
            elements.append(Spacer(1, 12))
        doc.build(elements)
        buffer.seek(0)
        return send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name="ioc_results.pdf")

    return jsonify({"error": "Unsupported format"}), 400


@main_bp.route("/admin")
def admin_dashboard():
    malicious_count = IOCResult.query.filter_by(classification="Malicious").count()
    benign_count = IOCResult.query.filter_by(classification="Benign").count()
    info_count = IOCResult.query.filter_by(classification="Informational").count()
    unknown_count = IOCResult.query.filter_by(classification="Unknown").count()

    return render_template("admin.html",
        total_iocs=IOCResult.query.count(),
        malicious_count=malicious_count,
        benign_count=benign_count,
        info_count=info_count,
        unknown_count=unknown_count,
        feedback_count=Feedback.query.count(),
        chart_data=json.dumps({
            "labels": ["Malicious", "Benign", "Informational", "Unknown"],
            "values": [malicious_count, benign_count, info_count, unknown_count]
        })
    )

@main_bp.route("/")
def landing():
    return render_template("landing.html")

# Signup
@main_bp.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session["user_id"] = user.id   # save logged-in user ID
            flash("Login successful!", "success")
            return redirect(url_for("main.index"))
        else:
            flash("Invalid email or password", "danger")
    return render_template("login.html", form=form)


@main_bp.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already registered", "danger")
        else:
            new_user = User(
                email=form.email.data,
                password=generate_password_hash(form.password.data)
            )
            db.session.add(new_user)
            db.session.commit()
            flash("Signup successful! Please log in.", "success")
            return redirect(url_for("main.login"))
    return render_template("signup.html", form=form)

# Dashboard
@main_bp.route("/index")
def dashboard():
    if "user" in session:
        return render_template("index.html", user=session["user"])
    return redirect(url_for("main.login"))

@main_bp.route("/history")
def history():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("main.login"))
    results = IOCResult.query.filter_by(user_id=user_id).all()
    return render_template("history.html", results=results)


# Logout
@main_bp.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("main.landing"))
