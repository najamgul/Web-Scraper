# routes.py
import os
import re
import json
import csv
import io
from flask import session, Blueprint, render_template, request, jsonify, send_file, redirect, url_for, flash
import pandas as pd
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

from app.scraper import google_cse_search
from app.vt_shodan_api import vt_lookup_domain, vt_lookup_ip, vt_lookup_url, shodan_lookup
from app.otx_api import otx_lookup
from app.ml_model import classify_threat
from app.forms import InputForm, LoginForm, SignupForm
from app.models import User, IOCResult, Feedback
from app import db

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


@main_bp.route("/", methods=["GET", "POST"])
@main_bp.route("/index", methods=["GET", "POST"])
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
        # OTX is queried for ALL types
        otx_data = otx_lookup(user_input, ioc_type) or {}

        if ioc_type == "ip":
            vt_data = vt_lookup_ip(user_input) or {}
            shodan_data = shodan_lookup(user_input) or {}
       
        if ioc_type == "ip":
            vt_data = vt_lookup_ip(user_input) or {}
            shodan_data = shodan_lookup(user_input) or {}
            
            # ✅ DEBUG: Check what VirusTotal returns
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
            vt_data = vt_lookup_domain(user_input) or {}  # VT supports hash lookup via domain endpoint
        
        # --- Google CSE used ONLY for display (not classification) ---
        if ioc_type == "keyword":
            scraped_data = google_cse_search(user_input)
        
        # --- Classification based ONLY on API data (VT, Shodan, OTX) ---
        # For keywords: uses ONLY OTX
        # For others: uses Random Forest with all APIs
        classification = classify_threat(
            vt_data=vt_data,
            shodan_data=shodan_data,
            otx_data=otx_data,
            ioc_type=ioc_type,
            user_input=user_input
        )

        # --- Save to DB ---
        ioc_result = IOCResult(
            input_value=user_input,
            type=ioc_type,
            vt_report=vt_data,
            shodan_report=shodan_data,
            otx_report=otx_data,  # Changed from abusix_report
            scraped_data=scraped_data,
            classification=classification,
            user_id=session.get("user_id"),
            timestamp=datetime.utcnow()
        )

        db.session.add(ioc_result)
        db.session.commit()

        # --- Chart Data ---
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
            "ioc_id": ioc_result.id,
            "input": user_input,
            "type": ioc_type,
            "vt": vt_data,
            "shodan": shodan_data,
            "otx": otx_data,
            "scraped": scraped_data,
            "classification": classification
        }, chart_data=json.dumps(chart_data))

    return render_template("index.html", form=form)


# ---- FEEDBACK ----
@main_bp.route("/feedback/<int:ioc_id>", methods=["POST"])
def feedback(ioc_id):
    feedback_value = request.form.get("feedback")
    if feedback_value not in ["Malicious", "Benign", "Informational"]:
        return jsonify({"error": "Invalid feedback"}), 400

    db.session.add(Feedback(ioc_id=ioc_id, correct_classification=feedback_value))
    db.session.commit()
    return jsonify({"message": "Feedback saved"})


# ---- EXPORT ROUTES ----
@main_bp.route("/export/<format>/<int:ioc_id>")
def export(format, ioc_id):
    """Export single result"""
    result = IOCResult.query.get_or_404(ioc_id)
    
    if format == "json":
        return jsonify({
            "input": result.input_value,
            "type": result.type,
            "classification": result.classification,
            "timestamp": result.timestamp.isoformat(),
            "vt_report": result.vt_report,
            "shodan_report": result.shodan_report,
            "otx_report": result.otx_report
        })
    
    elif format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Input", "Type", "Classification", "Timestamp"])
        writer.writerow([result.input_value, result.type, result.classification, result.timestamp])
        
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"threat_report_{ioc_id}.csv"
        )
    
    return jsonify({"error": "Invalid format"}), 400


# ---- HISTORY ----
@main_bp.route("/history")
def history():
    """View search history"""
    user_id = session.get("user_id")
    if user_id:
        results = IOCResult.query.filter_by(user_id=user_id).order_by(IOCResult.timestamp.desc()).all()
    else:
        results = IOCResult.query.order_by(IOCResult.timestamp.desc()).limit(50).all()
    
    return render_template("history.html", results=results)


# ---- AUTH ROUTES (keep as is) ----
@main_bp.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session["user_id"] = user.id
            session["username"] = user.username
            flash("Login successful!", "success")
            return redirect(url_for("main.index"))
        else:
            flash("Invalid credentials", "danger")
    return render_template("login.html", form=form)


@main_bp.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash("Username already exists", "danger")
        else:
            hashed_pw = generate_password_hash(form.password.data)
            new_user = User(username=form.username.data, password=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            flash("Account created! Please login.", "success")
            return redirect(url_for("main.login"))
    return render_template("signup.html", form=form)


@main_bp.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for("main.index"))