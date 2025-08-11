import os
import re
import json
import csv
import io
from flask import Blueprint, render_template, request, jsonify, send_file, redirect, url_for, flash

# Import scraping, API and ML functions
from app.scraper import scrape_and_enrich, google_dork_search
from app.vt_shodan_api import vt_lookup_domain, vt_lookup_ip, vt_lookup_url, shodan_lookup
from app.ml_model import classify_threat

# Import database and models
from app import db
from app.models import IOCResult, Feedback

# Import your form
from app.forms import InputForm

# Define blueprint (matches registration in __init__.py)
main_bp = Blueprint("main", __name__)

# ---- Helper function to detect IOC type from input ----
def detect_ioc_type(ioc):
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"  # Simple IPv4 regex
    domain_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.[A-Za-z]{2,})+$"  # Basic domain pattern
    url_pattern = r"^https?://[^\s/$.?#].[^\s]*$"  # HTTP/HTTPS URL pattern

    if re.match(ip_pattern, ioc):
        return "ip"
    elif re.match(url_pattern, ioc):
        return "url"
    elif re.match(domain_pattern, ioc):
        return "domain"
    else:
        return "keyword"

# ---- Main route: Home and processing user input ----
@main_bp.route("/", methods=["GET", "POST"])
def index():
    form = InputForm()
    if form.validate_on_submit():
        user_input = form.input_data.data.strip()
        if not user_input:
            flash("Please enter a keyword, IP, URL, or domain.", "warning")
            return redirect(url_for("main.index"))

        # Detect IOC type (ip, url, domain, or keyword)
        ioc_type = detect_ioc_type(user_input)
        vt_data = shodan_data = scraped_data = None

        # Based on type, call appropriate APIs or scraping
        if ioc_type == "keyword":
            urls = google_dork_search(user_input)
            scraped_data = scrape_and_enrich(urls)
        elif ioc_type == "domain":
            vt_data = vt_lookup_domain(user_input)
        elif ioc_type == "ip":
            vt_data = vt_lookup_ip(user_input)
            shodan_data = shodan_lookup(user_input)
        elif ioc_type == "url":
            vt_data = vt_lookup_url(user_input)

        # Run ML classification based on VT and Shodan data
        classification = classify_threat(vt_data, shodan_data)

        # Save all results in the database
        ioc_result = IOCResult(
            ioc_value=user_input,
            ioc_type=ioc_type,
            vt_report=json.dumps(vt_data) if vt_data else None,
            shodan_report=json.dumps(shodan_data) if shodan_data else None,
            scraped_data=json.dumps(scraped_data) if scraped_data else None,
            classification=classification
        )
        db.session.add(ioc_result)
        db.session.commit()

        # Prepare data for chart (for example, classification distribution)
        chart_data = {
            "labels": ["Malicious", "Benign"],
            "values": [
                IOCResult.query.filter_by(classification="malicious").count(),
                IOCResult.query.filter_by(classification="benign").count()
            ]
        }

        # Render results page with all data and chart
        return render_template("results.html", results={
            "input": user_input,
            "type": ioc_type,
            "vt": vt_data,
            "shodan": shodan_data,
            "scraped": scraped_data,
            "classification": classification
        }, chart_data=json.dumps(chart_data))

    # For GET or if form validation fails, just render the input form page
    return render_template("index.html", form=form)

# ---- Feedback route to collect user feedback on IOC classification ----
@main_bp.route("/feedback/<int:ioc_id>", methods=["POST"])
def feedback(ioc_id):
    feedback_value = request.form.get("feedback")
    if feedback_value not in ["malicious", "benign"]:
        return jsonify({"error": "Invalid feedback"}), 400
    # Add feedback to DB linked to IOCResult ID
    db.session.add(Feedback(ioc_id=ioc_id, feedback_value=feedback_value))
    db.session.commit()
    return jsonify({"message": "Feedback saved"})

# ---- Export results route for CSV or JSON ----
@main_bp.route("/export/<fmt>")
def export_results(fmt):
    results = IOCResult.query.all()
    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        # CSV headers
        writer.writerow(["id", "ioc_value", "ioc_type", "classification", "vt_report", "shodan_report", "scraped_data"])
        for r in results:
            writer.writerow([r.id, r.ioc_value, r.ioc_type, r.classification, r.vt_report, r.shodan_report, r.scraped_data])
        output.seek(0)
        # Send CSV as file attachment
        return send_file(io.BytesIO(output.getvalue().encode()), mimetype="text/csv", as_attachment=True, download_name="ioc_results.csv")
    elif fmt == "json":
        # Return JSON list of results with decoded JSON fields
        return jsonify([{
            "id": r.id,
            "ioc_value": r.ioc_value,
            "ioc_type": r.ioc_type,
            "classification": r.classification,
            "vt_report": json.loads(r.vt_report) if r.vt_report else None,
            "shodan_report": json.loads(r.shodan_report) if r.shodan_report else None,
            "scraped_data": json.loads(r.scraped_data) if r.scraped_data else None
        } for r in results])
    return jsonify({"error": "Unsupported format"}), 400

# ---- Admin Dashboard to show stats and charts ----
@main_bp.route("/admin")
def admin_dashboard():
    malicious_count = IOCResult.query.filter_by(classification="malicious").count()
    benign_count = IOCResult.query.filter_by(classification="benign").count()
    return render_template("admin.html",
        total_iocs=IOCResult.query.count(),
        malicious_count=malicious_count,
        benign_count=benign_count,
        feedback_count=Feedback.query.count(),
        chart_data=json.dumps({
            "labels": ["Malicious", "Benign"],
            "values": [malicious_count, benign_count]
        })
    )
