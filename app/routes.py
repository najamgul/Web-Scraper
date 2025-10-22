# routes.py
# routes.py
import os
import re
import json
import csv
import io
import logging
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from datetime import datetime, timedelta

from app.enrichment import enrich_threat_intelligence
from flask import session, Blueprint, render_template, request, jsonify, send_file, redirect, url_for, flash
import pandas as pd
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash
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

# ✅ INITIALIZE LOGGER
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ✅ CACHE SETUP
CACHE = {}
CACHE_DURATION = timedelta(hours=1)

def get_cached_result(ioc_value):
    """Check cache for recent scan"""
    cache_key = hashlib.md5(ioc_value.encode()).hexdigest()
    if cache_key in CACHE:
        cached_data, timestamp = CACHE[cache_key]
        if datetime.utcnow() - timestamp < CACHE_DURATION:
            logger.info(f"✅ Cache HIT for {ioc_value}")
            return cached_data
    return None

def set_cached_result(ioc_value, data):
    """Cache scan result"""
    cache_key = hashlib.md5(ioc_value.encode()).hexdigest()
    CACHE[cache_key] = (data, datetime.utcnow())
    logger.info(f"💾 Cached result for {ioc_value}")


# ✅ PARALLEL API FETCHER
def fetch_all_threat_data(user_input, ioc_type):
    """
    Fetch all API data in PARALLEL with detailed logging
    """
    results = {
        'vt_data': {},
        'shodan_data': {},
        'otx_data': {},
        'scraped_data': []
    }
    
    logger.info(f"📡 Fetching threat data for {ioc_type}: {user_input}")
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {}
        
        # Submit all API calls SIMULTANEOUSLY
        logger.info("   Submitting OTX lookup...")
        futures['otx'] = executor.submit(otx_lookup, user_input, ioc_type)
        
        if ioc_type == "ip":
            logger.info("   Submitting VT IP lookup...")
            futures['vt'] = executor.submit(vt_lookup_ip, user_input)
            logger.info("   Submitting Shodan lookup...")
            futures['shodan'] = executor.submit(shodan_lookup, user_input)
        elif ioc_type == "url":
            logger.info("   Submitting VT URL lookup...")
            futures['vt'] = executor.submit(vt_lookup_url, user_input)
        elif ioc_type in ["domain", "hash"]:
            logger.info("   Submitting VT domain/hash lookup...")
            futures['vt'] = executor.submit(vt_lookup_domain, user_input)
        
        # Only scrape for keywords
        if ioc_type == "keyword":
            logger.info("   Submitting Google CSE search...")
            futures['scraped'] = executor.submit(google_cse_search, user_input)
        
        # Collect results with timeout protection
        for key, future in futures.items():
            try:
                if key == 'vt':
                    result = future.result(timeout=15)  # Increased timeout
                    results['vt_data'] = result or {}
                    logger.info(f"   ✅ VT returned: {len(str(result))} chars")
                    if 'error' in results['vt_data']:
                        logger.warning(f"   ⚠️ VT error: {results['vt_data']['error']}")
                    
                elif key == 'shodan':
                    result = future.result(timeout=15)
                    results['shodan_data'] = result or {}
                    logger.info(f"   ✅ Shodan returned: {len(str(result))} chars")
                    if 'error' in results['shodan_data']:
                        logger.warning(f"   ⚠️ Shodan error: {results['shodan_data']['error']}")
                    
                elif key == 'otx':
                    result = future.result(timeout=15)
                    results['otx_data'] = result or {}
                    logger.info(f"   ✅ OTX returned: {len(str(result))} chars, classification: {result.get('classification', 'N/A')}")
                    if 'error' in results['otx_data']:
                        logger.warning(f"   ⚠️ OTX error: {results['otx_data']['error']}")
                    
                elif key == 'scraped':
                    result = future.result(timeout=20)
                    results['scraped_data'] = result or []
                    logger.info(f"   ✅ Scraped {len(results['scraped_data'])} results")
                    
            except TimeoutError:
                logger.error(f"   ❌ {key} API TIMEOUT after waiting")
            except Exception as e:
                logger.error(f"   ❌ {key} API ERROR: {e}", exc_info=True)
    
    # Log final results summary
    logger.info(f"📊 API Summary:")
    logger.info(f"   VT data: {'✅ OK' if results['vt_data'] and 'error' not in results['vt_data'] else '❌ Failed'}")
    logger.info(f"   Shodan data: {'✅ OK' if results['shodan_data'] and 'error' not in results['shodan_data'] else '❌ Failed'}")
    logger.info(f"   OTX data: {'✅ OK' if results['otx_data'] and 'error' not in results['otx_data'] else '❌ Failed'}")
    
    return results


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

def format_google_for_display(scraped_data):
    """
    Format Google Custom Search results for template display
    Similar to OTX formatting
    """
    if not scraped_data or not isinstance(scraped_data, list):
        return None
    
    # Filter out "No scraped data found" entries
    valid_results = [
        item for item in scraped_data 
        if isinstance(item, dict) and item.get('title', '').lower() != 'no scraped data found'
    ]
    
    if not valid_results:
        return None
    
    # Extract domains
    domains = []
    for result in valid_results:
        domain = result.get('displayLink', '')
        if domain:
            domains.append(domain)
    
    unique_domains = list(set(domains))
    
    # Analyze content for threat indicators
    threat_keywords = [
        'malware', 'virus', 'trojan', 'ransomware', 'phishing', 'scam', 
        'fraud', 'hack', 'exploit', 'vulnerability', 'breach', 'attack',
        'suspicious', 'malicious', 'threat', 'compromise', 'botnet', 'backdoor'
    ]
    
    safe_keywords = [
        'legitimate', 'safe', 'secure', 'trusted', 'official', 'verified',
        'protection', 'antivirus', 'security', 'defense'
    ]
    
    threat_indicators = []
    safe_indicators = []
    content_summary = []
    
    for result in valid_results:
        content = (result.get('snippet', '') + ' ' + result.get('content', '')).lower()
        title = result.get('title', '').lower()
        
        # Check for threat keywords
        for keyword in threat_keywords:
            if keyword in content or keyword in title:
                if keyword not in threat_indicators:
                    threat_indicators.append(keyword)
        
        # Check for safe keywords
        for keyword in safe_keywords:
            if keyword in content or keyword in title:
                if keyword not in safe_indicators:
                    safe_indicators.append(keyword)
        
        # Extract first meaningful sentence from snippet
        snippet = result.get('snippet', '')
        if snippet and len(snippet) > 20:
            content_summary.append(snippet[:150] + '...' if len(snippet) > 150 else snippet)
    
    # Calculate threat score based on findings
    threat_score = min(len(threat_indicators) * 10, 100)
    
    # Adjust based on safe indicators
    if safe_indicators:
        threat_score = max(threat_score - len(safe_indicators) * 5, 0)
    
    # Determine classification
    if threat_score >= 60:
        classification = "High Risk"
        risk_level = "Critical"
    elif threat_score >= 30:
        classification = "Medium Risk"
        risk_level = "High"
    elif threat_score > 0:
        classification = "Low Risk"
        risk_level = "Medium"
    else:
        classification = "Informational"
        risk_level = "Low"
    
    # Build summary
    if threat_indicators:
        summary = f"Found {len(valid_results)} search results with {len(threat_indicators)} threat-related indicators across {len(unique_domains)} domains"
    else:
        summary = f"Found {len(valid_results)} informational search results across {len(unique_domains)} domains with no immediate threat indicators"
    
    formatted = {
        'result_count': len(valid_results),
        'threat_score': threat_score,
        'classification': classification,
        'risk_level': risk_level,
        'summary': summary,
        
        # Domain analysis
        'total_domains': len(unique_domains),
        'unique_domains': unique_domains[:10],  # Top 10 domains
        
        # Content analysis
        'threat_indicators': threat_indicators[:10],
        'safe_indicators': safe_indicators[:5],
        'content_previews': content_summary[:5],
        
        # Top results
        'top_results': [
            {
                'title': r.get('title', 'No title'),
                'url': r.get('url', '#'),
                'domain': r.get('displayLink', 'Unknown'),
                'snippet': r.get('snippet', 'No description')[:200]
            }
            for r in valid_results[:5]
        ],
        
        # Raw data
        'raw': scraped_data
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


# ---- LANDING PAGE ----
@main_bp.route("/")
def landing():
    """Public landing page"""
    if 'user_id' in session:
        return redirect(url_for('main.index'))
    return render_template("landing.html")

# In routes.py, add this function
@main_bp.route("/clear-cache")
@login_required
def clear_cache():
    """Clear the scan result cache"""
    global CACHE
    CACHE.clear()
    flash("Cache cleared successfully!", "success")
    return redirect(url_for("main.index"))
# ---- INDEX PAGE (OPTIMIZED) ----
# ---- INDEX PAGE (OPTIMIZED) ----
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
        
        # ✅ CHECK CACHE FIRST
        cached = get_cached_result(user_input)
        if cached:
            flash("Results loaded from cache (scanned recently)", "info")
            return render_template("results.html", results=cached['results'], chart_data=cached['chart_data'])
        
        # ✅ FETCH ALL APIs IN PARALLEL
        logger.info(f"🚀 Starting PARALLEL API fetch for {ioc_type}: {user_input}")
        start_time = datetime.utcnow()
        
        api_results = fetch_all_threat_data(user_input, ioc_type)
        
        vt_data = api_results['vt_data']
        shodan_data = api_results['shodan_data']
        otx_data = api_results['otx_data']
        scraped_data = api_results['scraped_data']
        
        elapsed = (datetime.utcnow() - start_time).total_seconds()
        logger.info(f"⏱️  API fetch completed in {elapsed:.2f} seconds")
        
        # ML Classification (fast)
        classification = classify_threat(
            vt_data=vt_data,
            shodan_data=shodan_data,
            otx_data=otx_data,
            ioc_type=ioc_type,
            user_input=user_input
        )
        
        # ✅ CRITICAL: Skip AI enrichment entirely on page load
        # It will be loaded via AJAX after results page renders
        enrichment = None  # ← Don't even set a placeholder
        
        # Save to MongoDB
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
            enrichment_context=None,  # ← Will be populated by AJAX
            user_id=user_ref,
            timestamp=datetime.utcnow()
        )
        ioc_result.save()

        # Chart Data
        chart_data = {
            "labels": ["Malicious", "Benign", "Informational", "Unknown"],
            "values": [
                IOCResult.objects(classification="Malicious").count(),
                IOCResult.objects(classification="Benign").count(),
                IOCResult.objects(classification="Informational").count(),
                IOCResult.objects(classification="Unknown").count(),
            ]
        }
        
        results = {
            "ioc_id": str(ioc_result.id),
            "input": user_input,
            "type": ioc_type,
            "vt": vt_data,
            "shodan": shodan_data,
            "otx": otx_data,
            "google_formatted": format_google_for_display(scraped_data),
            "otx_formatted": format_otx_for_display(otx_data),
            "scraped": scraped_data,
            "classification": classification,
            "enrichment": None  # ← Will trigger AJAX load in template
        }
        
        # CACHE THE RESULT
        set_cached_result(user_input, {
            'results': results,
            'chart_data': json.dumps(chart_data)
        })
        
        total_time = (datetime.utcnow() - start_time).total_seconds()
        logger.info(f"✅ Page rendered in {total_time:.2f} seconds (enrichment will load via AJAX)")

        return render_template("results.html", results=results, chart_data=json.dumps(chart_data))
    
    return render_template("index.html", form=form)

# ✅ NEW: AJAX Endpoint for Lazy Loading Enrichment
@main_bp.route("/api/enrichment/<ioc_id>", methods=["GET"])
@login_required
def get_enrichment(ioc_id):
    """
    AJAX endpoint to load AI enrichment after page renders
    """
    try:
        ioc_result = IOCResult.objects.get(id=ioc_id)
        
        # Check if enrichment already exists
        enrichment = ioc_result.enrichment_context or {}
        
        if enrichment and not enrichment.get('loading'):
            logger.info(f"✅ Returning cached enrichment for {ioc_id}")
            return jsonify({
                'status': 'complete',
                'enrichment': enrichment
            })
        
        # Generate enrichment now
        logger.info(f"🧠 Generating enrichment for {ioc_id}")
        
        ENABLE_AI_ENRICHMENT = os.getenv('ENABLE_ENRICHMENT', 'true').lower() == 'true'
        
        if ENABLE_AI_ENRICHMENT:
            try:
                enrichment = enrich_threat_intelligence(
                    ioc_value=ioc_result.input_value,
                    ioc_type=ioc_result.type,
                    vt_data=ioc_result.vt_report,
                    shodan_data=ioc_result.shodan_report,
                    otx_data=ioc_result.otx_report,
                    classification=ioc_result.classification
                )
            except Exception as e:
                logger.error(f"Enrichment error: {e}")
                enrichment = {
                    'summary': 'AI enrichment failed. Please try again.',
                    'confidence': 'Low',
                    'error': str(e)
                }
        else:
            enrichment = {
                'summary': 'AI enrichment disabled for faster scanning',
                'confidence': 'Medium'
            }
        
        # Save enrichment to database
        ioc_result.enrichment_context = enrichment
        ioc_result.save()
        
        logger.info(f"✅ Enrichment completed for {ioc_id}")
        
        return jsonify({
            'status': 'complete',
            'enrichment': enrichment
        })
    
    except Exception as e:
        logger.error(f"Enrichment API error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


# ... rest of your routes (feedback, export, history, login, signup, dashboard, logout) ...

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
# ---- EXPORT ROUTES (ENHANCED WITH AI ENRICHMENT) ----
@main_bp.route("/export/<format>/<ioc_id>")
@login_required
def export(format, ioc_id):
    """Export single result in multiple formats with AI enrichment"""
    try:
        result = IOCResult.objects.get(id=ioc_id)
    except Exception as e:
        return jsonify({"error": f"Result not found: {str(e)}"}), 404
    
    # ✅ Get enrichment data (trigger generation if needed)
    enrichment = result.enrichment_context
    if not enrichment or enrichment.get('loading'):
        # Try to generate it now for export
        try:
            from app.enrichment import enrich_threat_intelligence
            enrichment = enrich_threat_intelligence(
                ioc_value=result.input_value,
                ioc_type=result.type,
                vt_data=result.vt_report,
                shodan_data=result.shodan_report,
                otx_data=result.otx_report,
                classification=result.classification
            )
            result.enrichment_context = enrichment
            result.save()
        except Exception as e:
            logger.error(f"Failed to generate enrichment for export: {e}")
            enrichment = {
                'summary': 'AI analysis unavailable',
                'recommendation': 'Manual review required',
                'confidence': 'Low'
            }
    
    # JSON Export
    if format == "json":
        return jsonify({
            "metadata": {
                "id": str(result.id),
                "generated_at": datetime.utcnow().isoformat(),
                "report_version": "2.0"
            },
            "ioc_details": {
                "input": result.input_value,
                "type": result.type,
                "classification": result.classification,
                "timestamp": result.timestamp.isoformat() if result.timestamp else None
            },
            "ai_analysis": {
                "summary": enrichment.get('summary', 'N/A'),
                "detailed_explanation": enrichment.get('why_malicious', 'N/A'),
                "key_indicators": enrichment.get('key_indicators', []),
                "recommendation": enrichment.get('recommendation', 'N/A'),
                "confidence_level": enrichment.get('confidence', 'Unknown'),
                "risk_score": enrichment.get('risk_score', 0),
                "sources_analyzed": enrichment.get('sources_analyzed', [])
            },
            "threat_intelligence": {
                "virustotal": result.vt_report,
                "shodan": result.shodan_report,
                "alienvault_otx": result.otx_report
            },
            "scraped_data": result.scraped_data
        })
    
    # CSV Export
    elif format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(["=" * 80])
        writer.writerow(["THREAT INTELLIGENCE REPORT"])
        writer.writerow(["Generated:", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")])
        writer.writerow(["=" * 80])
        writer.writerow([])
        
        # IOC Information
        writer.writerow(["━" * 80])
        writer.writerow(["INDICATOR OF COMPROMISE (IOC)"])
        writer.writerow(["━" * 80])
        writer.writerow(["ID", str(result.id)])
        writer.writerow(["Input", result.input_value])
        writer.writerow(["Type", result.type])
        writer.writerow(["Classification", result.classification])
        writer.writerow(["Scan Date", result.timestamp.strftime("%Y-%m-%d %H:%M:%S") if result.timestamp else "N/A"])
        writer.writerow([])
        
        # AI Analysis Section
        writer.writerow(["━" * 80])
        writer.writerow(["🤖 AI THREAT ANALYSIS"])
        writer.writerow(["━" * 80])
        writer.writerow([])
        
        writer.writerow(["Summary"])
        writer.writerow([enrichment.get('summary', 'N/A')])
        writer.writerow([])
        
        writer.writerow(["Detailed Analysis"])
        # Split long text into multiple rows
        explanation = enrichment.get('why_malicious', 'N/A')
        for line in explanation.split('\n'):
            if line.strip():
                writer.writerow([line.strip()])
        writer.writerow([])
        
        writer.writerow(["Key Threat Indicators"])
        indicators = enrichment.get('key_indicators', [])
        if indicators:
            for idx, indicator in enumerate(indicators, 1):
                writer.writerow([f"  {idx}.", indicator])
        else:
            writer.writerow(["  No specific indicators identified"])
        writer.writerow([])
        
        writer.writerow(["Recommended Action"])
        writer.writerow([enrichment.get('recommendation', 'N/A')])
        writer.writerow([])
        
        writer.writerow(["Confidence Level", enrichment.get('confidence', 'Unknown')])
        writer.writerow(["Risk Score", f"{enrichment.get('risk_score', 0)}/100"])
        writer.writerow(["Sources Analyzed", ", ".join(enrichment.get('sources_analyzed', []))])
        writer.writerow([])
        
        # VirusTotal Report
        writer.writerow(["━" * 80])
        writer.writerow(["VIRUSTOTAL ANALYSIS"])
        writer.writerow(["━" * 80])
        if result.vt_report and 'error' not in result.vt_report:
            stats = result.vt_report.get("last_analysis_stats", {})
            if not stats:
                stats = result.vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            if stats:
                writer.writerow(["Malicious Detections", stats.get("malicious", 0)])
                writer.writerow(["Suspicious Detections", stats.get("suspicious", 0)])
                writer.writerow(["Undetected", stats.get("undetected", 0)])
                writer.writerow(["Harmless", stats.get("harmless", 0)])
            else:
                writer.writerow(["No detection statistics available"])
        else:
            writer.writerow(["No VirusTotal data available"])
        writer.writerow([])
        
        # Shodan Report
        writer.writerow(["━" * 80])
        writer.writerow(["SHODAN NETWORK INTELLIGENCE"])
        writer.writerow(["━" * 80])
        if result.shodan_report and 'error' not in result.shodan_report:
            writer.writerow(["IP Address", result.shodan_report.get("ip_str", result.shodan_report.get("ip", "N/A"))])
            writer.writerow(["Organization", result.shodan_report.get("org", "N/A")])
            writer.writerow(["ISP", result.shodan_report.get("isp", "N/A")])
            writer.writerow(["Country", result.shodan_report.get("country_name", "N/A")])
            
            ports = result.shodan_report.get("ports", [])
            if not ports and "data" in result.shodan_report:
                ports = [item.get("port") for item in result.shodan_report["data"] if "port" in item]
            
            writer.writerow(["Open Ports", ", ".join(map(str, ports)) if ports else "None detected"])
        else:
            writer.writerow(["No Shodan data available"])
        writer.writerow([])
        writer.writerow(["━" * 80])
        writer.writerow(["GOOGLE SEARCH INTELLIGENCE"])
        writer.writerow(["━" * 80])
        
        google_fmt = format_google_for_display(result.scraped_data)
        if google_fmt:
            writer.writerow(["Search Results Found", google_fmt.get('result_count', 0)])
            writer.writerow(["Threat Score", f"{google_fmt.get('threat_score', 0)}/100"])
            writer.writerow(["Risk Classification", google_fmt.get('classification', 'N/A')])
            writer.writerow(["Unique Domains", google_fmt.get('total_domains', 0)])
            threat_indicators = google_fmt.get('threat_indicators', [])
            if threat_indicators:
                writer.writerow(["Threat Indicators", ", ".join(threat_indicators)])
                domains = google_fmt.get('unique_domains', [])
            if domains:
                writer.writerow(["Domains Found", ", ".join(domains[:10])])
            else:
                writer.writerow(["No Google search data available"])
                writer.writerow([])
        
        # OTX Report
        writer.writerow(["━" * 80])
        writer.writerow(["ALIENVAULT OTX THREAT INTELLIGENCE"])
        writer.writerow(["━" * 80])
        if result.otx_report and 'error' not in result.otx_report:
            writer.writerow(["Threat Score", f"{result.otx_report.get('threat_score', 0)}/100"])
            writer.writerow(["Classification", result.otx_report.get('classification', 'Unknown')])
            writer.writerow(["Threat Pulses", result.otx_report.get('source_count', 0)])
            
            details = result.otx_report.get('details', {})
            if details:
                writer.writerow(["Risk Level", details.get('risk_level', 'Unknown')])
                
                malware = details.get('malware_families', [])
                if malware:
                    writer.writerow(["Malware Families", ", ".join(malware[:5])])
                
                tags = details.get('top_tags', [])
                if tags:
                    writer.writerow(["Top Tags", ", ".join(tags[:10])])
        else:
            writer.writerow(["No OTX data available"])
        
        writer.writerow([])
        writer.writerow(["=" * 80])
        writer.writerow(["END OF REPORT"])
        writer.writerow(["=" * 80])
        
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"threat_report_{result.input_value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        

        
    
    # Excel Export
    elif format == "excel":
        wb = openpyxl.Workbook()
        
        # ============================================
        # WORKSHEET 1: EXECUTIVE SUMMARY
        # ============================================
        ws_summary = wb.active
        ws_summary.title = "Executive Summary"
        
        # Styling
        header_fill = PatternFill(start_color="4361ee", end_color="4361ee", fill_type="solid")
        header_font = Font(color="FFFFFF", bold=True, size=14)
        title_font = Font(bold=True, size=20, color="4361ee")
        section_font = Font(bold=True, size=12, color="4cc9f0")
        
        # Title
        ws_summary['A1'] = "🛡️ THREAT INTELLIGENCE REPORT"
        ws_summary['A1'].font = title_font
        ws_summary.merge_cells('A1:D1')
        
        ws_summary['A2'] = f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
        ws_summary.merge_cells('A2:D2')
        
        row = 4
        
        # IOC Details
        ws_summary[f'A{row}'] = "INDICATOR OF COMPROMISE"
        ws_summary[f'A{row}'].font = section_font
        ws_summary.merge_cells(f'A{row}:D{row}')
        row += 1
        
        ioc_data = [
            ["Input Value", result.input_value],
            ["Type", result.type],
            ["Classification", result.classification],
            ["Risk Score", f"{enrichment.get('risk_score', 0)}/100"],
            ["Scan Date", result.timestamp.strftime("%Y-%m-%d %H:%M:%S") if result.timestamp else "N/A"]
        ]
        
        for item in ioc_data:
            ws_summary[f'A{row}'] = item[0]
            ws_summary[f'A{row}'].font = Font(bold=True)
            ws_summary[f'B{row}'] = item[1]
            ws_summary.merge_cells(f'B{row}:D{row}')
            row += 1
        
        row += 1
        
        # AI Analysis
        ws_summary[f'A{row}'] = "🤖 AI THREAT ANALYSIS"
        ws_summary[f'A{row}'].font = section_font
        ws_summary.merge_cells(f'A{row}:D{row}')
        row += 1
        
        ws_summary[f'A{row}'] = "Summary"
        ws_summary[f'A{row}'].font = Font(bold=True)
        row += 1
        ws_summary[f'A{row}'] = enrichment.get('summary', 'N/A')
        ws_summary[f'A{row}'].alignment = Alignment(wrap_text=True)
        ws_summary.merge_cells(f'A{row}:D{row}')
        ws_summary.row_dimensions[row].height = 40
        row += 2
        
        ws_summary[f'A{row}'] = "Key Indicators"
        ws_summary[f'A{row}'].font = Font(bold=True)
        row += 1
        
        indicators = enrichment.get('key_indicators', [])
        if indicators:
            for indicator in indicators:
                ws_summary[f'A{row}'] = f"• {indicator}"
                ws_summary[f'A{row}'].alignment = Alignment(wrap_text=True)
                ws_summary.merge_cells(f'A{row}:D{row}')
                row += 1
        else:
            ws_summary[f'A{row}'] = "No specific indicators"
            row += 1
        
        row += 1
        ws_summary[f'A{row}'] = "Recommended Action"
        ws_summary[f'A{row}'].font = Font(bold=True, color="e74c3c" if result.classification == "Malicious" else "2ecc71")
        row += 1
        ws_summary[f'A{row}'] = enrichment.get('recommendation', 'N/A')
        ws_summary[f'A{row}'].alignment = Alignment(wrap_text=True)
        ws_summary.merge_cells(f'A{row}:D{row}')
        ws_summary.row_dimensions[row].height = 60
        
        # Set column widths
        ws_summary.column_dimensions['A'].width = 25
        ws_summary.column_dimensions['B'].width = 50
        ws_summary.column_dimensions['C'].width = 20
        ws_summary.column_dimensions['D'].width = 20
        
        # ============================================
        # WORKSHEET 2: DETAILED ANALYSIS
        # ============================================
        ws_detail = wb.create_sheet("Detailed Analysis")
        
        row = 1
        ws_detail[f'A{row}'] = "DETAILED THREAT ANALYSIS"
        ws_detail[f'A{row}'].font = title_font
        ws_detail.merge_cells(f'A{row}:B{row}')
        row += 2
        
        ws_detail[f'A{row}'] = "Why This Was Classified as " + result.classification
        ws_detail[f'A{row}'].font = section_font
        ws_detail.merge_cells(f'A{row}:B{row}')
        row += 1
        
        explanation = enrichment.get('why_malicious', 'No detailed explanation available')
        ws_detail[f'A{row}'] = explanation
        ws_detail[f'A{row}'].alignment = Alignment(wrap_text=True, vertical='top')
        ws_detail.merge_cells(f'A{row}:B{row}')
        ws_detail.row_dimensions[row].height = 150
        row += 2
        
        ws_detail[f'A{row}'] = "Confidence Level"
        ws_detail[f'A{row}'].font = Font(bold=True)
        ws_detail[f'B{row}'] = enrichment.get('confidence', 'Unknown')
        row += 1
        
        ws_detail[f'A{row}'] = "Sources Analyzed"
        ws_detail[f'A{row}'].font = Font(bold=True)
        ws_detail[f'B{row}'] = ", ".join(enrichment.get('sources_analyzed', []))
        
        ws_detail.column_dimensions['A'].width = 25
        ws_detail.column_dimensions['B'].width = 80
        
        # ============================================
        # WORKSHEET 3: VIRUSTOTAL
        # ============================================
        ws_vt = wb.create_sheet("VirusTotal")
        
        row = 1
        ws_vt[f'A{row}'] = "VIRUSTOTAL ANALYSIS"
        ws_vt[f'A{row}'].font = title_font
        row += 2
        
        if result.vt_report and 'error' not in result.vt_report:
            stats = result.vt_report.get("last_analysis_stats", {})
            if not stats:
                stats = result.vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            if stats:
                ws_vt[f'A{row}'] = "Detection Category"
                ws_vt[f'B{row}'] = "Count"
                ws_vt[f'A{row}'].font = header_font
                ws_vt[f'B{row}'].font = header_font
                ws_vt[f'A{row}'].fill = header_fill
                ws_vt[f'B{row}'].fill = header_fill
                row += 1
                
                for key, value in stats.items():
                    ws_vt[f'A{row}'] = key.capitalize()
                    ws_vt[f'B{row}'] = value
                    row += 1
        else:
            ws_vt[f'A{row}'] = "No VirusTotal data available"
        
        ws_vt.column_dimensions['A'].width = 30
        ws_vt.column_dimensions['B'].width = 20
        
        # ============================================
        # WORKSHEET 4: SHODAN
        # ============================================
        ws_shodan = wb.create_sheet("Shodan")
        
        row = 1
        ws_shodan[f'A{row}'] = "SHODAN NETWORK INTELLIGENCE"
        ws_shodan[f'A{row}'].font = title_font
        row += 2
        
        if result.shodan_report and 'error' not in result.shodan_report:
            shodan_data = [
                ["IP Address", result.shodan_report.get("ip_str", result.shodan_report.get("ip", "N/A"))],
                ["Organization", result.shodan_report.get("org", "N/A")],
                ["ISP", result.shodan_report.get("isp", "N/A")],
                ["Country", result.shodan_report.get("country_name", "N/A")],
                ["City", result.shodan_report.get("city", "N/A")]
            ]
            
            for item in shodan_data:
                ws_shodan[f'A{row}'] = item[0]
                ws_shodan[f'A{row}'].font = Font(bold=True)
                ws_shodan[f'B{row}'] = item[1]
                row += 1
            
            row += 1
            ports = result.shodan_report.get("ports", [])
            if not ports and "data" in result.shodan_report:
                ports = [item.get("port") for item in result.shodan_report["data"] if "port" in item]
            
            ws_shodan[f'A{row}'] = "Open Ports"
            ws_shodan[f'A{row}'].font = Font(bold=True)
            ws_shodan[f'B{row}'] = ", ".join(map(str, ports)) if ports else "None"
        else:
            ws_shodan[f'A{row}'] = "No Shodan data available"
        
        ws_shodan.column_dimensions['A'].width = 30
        ws_shodan.column_dimensions['B'].width = 50
        
        # ============================================
        # WORKSHEET 5: OTX
        # ============================================
        ws_otx = wb.create_sheet("AlienVault OTX")
        
        row = 1
        ws_otx[f'A{row}'] = "ALIENVAULT OTX THREAT INTELLIGENCE"
        ws_otx[f'A{row}'].font = title_font
        row += 2
        
        if result.otx_report and 'error' not in result.otx_report:
            otx_data = [
                ["Threat Score", f"{result.otx_report.get('threat_score', 0)}/100"],
                ["Classification", result.otx_report.get('classification', 'Unknown')],
                ["Threat Pulses", result.otx_report.get('source_count', 0)]
            ]
            
            details = result.otx_report.get('details', {})
            if details:
                otx_data.append(["Risk Level", details.get('risk_level', 'Unknown')])
            
            for item in otx_data:
                ws_otx[f'A{row}'] = item[0]
                ws_otx[f'A{row}'].font = Font(bold=True)
                ws_otx[f'B{row}'] = item[1]
                row += 1
            
            if details:
                row += 1
                malware = details.get('malware_families', [])
                if malware:
                    ws_otx[f'A{row}'] = "Malware Families"
                    ws_otx[f'A{row}'].font = Font(bold=True)
                    row += 1
                    for family in malware[:10]:
                        ws_otx[f'A{row}'] = f"• {family}"
                        row += 1
                
                row += 1
                tags = details.get('top_tags', [])
                if tags:
                    ws_otx[f'A{row}'] = "Top Tags"
                    ws_otx[f'A{row}'].font = Font(bold=True)
                    ws_otx[f'B{row}'] = ", ".join(tags[:15])
        else:
            ws_otx[f'A{row}'] = "No OTX data available"
        
        ws_otx.column_dimensions['A'].width = 30
        ws_otx.column_dimensions['B'].width = 60
        
        # Save Excel file
        excel_file = io.BytesIO()
        wb.save(excel_file)
        excel_file.seek(0)
        
        return send_file(
            excel_file,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name=f"threat_report_{result.input_value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        )
    
    # PDF Export
    elif format == "pdf":
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
        styles = getSampleStyleSheet()
        story = []
        
        # Custom Styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=colors.HexColor('#4361ee'),
            spaceAfter=10,
            alignment=1,
            fontName='Helvetica-Bold'
        )
        
        section_style = ParagraphStyle(
            'SectionHeader',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#4cc9f0'),
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold'
        )
        
        subtitle_style = ParagraphStyle(
            'Subtitle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.gray,
            alignment=1,
            spaceAfter=20
        )
        
        # Title
        story.append(Paragraph("🛡️ THREAT INTELLIGENCE REPORT", title_style))
        story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", subtitle_style))
        story.append(Spacer(1, 0.2*inch))
        
        # IOC Summary Table
        story.append(Paragraph("INDICATOR OF COMPROMISE", section_style))
        
        ioc_data = [
            ['Field', 'Value'],
            ['Input', result.input_value],
            ['Type', result.type],
            ['Classification', result.classification],
            ['Risk Score', f"{enrichment.get('risk_score', 0)}/100"],
            ['Scan Date', result.timestamp.strftime("%Y-%m-%d %H:%M:%S") if result.timestamp else "N/A"]
        ]
        
        ioc_table = Table(ioc_data, colWidths=[2*inch, 4.5*inch])
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4361ee')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(ioc_table)
        story.append(Spacer(1, 0.3*inch))
        
        # AI Analysis Section
        story.append(Paragraph("🤖 AI THREAT ANALYSIS", section_style))
        
        # Summary
        summary_style = ParagraphStyle(
            'Summary',
            parent=styles['Normal'],
            fontSize=11,
            leading=16,
            spaceAfter=12,
            leftIndent=20,
            rightIndent=20,
            backColor=colors.HexColor('#f0f8ff')
        )
        story.append(Paragraph(f"<b>Summary:</b> {enrichment.get('summary', 'N/A')}", summary_style))
        story.append(Spacer(1, 0.1*inch))
        
        # Key Indicators
        story.append(Paragraph("<b>Key Threat Indicators:</b>", styles['Normal']))
        story.append(Spacer(1, 0.05*inch))
        
        indicators = enrichment.get('key_indicators', [])
        if indicators:
            indicator_data = [['#', 'Indicator']]
            for idx, indicator in enumerate(indicators, 1):
                indicator_data.append([str(idx), indicator])
            
            indicator_table = Table(indicator_data, colWidths=[0.5*inch, 6*inch])
            indicator_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4cc9f0')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(indicator_table)
        else:
            story.append(Paragraph("No specific indicators identified", styles['Normal']))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Recommendation Box
        recommendation = enrichment.get('recommendation', 'N/A')
        
        # Color code based on classification
        if result.classification == "Malicious":
            rec_color = colors.HexColor('#ffe6e6')
            border_color = colors.HexColor('#e74c3c')
        elif result.classification == "Benign":
            rec_color = colors.HexColor('#e6f7e6')
            border_color = colors.HexColor('#2ecc71')
        else:
            rec_color = colors.HexColor('#fff8e6')
            border_color = colors.HexColor('#f39c12')
        
        rec_style = ParagraphStyle(
            'Recommendation',
            parent=styles['Normal'],
            fontSize=11,
            leading=16,
            backColor=rec_color
        )
        
        rec_data = [
            [Paragraph("<b>🛡️ RECOMMENDED ACTION</b>", styles['Heading3'])],
            [Paragraph(recommendation, rec_style)]
        ]
        
        rec_table = Table(rec_data, colWidths=[6.5*inch])
        rec_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), border_color),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 15),
            ('RIGHTPADDING', (0, 0), (-1, -1), 15),
            ('BOX', (0, 0), (-1, -1), 2, border_color),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(rec_table)
        story.append(Spacer(1, 0.1*inch))
        
        # Confidence and Risk Score
        meta_data = [
            ['Confidence Level', enrichment.get('confidence', 'Unknown')],
            ['Risk Score', f"{enrichment.get('risk_score', 0)}/100"],
            ['Sources Analyzed', ", ".join(enrichment.get('sources_analyzed', []))]
        ]
        
        meta_table = Table(meta_data, colWidths=[2*inch, 4.5*inch])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Detailed Explanation (if long, add page break before)
        explanation = enrichment.get('why_malicious', '')
        if explanation and len(explanation) > 200:
            story.append(Paragraph("DETAILED ANALYSIS", section_style))
            
            # Split into paragraphs
            for para in explanation.split('\n'):
                if para.strip():
                    story.append(Paragraph(para.strip(), styles['Normal']))
                    story.append(Spacer(1, 0.05*inch))
            
            story.append(Spacer(1, 0.2*inch))
        
        # VirusTotal Report
        story.append(Paragraph("VIRUSTOTAL ANALYSIS", section_style))
        if result.vt_report and 'error' not in result.vt_report:
            stats = result.vt_report.get("last_analysis_stats", {})
            if not stats:
                stats = result.vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            if stats:
                vt_data = [['Category', 'Count']] + [[k.capitalize(), str(v)] for k, v in stats.items()]
                vt_table = Table(vt_data, colWidths=[3*inch, 3.5*inch])
                vt_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4cc9f0')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('PADDING', (0, 0), (-1, -1), 8),
                ]))
                story.append(vt_table)
            else:
                story.append(Paragraph("No detection statistics available", styles['Normal']))
        else:
            story.append(Paragraph("No VirusTotal data available", styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Shodan Report
        story.append(Paragraph("SHODAN NETWORK INTELLIGENCE", section_style))
        if result.shodan_report and 'error' not in result.shodan_report:
            shodan_data = [
                ['IP Address', result.shodan_report.get("ip_str", result.shodan_report.get("ip", "N/A"))],
                ['Organization', result.shodan_report.get("org", "N/A")],
                ['ISP', result.shodan_report.get("isp", "N/A")],
                ['Country', result.shodan_report.get("country_name", "N/A")]
            ]
            
            ports = result.shodan_report.get("ports", [])
            if not ports and "data" in result.shodan_report:
                ports = [item.get("port") for item in result.shodan_report["data"] if "port" in item]
            
            shodan_data.append(['Open Ports', ", ".join(map(str, ports[:20])) if ports else "None"])
            
            shodan_table = Table(shodan_data, colWidths=[2*inch, 4.5*inch])
            shodan_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('BACKGROUND', (0, 0), (-1, -1), colors.beige),
                ('PADDING', (0, 0), (-1, -1), 8),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(shodan_table)
        else:
            story.append(Paragraph("No Shodan data available", styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # OTX Report
        story.append(Paragraph("ALIENVAULT OTX THREAT INTELLIGENCE", section_style))
        if result.otx_report and 'error' not in result.otx_report:
            otx_data = [
                ['Threat Score', f"{result.otx_report.get('threat_score', 0)}/100"],
                ['Classification', result.otx_report.get('classification', 'Unknown')],
                ['Threat Pulses', str(result.otx_report.get('source_count', 0))]
            ]
            
            details = result.otx_report.get('details', {})
            if details:
                otx_data.append(['Risk Level', details.get('risk_level', 'Unknown')])
                
                malware = details.get('malware_families', [])
                if malware:
                    otx_data.append(['Malware Families', ", ".join(malware[:5])])
                
                tags = details.get('top_tags', [])
                if tags:
                    otx_data.append(['Top Tags', ", ".join(tags[:10])])
            
            otx_table = Table(otx_data, colWidths=[2*inch, 4.5*inch])
            otx_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('BACKGROUND', (0, 0), (-1, -1), colors.beige),
                ('PADDING', (0, 0), (-1, -1), 8),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(otx_table)
        else:
            story.append(Paragraph("No OTX data available", styles['Normal']))
        
        # Footer
        story.append(Spacer(1, 0.5*inch))
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.grey,
            alignment=1
        )
        story.append(Paragraph("━" * 100, footer_style))
        story.append(Paragraph("This report was generated automatically by the Threat Intelligence Scanner", footer_style))
        story.append(Paragraph(f"Report ID: {str(result.id)}", footer_style))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"threat_report_{result.input_value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
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