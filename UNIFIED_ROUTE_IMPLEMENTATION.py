"""
Update routes.py to use the unified orchestrator
Add this route to replace the current index() function
"""

# ADD THIS TO routes.py after the imports section:

from app.orchestrator import (
    orchestrate_threat_intelligence,
    detect_input_type,
    format_results_for_template
)

# REPLACE the existing @main_bp.route("/index", methods=["GET", "POST"]) with this:

@main_bp.route("/index-unified", methods=["GET", "POST"])
@login_required
def index_unified():
    """
    🚀 UNIFIED THREAT INTELLIGENCE ENDPOINT
    
    This endpoint orchestrates ALL threat intelligence modules:
    - Automatic input detection (IP, URL, domain, hash, keyword)
    - Parallel API fetching (VirusTotal, Shodan, OTX, Google CSE)
    - ML classification (Random Forest with TF-IDF)
    - LLM analysis (Gemini/Ollama)
    - Unified results display
    """
    form = InputForm()
    
    if form.validate_on_submit():
        user_input = form.input_data.data.strip()
        
        if not user_input:
            flash("Please enter a keyword, IP, URL, domain, or hash.", "warning")
            return redirect(url_for("main.index_unified"))
        
        logger.info(f"\n{'='*80}")
        logger.info(f"🎯 NEW UNIFIED SEARCH REQUEST")
        logger.info(f"   User: {session.get('username', 'Anonymous')}")
        logger.info(f"   Input: {user_input}")
        logger.info(f"{'='*80}\n")
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # STEP 1: Check Cache
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        cached = get_cached_result(user_input)
        if cached:
            logger.info("💾 Returning cached results")
            flash("Results loaded from cache (scanned recently)", "info")
            return render_template(
                "results.html",
                results=cached['results'],
                chart_data=cached.get('chart_data', '{}')
            )
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # STEP 2: Run Unified Orchestration Pipeline
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        try:
            orchestrated_data = orchestrate_threat_intelligence(user_input)
        except Exception as e:
            logger.error(f"❌ Orchestration failed: {e}", exc_info=True)
            flash(f"Error analyzing threat: {str(e)}", "danger")
            return redirect(url_for("main.index_unified"))
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # STEP 3: Save to Database
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        user_ref = None
        if session.get("user_id"):
            try:
                user_ref = User.objects.get(id=session.get("user_id"))
            except Exception as e:
                logger.warning(f"User lookup failed: {e}")
        
        ioc_result = IOCResult(
            input_value=orchestrated_data['input_value'],
            type=orchestrated_data['input_type'],
            vt_report=orchestrated_data.get('vt_data', {}),
            shodan_report=orchestrated_data.get('shodan_data', {}),
            otx_report=orchestrated_data.get('otx_data', {}),
            scraped_data=orchestrated_data.get('google_data', []),
            classification=orchestrated_data.get('classification', 'Unknown'),
            enrichment_context=orchestrated_data.get('llm_analysis', {}),
            user_id=user_ref,
            timestamp=datetime.utcnow()
        )
        ioc_result.save()
        logger.info(f"💾 Saved to MongoDB with ID: {ioc_result.id}")
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # STEP 4: Format Results for Template
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        template_data = format_results_for_template(orchestrated_data)
        template_data['ioc_id'] = str(ioc_result.id)
        
        # Format OTX data for template
        if orchestrated_data.get('otx_data'):
            template_data['otx_formatted'] = format_otx_for_display(
                orchestrated_data['otx_data']
            )
        
        # Format Google data for template
        if orchestrated_data.get('google_data'):
            template_data['google_formatted'] = format_google_for_display(
                orchestrated_data['google_data']
            )
        
        # Chart data for dashboard
        chart_data = {
            "labels": ["Malicious", "Benign", "Informational", "Suspicious", "Unknown"],
            "values": [
                IOCResult.objects(classification="Malicious").count(),
                IOCResult.objects(classification="Benign").count(),
                IOCResult.objects(classification="Informational").count(),
                IOCResult.objects(classification="Suspicious").count(),
                IOCResult.objects(classification="Unknown").count(),
            ]
        }
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # STEP 5: Cache Results
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        set_cached_result(user_input, {
            'results': template_data,
            'chart_data': json.dumps(chart_data)
        })
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # STEP 6: Render Results
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        logger.info(f"\n{'='*80}")
        logger.info(f"✅ UNIFIED ANALYSIS COMPLETE")
        logger.info(f"   Classification: {template_data.get('classification')}")
        logger.info(f"   Total Time: {orchestrated_data.get('timing', {}).get('pipeline_total', 'N/A')}")
        logger.info(f"   Errors: {len(orchestrated_data.get('errors', []))}")
        logger.info(f"{'='*80}\n")
        
        if orchestrated_data.get('errors'):
            flash(f"Note: {len(orchestrated_data['errors'])} API(s) had issues", "warning")
        
        return render_template(
            "results.html",
            results=template_data,
            chart_data=json.dumps(chart_data)
        )
    
    # GET request - show form
    return render_template("index.html", form=form)
