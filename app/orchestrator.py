"""
Unified Threat Intelligence Orchestrator
========================================
This module orchestrates all threat intelligence modules into a single pipeline:
- Google Custom Search Engine (CSE)
- VirusTotal API
- Shodan API
- AlienVault OTX
- LLM Analysis (Gemini/Ollama)
- ML Classification (Random Forest with TF-IDF)

Author: Threat Intelligence System
Date: 2025-10-25
"""

import logging
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
from datetime import datetime
from typing import Dict, List, Tuple, Any

# Import all API modules
from app.scraper import google_cse_search
from app.vt_shodan_api import vt_lookup_ip, vt_lookup_domain, vt_lookup_url, shodan_lookup
from app.otx_api import otx_lookup
from app.abuseipdb_api import abuseipdb_lookup
from app.llm_service import generate_threat_explanation

try:
    from app.ml_model_improved import classify_threat_with_details, classify_threat
    ML_MODEL_TYPE = "improved"
except ImportError:
    from app.ml_model import classify_threat
    classify_threat_with_details = None
    ML_MODEL_TYPE = "legacy"

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ============================================================================
# INPUT TYPE DETECTION
# ============================================================================

def detect_input_type(user_input: str) -> str:
    """
    Automatically detect the type of user input.
    
    Args:
        user_input (str): Raw user input
    
    Returns:
        str: One of 'ip', 'url', 'domain', 'hash', or 'keyword'
    
    Examples:
        >>> detect_input_type("192.168.1.1")
        'ip'
        >>> detect_input_type("https://example.com/page")
        'url'
        >>> detect_input_type("example.com")
        'domain'
        >>> detect_input_type("d41d8cd98f00b204e9800998ecf8427e")
        'hash'
        >>> detect_input_type("malware analysis")
        'keyword'
    """
    user_input = user_input.strip()
    
    # IP Address Pattern (IPv4)
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    if re.match(ip_pattern, user_input):
        # Validate IP ranges
        parts = user_input.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            return "ip"
    
    # URL Pattern (http/https)
    url_pattern = r"^https?://[^\s/$.?#].[^\s]*$"
    if re.match(url_pattern, user_input, re.IGNORECASE):
        return "url"
    
    # Domain Pattern (e.g., example.com, sub.example.co.uk)
    domain_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.[A-Za-z]{2,})+$"
    if re.match(domain_pattern, user_input):
        return "domain"
    
    # Hash Pattern (MD5: 32, SHA1: 40, SHA256: 64, SHA512: 128)
    hash_pattern = r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$"
    if re.match(hash_pattern, user_input):
        return "hash"
    
    # Default to keyword search
    return "keyword"


# ============================================================================
# API ORCHESTRATION FUNCTIONS
# ============================================================================

def search_virustotal(user_input: str, input_type: str) -> Dict:
    """
    Search VirusTotal based on input type.
    
    Args:
        user_input: The IOC to search
        input_type: Type of input (ip, url, domain, hash)
    
    Returns:
        dict: VirusTotal results with threat_score, classification, details
    """
    try:
        logger.info(f"🔍 Searching VirusTotal for {input_type}: {user_input}")
        
        if input_type == "ip":
            result = vt_lookup_ip(user_input)
        elif input_type == "url":
            result = vt_lookup_url(user_input)
        elif input_type in ["domain", "hash"]:
            result = vt_lookup_domain(user_input)
        else:
            # Keywords don't have direct VT lookup
            return {"error": "VirusTotal does not support keyword search", "threat_score": 0}
        
        if result and 'error' not in result:
            logger.info(f"✅ VirusTotal: {result.get('classification', 'Unknown')} (Score: {result.get('threat_score', 0)})")
        else:
            logger.warning(f"⚠️ VirusTotal: {result.get('error', 'Unknown error')}")
        
        return result or {}
    
    except Exception as e:
        logger.error(f"❌ VirusTotal error: {e}", exc_info=True)
        return {"error": str(e), "threat_score": 0, "classification": "Unknown"}


def search_shodan(user_input: str, input_type: str) -> Dict:
    """
    Search Shodan for exposed devices/services.
    
    Args:
        user_input: The IOC to search
        input_type: Type of input (primarily 'ip')
    
    Returns:
        dict: Shodan results with open ports, services, vulnerabilities
    """
    try:
        # Shodan primarily works with IPs
        if input_type != "ip":
            logger.info(f"ℹ️ Shodan: Skipping (not an IP address)")
            return {"error": "Shodan only supports IP addresses", "info": "Not applicable"}
        
        logger.info(f"🔍 Searching Shodan for IP: {user_input}")
        result = shodan_lookup(user_input)
        
        if result and 'error' not in result:
            ports = result.get('ports', [])
            logger.info(f"✅ Shodan: Found {len(ports)} open ports")
        else:
            logger.warning(f"⚠️ Shodan: {result.get('error', 'Unknown error')}")
        
        return result or {}
    
    except Exception as e:
        logger.error(f"❌ Shodan error: {e}", exc_info=True)
        return {"error": str(e)}


def search_otxvault(user_input: str, input_type: str) -> Dict:
    """
    Search AlienVault OTX for threat intelligence.
    
    Args:
        user_input: The IOC to search
        input_type: Type of input
    
    Returns:
        dict: OTX results with pulses, malware families, threat score
    """
    try:
        logger.info(f"🔍 Searching AlienVault OTX for {input_type}: {user_input}")
        result = otx_lookup(user_input, input_type)
        
        if result and 'error' not in result:
            classification = result.get('classification', 'Unknown')
            pulses = result.get('details', {}).get('pulses', 0)
            logger.info(f"✅ OTX: {classification} ({pulses} pulses)")
        else:
            logger.warning(f"⚠️ OTX: {result.get('error', 'Unknown error')}")
        
        return result or {}
    
    except Exception as e:
        logger.error(f"❌ OTX error: {e}", exc_info=True)
        return {"error": str(e), "threat_score": 0, "classification": "Unknown"}


def search_abuseipdb(user_input: str, input_type: str) -> Dict:
    """
    Search AbuseIPDB for IP reputation and abuse reports.
    
    Args:
        user_input: The IOC to search
        input_type: Type of input (primarily 'ip')
    
    Returns:
        dict: AbuseIPDB results with abuse confidence score and reports
    """
    try:
        # AbuseIPDB only works with IPs
        if input_type != "ip":
            logger.info(f"ℹ️ AbuseIPDB: Skipping (not an IP address)")
            return {"error": "AbuseIPDB only supports IP addresses", "info": "Not applicable"}
        
        logger.info(f"🔍 Searching AbuseIPDB for IP: {user_input}")
        result = abuseipdb_lookup(user_input)
        
        if result and 'error' not in result:
            confidence = result.get('abuse_confidence_score', 0)
            reports = result.get('total_reports', 0)
            logger.info(f"✅ AbuseIPDB: Confidence {confidence}%, {reports} reports")
        else:
            logger.warning(f"⚠️ AbuseIPDB: {result.get('error', 'Unknown error')}")
        
        return result or {}
    
    except Exception as e:
        logger.error(f"❌ AbuseIPDB error: {e}", exc_info=True)
        return {"error": str(e)}


def search_google_cse(keyword: str, input_type: str) -> List[Dict]:
    """
    Search Google Custom Search Engine for keyword-based threat research.
    
    Args:
        keyword: Search keyword
        input_type: Should be 'keyword' for CSE to run
    
    Returns:
        list: Google search results with titles, URLs, snippets
    """
    try:
        if input_type != "keyword":
            logger.info(f"ℹ️ Google CSE: Skipping (only works for keywords)")
            return []
        
        logger.info(f"🔍 Searching Google CSE for keyword: {keyword}")
        results = google_cse_search(keyword)
        
        if results and isinstance(results, list) and len(results) > 0:
            logger.info(f"✅ Google CSE: Found {len(results)} results")
        else:
            logger.warning(f"⚠️ Google CSE: No results found")
        
        return results or []
    
    except Exception as e:
        logger.error(f"❌ Google CSE error: {e}", exc_info=True)
        return []


def analyze_with_llm(unified_context: Dict) -> Dict:
    """
    Generate AI-powered threat analysis using LLM (Gemini/Ollama).
    
    Args:
        unified_context: Combined intelligence from all sources
    
    Returns:
        dict: LLM analysis with summary, explanation, indicators, recommendation
    """
    try:
        logger.info(f"🤖 Generating AI analysis with LLM...")
        
        # Build context for LLM
        llm_context = {
            'ioc_value': unified_context.get('input_value'),
            'ioc_type': unified_context.get('input_type'),
            'classification': unified_context.get('classification', 'Unknown'),
            'vt_summary': unified_context.get('vt_summary', 'No data'),
            'shodan_summary': unified_context.get('shodan_summary', 'No data'),
            'otx_summary': unified_context.get('otx_summary', 'No data'),
            'whois_summary': 'Skipped for performance',
            'raw_data': {
                'vt': unified_context.get('vt_data', {}),
                'shodan': unified_context.get('shodan_data', {}),
                'otx': unified_context.get('otx_data', {}),
                'google': unified_context.get('google_data', [])
            }
        }
        
        analysis = generate_threat_explanation(llm_context)
        
        if analysis and 'summary' in analysis:
            logger.info(f"✅ LLM Analysis: Generated {len(analysis.get('summary', ''))} char summary")
        else:
            logger.warning(f"⚠️ LLM Analysis: Using fallback")
        
        return analysis or {}
    
    except Exception as e:
        logger.error(f"❌ LLM Analysis error: {e}", exc_info=True)
        return {
            'summary': 'AI analysis unavailable',
            'explanation': f'Error generating analysis: {str(e)}',
            'indicators': [],
            'recommendation': 'Manual review recommended',
            'confidence': 'Low'
        }


def classify_threat_level(unified_context: Dict) -> Tuple[str, Dict]:
    """
    Classify threat level using ML model (Random Forest with TF-IDF).
    
    Args:
        unified_context: Combined intelligence from all sources
    
    Returns:
        tuple: (classification, details_dict)
            - classification: One of 'Malicious', 'Suspicious', 'Benign'
            - details_dict: Model confidence, API scores, reasoning
    """
    try:
        logger.info(f"🧠 Classifying threat with ML model ({ML_MODEL_TYPE})...")
        
        # Extract text for classification
        input_value = unified_context.get('input_value', '')
        input_type = unified_context.get('input_type', 'unknown')
        
        # Get API data
        vt_data = unified_context.get('vt_data', {})
        shodan_data = unified_context.get('shodan_data', {})
        otx_data = unified_context.get('otx_data', {})
        abuseipdb_data = unified_context.get('abuseipdb_data', {})
        
        # Use improved model with details if available
        if classify_threat_with_details:
            classification, details = classify_threat_with_details(
                user_input=input_value,
                ioc_type=input_type,
                vt_data=vt_data,
                shodan_data=shodan_data,
                otx_data=otx_data,
                abuseipdb_data=abuseipdb_data
            )
            logger.info(f"✅ ML Classification: {classification} (Confidence: {details.get('model_confidence', 0):.2%})")
            logger.info(f"   Context: {details.get('context_analysis', 'N/A')}")
            logger.info(f"   Reasoning: {details.get('reasoning', 'N/A')}")
            return classification, details
        else:
            # Fallback to legacy model
            classification = classify_threat(
                user_input=input_value,
                ioc_type=input_type,
                vt_data=vt_data,
                shodan_data=shodan_data,
                otx_data=otx_data,
                abuseipdb_data=abuseipdb_data
            )
            logger.info(f"✅ ML Classification (legacy): {classification}")
            return classification, {'model': 'legacy', 'confidence': 'N/A'}
    
    except Exception as e:
        logger.error(f"❌ ML Classification error: {e}", exc_info=True)
        return "Unknown", {'error': str(e)}


# ============================================================================
# PARALLEL API FETCHER
# ============================================================================

def fetch_all_intelligence_parallel(user_input: str, input_type: str) -> Dict:
    """
    Fetch data from ALL threat intelligence sources IN PARALLEL.
    
    This is the core orchestration function that runs:
    - VirusTotal
    - Shodan (if IP)
    - AlienVault OTX
    - Google CSE (if keyword)
    
    All APIs are called simultaneously using ThreadPoolExecutor.
    
    Args:
        user_input: The IOC or keyword to investigate
        input_type: Type detected (ip, url, domain, hash, keyword)
    
    Returns:
        dict: Unified results from all sources with timing info
    """
    logger.info(f"{'='*70}")
    logger.info(f"🚀 STARTING PARALLEL THREAT INTELLIGENCE PIPELINE")
    logger.info(f"   Input: {user_input}")
    logger.info(f"   Type: {input_type}")
    logger.info(f"{'='*70}")
    
    start_time = datetime.utcnow()
    results = {
        'vt_data': {},
        'shodan_data': {},
        'otx_data': {},
        'abuseipdb_data': {},
        'google_data': [],
        'timing': {},
        'errors': []
    }
    
    # Submit all tasks to thread pool
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        
        # VirusTotal (for all except keywords)
        if input_type != "keyword":
            futures['vt'] = executor.submit(search_virustotal, user_input, input_type)
        
        # Shodan (only for IPs)
        if input_type == "ip":
            futures['shodan'] = executor.submit(search_shodan, user_input, input_type)
        
        # AbuseIPDB (only for IPs)
        if input_type == "ip":
            futures['abuseipdb'] = executor.submit(search_abuseipdb, user_input, input_type)
        
        # OTX (for all types)
        futures['otx'] = executor.submit(search_otxvault, user_input, input_type)
        
        # Google CSE (only for keywords)
        if input_type == "keyword":
            futures['google'] = executor.submit(search_google_cse, user_input, input_type)
        
        # Collect results as they complete (with timeout protection)
        for key, future in futures.items():
            api_start = datetime.utcnow()
            try:
                # Set timeout based on API
                timeout = 20 if key == 'otx' else 15
                
                result = future.result(timeout=timeout)
                elapsed = (datetime.utcnow() - api_start).total_seconds()
                
                # Store result
                if key == 'vt':
                    results['vt_data'] = result
                elif key == 'shodan':
                    results['shodan_data'] = result
                elif key == 'abuseipdb':
                    results['abuseipdb_data'] = result
                elif key == 'otx':
                    results['otx_data'] = result
                elif key == 'google':
                    results['google_data'] = result
                
                results['timing'][key] = f"{elapsed:.2f}s"
                
            except TimeoutError:
                elapsed = (datetime.utcnow() - api_start).total_seconds()
                error_msg = f"{key.upper()} API timeout after {elapsed:.1f}s"
                logger.error(f"❌ {error_msg}")
                results['errors'].append(error_msg)
                results['timing'][key] = f"TIMEOUT ({elapsed:.1f}s)"
                
            except Exception as e:
                elapsed = (datetime.utcnow() - api_start).total_seconds()
                error_msg = f"{key.upper()} error: {str(e)}"
                logger.error(f"❌ {error_msg}")
                results['errors'].append(error_msg)
                results['timing'][key] = f"ERROR ({elapsed:.1f}s)"
    
    total_elapsed = (datetime.utcnow() - start_time).total_seconds()
    results['timing']['total'] = f"{total_elapsed:.2f}s"
    
    # Log summary
    logger.info(f"\n{'='*70}")
    logger.info(f"📊 PARALLEL FETCH SUMMARY")
    logger.info(f"   Total Time: {total_elapsed:.2f}s")
    for api, timing in results['timing'].items():
        if api != 'total':
            status = '✅' if 'ERROR' not in timing and 'TIMEOUT' not in timing else '❌'
            logger.info(f"   {status} {api.upper()}: {timing}")
    logger.info(f"{'='*70}\n")
    
    return results


# ============================================================================
# UNIFIED ORCHESTRATION PIPELINE
# ============================================================================

def orchestrate_threat_intelligence(user_input: str) -> Dict:
    """
    MAIN ORCHESTRATION FUNCTION
    
    This is the single entry point that:
    1. Detects input type automatically
    2. Fetches data from ALL relevant APIs in parallel
    3. Runs ML classification
    4. Generates LLM analysis
    5. Returns unified structured response
    
    Args:
        user_input (str): User's search query (keyword, IP, URL, domain, hash)
    
    Returns:
        dict: Comprehensive threat intelligence report with:
            - input_value: Original input
            - input_type: Detected type
            - classification: Threat level (Malicious/Suspicious/Benign)
            - classification_details: ML model confidence and reasoning
            - vt_data: VirusTotal results
            - shodan_data: Shodan results
            - otx_data: OTX results
            - google_data: Google CSE results (for keywords)
            - llm_analysis: AI-generated explanation
            - timing: Performance metrics
            - errors: Any errors encountered
    """
    logger.info(f"\n{'#'*70}")
    logger.info(f"# UNIFIED THREAT INTELLIGENCE ORCHESTRATOR")
    logger.info(f"# Input: {user_input}")
    logger.info(f"{'#'*70}\n")
    
    pipeline_start = datetime.utcnow()
    
    # Step 1: Detect input type
    logger.info("STEP 1️⃣: Detecting input type...")
    input_type = detect_input_type(user_input)
    logger.info(f"✅ Detected type: {input_type}\n")
    
    # Step 2: Fetch all intelligence in parallel
    logger.info("STEP 2️⃣: Fetching threat intelligence from all sources...")
    intel_results = fetch_all_intelligence_parallel(user_input, input_type)
    
    # Step 3: Build unified context
    logger.info("STEP 3️⃣: Building unified context...")
    unified_context = {
        'input_value': user_input,
        'input_type': input_type,
    'vt_data': intel_results.get('vt_data', {}),
    'shodan_data': intel_results.get('shodan_data', {}),
    'otx_data': intel_results.get('otx_data', {}),
    'abuseipdb_data': intel_results.get('abuseipdb_data', {}),
    'google_data': intel_results.get('google_data', []),
    'vt_summary': _extract_summary(intel_results.get('vt_data', {})),
    'shodan_summary': _extract_summary(intel_results.get('shodan_data', {})),
    'otx_summary': _extract_summary(intel_results.get('otx_data', {})),
    'abuseipdb_summary': _extract_summary(intel_results.get('abuseipdb_data', {})),
    }
    
    # Step 4: ML Classification
    logger.info("\nSTEP 4️⃣: Running ML threat classification...")
    classification, class_details = classify_threat_level(unified_context)
    unified_context['classification'] = classification
    unified_context['classification_details'] = class_details
    
    # Step 5: LLM Analysis (optional, can be async)
    logger.info("\nSTEP 5️⃣: Generating AI analysis...")
    llm_analysis = analyze_with_llm(unified_context)
    unified_context['llm_analysis'] = llm_analysis
    
    # Add metadata
    total_time = (datetime.utcnow() - pipeline_start).total_seconds()
    unified_context['timing'] = intel_results.get('timing', {})
    unified_context['timing']['pipeline_total'] = f"{total_time:.2f}s"
    unified_context['errors'] = intel_results.get('errors', [])
    unified_context['timestamp'] = datetime.utcnow()
    
    logger.info(f"\n{'#'*70}")
    logger.info(f"✅ ORCHESTRATION COMPLETE")
    logger.info(f"   Classification: {classification}")
    logger.info(f"   Total Pipeline Time: {total_time:.2f}s")
    logger.info(f"   Errors: {len(unified_context['errors'])}")
    logger.info(f"{'#'*70}\n")
    
    return unified_context


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _extract_summary(api_data: Dict) -> str:
    """Extract a human-readable summary from API response"""
    if not api_data or 'error' in api_data:
        return api_data.get('error', 'No data available')
    
    # Try to get summary from details
    if 'details' in api_data and 'summary' in api_data['details']:
        return api_data['details']['summary']
    
    # Fallback to classification
    classification = api_data.get('classification', 'Unknown')
    threat_score = api_data.get('threat_score', 0)
    return f"Classification: {classification} (Score: {threat_score})"


def format_results_for_template(orchestrated_data: Dict) -> Dict:
    """
    Format orchestrated data for Flask template rendering.
    
    Args:
        orchestrated_data: Output from orchestrate_threat_intelligence()
    
    Returns:
        dict: Template-friendly data structure
    """
    return {
        'input_value': orchestrated_data.get('input_value'),
        'input_type': orchestrated_data.get('input_type'),
        'classification': orchestrated_data.get('classification', 'Unknown'),
        'classification_details': orchestrated_data.get('classification_details', {}),
        
        # API Results
        'vt': orchestrated_data.get('vt_data', {}),
        'shodan': orchestrated_data.get('shodan_data', {}),
        'abuseipdb': orchestrated_data.get('abuseipdb_data', {}),
        'otx': orchestrated_data.get('otx_data', {}),
        'google_results': orchestrated_data.get('google_data', []),
        
        # AI Analysis
        'llm_analysis': orchestrated_data.get('llm_analysis', {}),
        'enrichment': orchestrated_data.get('llm_analysis', {}),  # Alias for compatibility
        
        # Metadata
        'timing': orchestrated_data.get('timing', {}),
        'errors': orchestrated_data.get('errors', []),
        'timestamp': orchestrated_data.get('timestamp'),
        
        # For backward compatibility with existing templates
        'ioc_id': None,  # Will be set after DB save
    }
