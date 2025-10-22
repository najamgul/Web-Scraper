# app/enrichment.py
"""
AI-Powered Threat Context Enrichment
Aggregates data from multiple sources and generates human-readable explanations
"""
import logging
from app.llm_service import generate_threat_explanation
from app.whois_lookup import get_whois_data
from datetime import datetime

logger = logging.getLogger(__name__)


def enrich_threat_intelligence(ioc_value, ioc_type, vt_data, shodan_data, otx_data, classification):
    """
    ✅ OPTIMIZED: Skip WHOIS lookup to save 5-10 seconds
    """
    try:
        logger.info(f"🧠 Starting enrichment for {ioc_type}: {ioc_value}")
        
        # ✅ SKIP WHOIS - too slow
        whois_data = None
        
        # Extract summaries
        vt_summary = extract_vt_summary(vt_data)
        shodan_summary = extract_shodan_summary(shodan_data, ioc_type)
        otx_summary = extract_otx_summary(otx_data)
        whois_summary = "WHOIS lookup disabled for speed optimization"
        
        # Build context
        context = {
            'ioc_value': ioc_value,
            'ioc_type': ioc_type,
            'classification': classification,
            'vt_summary': vt_summary,
            'shodan_summary': shodan_summary,
            'otx_summary': otx_summary,
            'whois_summary': whois_summary,
            'raw_data': {
                'vt': vt_data,
                'shodan': shodan_data,
                'otx': otx_data,
                'whois': None  # ✅ Skip WHOIS
            }
        }
        
        # ✅ AI explanation with shorter timeout
        ai_explanation = generate_threat_explanation(context)
        
        enrichment = {
            'summary': ai_explanation.get('summary', ''),
            'why_malicious': ai_explanation.get('explanation', ''),
            'key_indicators': ai_explanation.get('indicators', []),
            'recommendation': ai_explanation.get('recommendation', ''),
            'confidence': ai_explanation.get('confidence', 'Medium'),
            'risk_score': calculate_risk_score(vt_data, shodan_data, otx_data),
            'sources_analyzed': get_sources_used(vt_data, shodan_data, otx_data, None),  # ✅ No WHOIS
            'technical_details': {
                'vt_detections': vt_summary,
                'network_exposure': shodan_summary,
                'threat_intelligence': otx_summary,
                'registration_info': whois_summary
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        logger.info(f"✅ Enrichment completed for {ioc_value}")
        return enrichment
    
    except Exception as e:
        logger.error(f"❌ Enrichment error for {ioc_value}: {e}", exc_info=True)
        return {
            'summary': 'Enrichment unavailable',
            'error': str(e),
            'confidence': 'Low'
        }


def extract_vt_summary(vt_data):
    """Extract key findings from VirusTotal report"""
    if not vt_data or 'error' in vt_data:
        return "No VirusTotal data available"
    
    try:
        details = vt_data.get('details', {})
        malicious = details.get('malicious', 0)
        suspicious = details.get('suspicious', 0)
        total = details.get('total_engines', 0)
        
        if malicious > 0:
            return f"{malicious}/{total} security vendors flagged as malicious"
        elif suspicious > 0:
            return f"{suspicious}/{total} security vendors flagged as suspicious"
        else:
            return "Clean - no malicious detections"
    except Exception as e:
        logger.error(f"Error extracting VT summary: {e}")
        return "VirusTotal analysis incomplete"


def extract_shodan_summary(shodan_data, ioc_type):
    """Extract key findings from Shodan report"""
    if not shodan_data or 'error' in shodan_data or ioc_type != 'ip':
        return "No network exposure data"
    
    try:
        details = shodan_data.get('details', {})
        ports = details.get('ports', [])
        vulns = details.get('vulnerabilities', 0)
        
        summary_parts = []
        
        if ports:
            summary_parts.append(f"{len(ports)} open ports detected")
            
            # Highlight risky ports
            risky_ports = [p for p in ports if p in [22, 23, 3389, 445, 1433, 3306]]
            if risky_ports:
                summary_parts.append(f"including high-risk services: {', '.join(map(str, risky_ports))}")
        
        if vulns > 0:
            summary_parts.append(f"{vulns} known CVE vulnerabilities")
        
        return '. '.join(summary_parts) if summary_parts else "No significant network exposure"
    
    except Exception as e:
        logger.error(f"Error extracting Shodan summary: {e}")
        return "Network analysis incomplete"


def extract_otx_summary(otx_data):
    """Extract key findings from AlienVault OTX report"""
    if not otx_data or 'error' in otx_data:
        return "No threat intelligence data"
    
    try:
        details = otx_data.get('details', {})
        pulses = otx_data.get('source_count', 0)
        classification = otx_data.get('classification', 'Unknown')
        
        summary_parts = []
        
        if pulses > 0:
            summary_parts.append(f"Found in {pulses} threat intelligence reports")
        
        malware_families = details.get('malware_families', [])
        if malware_families:
            summary_parts.append(f"Associated with: {', '.join(malware_families[:3])}")
        
        attack_techniques = details.get('attack_techniques', [])
        if attack_techniques:
            summary_parts.append(f"MITRE ATT&CK: {', '.join(attack_techniques[:2])}")
        
        return '. '.join(summary_parts) if summary_parts else "No threat intelligence matches"
    
    except Exception as e:
        logger.error(f"Error extracting OTX summary: {e}")
        return "Threat intelligence analysis incomplete"


def extract_whois_summary(whois_data):
    """Extract key findings from WHOIS data"""
    if not whois_data or 'error' in whois_data:
        return "No registration data"
    
    try:
        summary_parts = []
        
        # Domain age
        if 'creation_date' in whois_data:
            creation = whois_data['creation_date']
            if isinstance(creation, str):
                summary_parts.append(f"Registered: {creation}")
            
            # Check if newly registered (suspicious)
            if whois_data.get('days_old', 999) < 30:
                summary_parts.append("⚠️ Newly registered domain (< 30 days)")
        
        # Registrar
        if 'registrar' in whois_data:
            summary_parts.append(f"Registrar: {whois_data['registrar']}")
        
        # Privacy protection
        if whois_data.get('privacy_protected', False):
            summary_parts.append("⚠️ WHOIS privacy protection enabled")
        
        return '. '.join(summary_parts) if summary_parts else "Registration data available"
    
    except Exception as e:
        logger.error(f"Error extracting WHOIS summary: {e}")
        return "Registration analysis incomplete"


def calculate_risk_score(vt_data, shodan_data, otx_data):
    """
    Calculate overall risk score (0-100)
    """
    score = 0
    
    # VirusTotal component (40 points max)
    if vt_data and 'details' in vt_data:
        malicious = vt_data['details'].get('malicious', 0)
        total = vt_data['details'].get('total_engines', 1)
        if total > 0:
            score += min((malicious / total) * 40, 40)
    
    # Shodan component (30 points max)
    if shodan_data and 'details' in shodan_data:
        vulns = shodan_data['details'].get('vulnerabilities', 0)
        score += min(vulns * 3, 30)
    
    # OTX component (30 points max)
    if otx_data and 'threat_score' in otx_data:
        otx_score = otx_data['threat_score']
        score += min(otx_score * 0.3, 30)
    
    return min(int(score), 100)


def get_sources_used(vt_data, shodan_data, otx_data, whois_data):
    """
    Get list of sources that provided data
    """
    sources = []
    
    if vt_data and 'error' not in vt_data:
        sources.append('VirusTotal')
    if shodan_data and 'error' not in shodan_data:
        sources.append('Shodan')
    if otx_data and 'error' not in otx_data:
        sources.append('AlienVault OTX')
    if whois_data and 'error' not in whois_data:
        sources.append('WHOIS')
    
    return sources