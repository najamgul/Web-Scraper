# app/otx_api.py
import os
from OTXv2 import OTXv2, IndicatorTypes
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

OTX_API_KEY = os.getenv("OTX_API_KEY", "your_otx_api_key_here")

# Initialize OTX client
try:
    otx_client = OTXv2(OTX_API_KEY)
    logger.info("✅ OTX client initialized successfully")
except Exception as e:
    logger.error(f"❌ Failed to initialize OTX client: {e}")
    otx_client = None


def otx_lookup(query, ioc_type):
    """
    ✅ SIMPLIFIED: Query OTX without nested executor
    Timeout is handled by the parent ThreadPoolExecutor in routes.py
    """
    if not otx_client:
        logger.warning("OTX client not initialized")
        return {
            "error": "OTX client not initialized. Check your API key.",
            "threat_score": 0,
            "classification": "Unknown",
            "source_count": 0,
            "details": {},
            "raw": {}
        }
    
    try:
        logger.info(f"🔍 OTX lookup started for {ioc_type}: {query}")
        
        if ioc_type == "keyword":
            result = _otx_keyword_lookup(query)
        elif ioc_type == "ip":
            result = _otx_ip_lookup(query)
        elif ioc_type == "domain":
            result = _otx_domain_lookup(query)
        elif ioc_type == "url":
            result = _otx_url_lookup(query)
        elif ioc_type == "hash":
            result = _otx_hash_lookup(query)
        else:
            result = _otx_keyword_lookup(query)
        
        logger.info(f"✅ OTX lookup completed: {result.get('classification', 'Unknown')}, score: {result.get('threat_score', 0)}")
        return result
    
    except Exception as e:
        logger.error(f"❌ OTX API error for {ioc_type} '{query}': {e}", exc_info=True)
        return {
            "error": str(e),
            "threat_score": 0,
            "classification": "Unknown",
            "source_count": 0,
            "details": {"summary": f"Error: {str(e)}"},
            "raw": {}
        }


def _otx_keyword_lookup(keyword):
    """
    ✅ FIXED: Search OTX pulses WITHOUT nested ThreadPoolExecutor
    Timeout is now handled ONLY by routes.py (40 seconds for keywords)
    """
    try:
        logger.info(f"   Searching OTX pulses for keyword: {keyword}")
        
        # ✅ CRITICAL FIX: Direct call - NO nested ThreadPoolExecutor
        # The timeout is handled by routes.py's /api/otx endpoint
        results = otx_client.search_pulses(keyword)
        
        if not results or 'results' not in results:
            logger.info(f"   No OTX results for keyword: {keyword}")
            return {
                "threat_score": 0,
                "classification": "Benign",
                "source_count": 0,
                "details": {
                    "summary": f"No threat intelligence found for keyword '{keyword}'",
                    "pulses": 0,
                    "risk_level": "Low"
                },
                "raw": {"keyword": keyword, "pulses": []}
            }
        
        pulses = results.get('results', [])
        pulse_count = len(pulses)
        logger.info(f"   Found {pulse_count} pulses for keyword: {keyword}")
        
        # ✅ Process pulses (limit to 20 for speed)
        malicious_indicators = 0
        malware_families = []
        attack_ids = []
        tags = []
        adversaries = []
        
        for pulse in pulses[:20]:  # ← Increased from 15 to 20
            pulse_name = pulse.get('name', '').lower()
            pulse_tags = pulse.get('tags', [])
            tags.extend(pulse_tags)
            
            malicious_terms = [
                'malware', 'ransomware', 'trojan', 'backdoor', 'phishing', 
                'fraud', 'scam', 'exploit', 'vulnerability', 'botnet',
                'c2', 'command and control', 'apt', 'threat', 'attack'
            ]
            
            if any(term in pulse_name for term in malicious_terms):
                malicious_indicators += 1
            
            if any(term in ' '.join(pulse_tags).lower() for term in malicious_terms):
                malicious_indicators += 1
            
            if 'malware_families' in pulse:
                malware_families.extend(pulse.get('malware_families', []))
            
            if 'attack_ids' in pulse:
                attack_ids.extend(pulse.get('attack_ids', []))
            
            if 'adversary' in pulse:
                adv = pulse.get('adversary', '')
                if adv:
                    adversaries.append(adv)
        
        # Calculate threat score
        threat_score = min(
            (pulse_count * 5) +
            (malicious_indicators * 10) +
            (len(set(malware_families)) * 15) +
            (len(set(attack_ids)) * 10),
            100
        )
        
        # Determine classification
        if threat_score >= 70:
            classification = "Malicious"
            risk_level = "Critical"
        elif threat_score >= 40:
            classification = "Suspicious"
            risk_level = "High"
        elif threat_score >= 10:
            classification = "Informational"
            risk_level = "Medium"
        else:
            classification = "Benign"
            risk_level = "Low"
        
        logger.info(f"   Keyword analysis: score={threat_score}, classification={classification}")
        
        details = {
            "summary": f"Found {pulse_count} threat intelligence reports mentioning '{keyword}'",
            "risk_level": risk_level,
            "pulses": pulse_count,
            "malicious_indicators": malicious_indicators,
            "malware_families": list(set(malware_families))[:5],
            "attack_techniques": list(set(attack_ids))[:5],
            "top_tags": list(set(tags))[:10],
            "adversaries": list(set([a for a in adversaries if a]))[:3],
            "top_pulses": [
                {
                    "name": p.get('name', 'Unknown'),
                    "created": p.get('created', 'N/A'),
                    "author": p.get('author_name', 'Anonymous')
                }
                for p in pulses[:5]
            ]
        }
        
        return {
            "threat_score": threat_score,
            "classification": classification,
            "source_count": pulse_count,
            "details": details,
            "raw": {
                "keyword": keyword,
                "total_pulses": pulse_count,
                "pulses": pulses[:5]  # Only include first 5 in raw data
            }
        }
    
    except Exception as e:
        logger.error(f"Keyword lookup error: {e}", exc_info=True)
        return {
            "error": str(e),
            "threat_score": 0,
            "classification": "Unknown",
            "source_count": 0,
            "details": {"summary": f"Error analyzing keyword: {str(e)}"},
            "raw": {}
        }


def _otx_ip_lookup(ip):
    """Look up IP address reputation in OTX"""
    try:
        logger.info(f"   Querying OTX for IP: {ip}")
        result = otx_client.get_indicator_details_full(IndicatorTypes.IPv4, ip)
        
        pulse_info = result.get('pulse_info', {})
        pulse_count = pulse_info.get('count', 0)
        pulses = pulse_info.get('pulses', [])
        general = result.get('general', {})
        
        logger.info(f"   OTX IP result: {pulse_count} pulses")
        
        malicious_count = 0
        tags = []
        
        for pulse in pulses[:10]:
            tags.extend(pulse.get('tags', []))
            if any(term in pulse.get('name', '').lower() 
                   for term in ['malicious', 'malware', 'botnet', 'c2', 'exploit']):
                malicious_count += 1
        
        threat_score = min((pulse_count * 8) + (malicious_count * 15), 100)
        
        if threat_score >= 60 or malicious_count >= 3:
            classification = "Malicious"
            risk_level = "Critical"
        elif threat_score >= 30 or pulse_count >= 5:
            classification = "Suspicious"
            risk_level = "High"
        elif pulse_count > 0:
            classification = "Informational"
            risk_level = "Medium"
        else:
            classification = "Benign"
            risk_level = "Low"
        
        logger.info(f"   IP analysis: score={threat_score}, classification={classification}")
        
        details = {
            "summary": f"IP {ip} found in {pulse_count} threat reports" if pulse_count > 0 else f"IP {ip} appears clean",
            "risk_level": risk_level,
            "pulses": pulse_count,
            "malicious_reports": malicious_count,
            "country": general.get('country_name', 'Unknown'),
            "country_code": general.get('country_code', 'N/A'),
            "city": general.get('city', 'Unknown'),
            "asn": general.get('asn', 'N/A'),
            "top_tags": list(set(tags))[:10],
            "reputation": general.get('reputation', 0)
        }
        
        return {
            "threat_score": threat_score,
            "classification": classification,
            "source_count": pulse_count,
            "details": details,
            "raw": {
                "ip": ip,
                "pulse_info": pulse_info,
                "general": general
            }
        }
    
    except Exception as e:
        logger.error(f"IP lookup error: {e}", exc_info=True)
        return {
            "error": str(e),
            "threat_score": 0,
            "classification": "Unknown",
            "source_count": 0,
            "details": {"summary": f"Error analyzing IP: {str(e)}"},
            "raw": {}
        }


def _otx_domain_lookup(domain):
    """Look up domain reputation in OTX"""
    try:
        logger.info(f"   Querying OTX for domain: {domain}")
        result = otx_client.get_indicator_details_full(IndicatorTypes.DOMAIN, domain)
        
        pulse_info = result.get('pulse_info', {})
        pulse_count = pulse_info.get('count', 0)
        pulses = pulse_info.get('pulses', [])
        
        logger.info(f"   OTX domain result: {pulse_count} pulses")
        
        malicious_count = 0
        tags = []
        
        for pulse in pulses[:10]:
            tags.extend(pulse.get('tags', []))
            pulse_name = pulse.get('name', '').lower()
            if any(term in pulse_name for term in ['phishing', 'malware', 'c2', 'malicious']):
                malicious_count += 1
        
        threat_score = min((pulse_count * 10) + (malicious_count * 20), 100)
        
        if threat_score >= 60:
            classification = "Malicious"
            risk_level = "Critical"
        elif threat_score >= 30:
            classification = "Suspicious"
            risk_level = "High"
        elif pulse_count > 0:
            classification = "Informational"
            risk_level = "Medium"
        else:
            classification = "Benign"
            risk_level = "Low"
        
        logger.info(f"   Domain analysis: score={threat_score}, classification={classification}")
        
        details = {
            "summary": f"Domain {domain} found in {pulse_count} threat reports" if pulse_count > 0 else f"Domain {domain} appears clean",
            "risk_level": risk_level,
            "pulses": pulse_count,
            "malicious_reports": malicious_count,
            "top_tags": list(set(tags))[:10],
            "alexa_rank": result.get('alexa', 'N/A')
        }
        
        return {
            "threat_score": threat_score,
            "classification": classification,
            "source_count": pulse_count,
            "details": details,
            "raw": {
                "domain": domain,
                "pulse_info": pulse_info
            }
        }
    
    except Exception as e:
        logger.error(f"Domain lookup error: {e}", exc_info=True)
        return {
            "error": str(e),
            "threat_score": 0,
            "classification": "Unknown",
            "source_count": 0,
            "details": {"summary": f"Error analyzing domain: {str(e)}"},
            "raw": {}
        }


def _otx_url_lookup(url):
    """Look up URL reputation in OTX"""
    try:
        logger.info(f"   Querying OTX for URL: {url}")
        result = otx_client.get_indicator_details_full(IndicatorTypes.URL, url)
        
        pulse_info = result.get('pulse_info', {})
        pulse_count = pulse_info.get('count', 0)
        
        logger.info(f"   OTX URL result: {pulse_count} pulses")
        
        threat_score = min(pulse_count * 12, 100)
        
        if threat_score >= 50:
            classification = "Malicious"
            risk_level = "Critical"
        elif threat_score >= 25:
            classification = "Suspicious"
            risk_level = "High"
        elif pulse_count > 0:
            classification = "Informational"
            risk_level = "Medium"
        else:
            classification = "Benign"
            risk_level = "Low"
        
        logger.info(f"   URL analysis: score={threat_score}, classification={classification}")
        
        details = {
            "summary": f"URL found in {pulse_count} threat reports" if pulse_count > 0 else "URL appears clean",
            "risk_level": risk_level,
            "pulses": pulse_count
        }
        
        return {
            "threat_score": threat_score,
            "classification": classification,
            "source_count": pulse_count,
            "details": details,
            "raw": {
                "url": url,
                "pulse_info": pulse_info
            }
        }
    
    except Exception as e:
        logger.error(f"URL lookup error: {e}", exc_info=True)
        return {
            "error": str(e),
            "threat_score": 0,
            "classification": "Unknown",
            "source_count": 0,
            "details": {"summary": f"Error analyzing URL: {str(e)}"},
            "raw": {}
        }


def _otx_hash_lookup(file_hash):
    """Look up file hash in OTX"""
    try:
        hash_length = len(file_hash)
        if hash_length == 32:
            indicator_type = IndicatorTypes.FILE_HASH_MD5
            hash_type_name = "MD5"
        elif hash_length == 40:
            indicator_type = IndicatorTypes.FILE_HASH_SHA1
            hash_type_name = "SHA1"
        elif hash_length == 64:
            indicator_type = IndicatorTypes.FILE_HASH_SHA256
            hash_type_name = "SHA256"
        else:
            return {
                "error": "Invalid hash length",
                "threat_score": 0,
                "classification": "Unknown",
                "source_count": 0,
                "details": {"summary": "Invalid hash format"},
                "raw": {}
            }
        
        logger.info(f"   Querying OTX for {hash_type_name} hash: {file_hash[:16]}...")
        result = otx_client.get_indicator_details_full(indicator_type, file_hash)
        
        pulse_info = result.get('pulse_info', {})
        pulse_count = pulse_info.get('count', 0)
        pulses = pulse_info.get('pulses', [])
        
        logger.info(f"   OTX hash result: {pulse_count} pulses")
        
        malware_families = []
        for pulse in pulses[:10]:
            if 'malware_families' in pulse:
                malware_families.extend(pulse.get('malware_families', []))
        
        threat_score = min((pulse_count * 15) + (len(set(malware_families)) * 20), 100)
        
        if pulse_count > 0:
            classification = "Malicious"
            risk_level = "Critical"
        else:
            classification = "Benign"
            risk_level = "Low"
        
        logger.info(f"   Hash analysis: score={threat_score}, classification={classification}")
        
        details = {
            "summary": f"Hash found in {pulse_count} malware reports" if pulse_count > 0 else "Hash not found in threat database",
            "risk_level": risk_level,
            "pulses": pulse_count,
            "malware_families": list(set(malware_families))[:5],
            "hash_type": hash_type_name
        }
        
        return {
            "threat_score": threat_score,
            "classification": classification,
            "source_count": pulse_count,
            "details": details,
            "raw": {
                "hash": file_hash,
                "hash_type": indicator_type,
                "pulse_info": pulse_info
            }
        }
    
    except Exception as e:
        logger.error(f"Hash lookup error: {e}", exc_info=True)
        return {
            "error": str(e),
            "threat_score": 0,
            "classification": "Unknown",
            "source_count": 0,
            "details": {"summary": f"Error analyzing hash: {str(e)}"},
            "raw": {}
        }