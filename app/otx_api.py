# otx_api.py
import os
from OTXv2 import OTXv2, IndicatorTypes
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

OTX_API_KEY = os.getenv("OTX_API_KEY", "your_otx_api_key_here")

# Initialize OTX client
try:
    otx_client = OTXv2(OTX_API_KEY)
except Exception as e:
    logger.error(f"Failed to initialize OTX client: {e}")
    otx_client = None


def otx_lookup(query, ioc_type):
    """
    Query the AlienVault OTX Threat Intelligence API for IPs, URLs, domains, hashes, or keywords.
    Returns structured JSON that can be used by ml_model.py.
    
    Args:
        query (str): The indicator to look up (IP, domain, URL, hash, or keyword)
        ioc_type (str): Type of indicator - 'ip', 'domain', 'url', 'hash', 'keyword'
    
    Returns:
        dict: {
            "threat_score": int (0-100),
            "classification": str (malicious/suspicious/benign/unknown),
            "source_count": int (number of pulses/sources),
            "details": dict (human-readable details),
            "raw": dict (full OTX response)
        }
    """
    
    if not otx_client:
        return {
            "error": "OTX client not initialized. Check your API key.",
            "threat_score": 0,
            "classification": "unknown",
            "source_count": 0,
            "details": {},
            "raw": {}
        }
    
    try:
        if ioc_type == "keyword":
            return _otx_keyword_lookup(query)
        elif ioc_type == "ip":
            return _otx_ip_lookup(query)
        elif ioc_type == "domain":
            return _otx_domain_lookup(query)
        elif ioc_type == "url":
            return _otx_url_lookup(query)
        elif ioc_type == "hash":
            return _otx_hash_lookup(query)
        else:
            # Default to keyword search for unknown types
            return _otx_keyword_lookup(query)
    
    except Exception as e:
        logger.error(f"OTX API error for {ioc_type} '{query}': {e}")
        return {
            "error": str(e),
            "threat_score": 0,
            "classification": "unknown",
            "source_count": 0,
            "details": {},
            "raw": {}
        }


def _otx_keyword_lookup(keyword):
    """
    Search OTX pulses for keyword-based threats (e.g., 'fraud', 'rdx', 'ransomware')
    """
    try:
        # Search pulses containing the keyword
        results = otx_client.search_pulses(keyword)
        
        if not results or 'results' not in results:
            return {
                "threat_score": 0,
                "classification": "benign",
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
        
        # Analyze pulses for malicious indicators
        malicious_indicators = 0
        malware_families = []
        attack_ids = []
        tags = []
        adversaries = []
        
        for pulse in pulses[:20]:  # Check top 20 pulses
            pulse_name = pulse.get('name', '').lower()
            pulse_tags = pulse.get('tags', [])
            tags.extend(pulse_tags)
            
            # Count malicious keywords in pulse names and tags
            malicious_terms = [
                'malware', 'ransomware', 'trojan', 'backdoor', 'phishing', 
                'fraud', 'scam', 'exploit', 'vulnerability', 'botnet',
                'c2', 'command and control', 'apt', 'threat', 'attack',
                'rootkit', 'keylogger', 'spyware', 'worm', 'virus'
            ]
            
            if any(term in pulse_name for term in malicious_terms):
                malicious_indicators += 1
            
            if any(term in ' '.join(pulse_tags).lower() for term in malicious_terms):
                malicious_indicators += 1
            
            # Extract malware families
            if 'malware_families' in pulse:
                malware_families.extend(pulse.get('malware_families', []))
            
            # Extract ATT&CK IDs
            if 'attack_ids' in pulse:
                attack_ids.extend(pulse.get('attack_ids', []))
            
            # Extract adversary info
            if 'adversary' in pulse:
                adversaries.append(pulse.get('adversary', ''))
        
        # Calculate threat score (0-100)
        threat_score = min(
            (pulse_count * 5) +          # 5 points per pulse
            (malicious_indicators * 10) + # 10 points per malicious indicator
            (len(set(malware_families)) * 15) + # 15 points per unique malware family
            (len(set(attack_ids)) * 10),  # 10 points per ATT&CK technique
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
        
        # Create human-readable details
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
                "pulses": pulses[:5]
            }
        }
    
    except Exception as e:
        logger.error(f"Keyword lookup error: {e}")
        return {
            "error": str(e),
            "threat_score": 0,
            "classification": "Unknown",
            "source_count": 0,
            "details": {"summary": f"Error analyzing keyword: {str(e)}"},
            "raw": {}
        }


def _otx_ip_lookup(ip):
    """
    Look up IP address reputation in OTX
    """
    try:
        # Get full IP details from OTX
        result = otx_client.get_indicator_details_full(IndicatorTypes.IPv4, ip)
        
        # Extract pulse information
        pulse_info = result.get('pulse_info', {})
        pulse_count = pulse_info.get('count', 0)
        pulses = pulse_info.get('pulses', [])
        
        # Extract general info
        general = result.get('general', {})
        
        # Count malicious pulses
        malicious_count = 0
        tags = []
        
        for pulse in pulses[:10]:
            tags.extend(pulse.get('tags', []))
            if any(term in pulse.get('name', '').lower() 
                   for term in ['malicious', 'malware', 'botnet', 'c2', 'exploit']):
                malicious_count += 1
        
        # Calculate threat score
        threat_score = min(
            (pulse_count * 8) +           # 8 points per pulse
            (malicious_count * 15),       # 15 points per malicious pulse
            100
        )
        
        # Determine classification
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
        
        # Create details
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
        logger.error(f"IP lookup error: {e}")
        return {
            "error": str(e),
            "threat_score": 0,
            "classification": "Unknown",
            "source_count": 0,
            "details": {"summary": f"Error analyzing IP: {str(e)}"},
            "raw": {}
        }


def _otx_domain_lookup(domain):
    """
    Look up domain reputation in OTX
    """
    try:
        result = otx_client.get_indicator_details_full(IndicatorTypes.DOMAIN, domain)
        
        pulse_info = result.get('pulse_info', {})
        pulse_count = pulse_info.get('count', 0)
        pulses = pulse_info.get('pulses', [])
        
        # Analyze pulses
        malicious_count = 0
        tags = []
        
        for pulse in pulses[:10]:
            tags.extend(pulse.get('tags', []))
            pulse_name = pulse.get('name', '').lower()
            if any(term in pulse_name for term in ['phishing', 'malware', 'c2', 'malicious']):
                malicious_count += 1
        
        # Calculate threat score
        threat_score = min(
            (pulse_count * 10) + (malicious_count * 20),
            100
        )
        
        # Classification
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
        
        # Details
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
        logger.error(f"Domain lookup error: {e}")
        return {
            "error": str(e),
            "threat_score": 0,
            "classification": "Unknown",
            "source_count": 0,
            "details": {"summary": f"Error analyzing domain: {str(e)}"},
            "raw": {}
        }


def _otx_url_lookup(url):
    """
    Look up URL reputation in OTX
    """
    try:
        result = otx_client.get_indicator_details_full(IndicatorTypes.URL, url)
        
        pulse_info = result.get('pulse_info', {})
        pulse_count = pulse_info.get('count', 0)
        
        # Calculate threat score
        threat_score = min(pulse_count * 12, 100)
        
        # Classification
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
        logger.error(f"URL lookup error: {e}")
        return {
            "error": str(e),
            "threat_score": 0,
            "classification": "Unknown",
            "source_count": 0,
            "details": {"summary": f"Error analyzing URL: {str(e)}"},
            "raw": {}
        }


def _otx_hash_lookup(file_hash):
    """
    Look up file hash in OTX (supports MD5, SHA1, SHA256)
    """
    try:
        # Detect hash type by length
        hash_length = len(file_hash)
        if hash_length == 32:
            indicator_type = IndicatorTypes.FILE_HASH_MD5
        elif hash_length == 40:
            indicator_type = IndicatorTypes.FILE_HASH_SHA1
        elif hash_length == 64:
            indicator_type = IndicatorTypes.FILE_HASH_SHA256
        else:
            return {
                "error": "Invalid hash length",
                "threat_score": 0,
                "classification": "Unknown",
                "source_count": 0,
                "details": {"summary": "Invalid hash format"},
                "raw": {}
            }
        
        result = otx_client.get_indicator_details_full(indicator_type, file_hash)
        
        pulse_info = result.get('pulse_info', {})
        pulse_count = pulse_info.get('count', 0)
        pulses = pulse_info.get('pulses', [])
        
        # Analyze pulses for malware
        malware_families = []
        for pulse in pulses[:10]:
            if 'malware_families' in pulse:
                malware_families.extend(pulse.get('malware_families', []))
        
        # Calculate threat score - files in OTX are usually malicious
        threat_score = min(
            (pulse_count * 15) + (len(set(malware_families)) * 20),
            100
        )
        
        # Classification
        if pulse_count > 0:
            classification = "Malicious"
            risk_level = "Critical"
        else:
            classification = "Benign"
            risk_level = "Low"
        
        details = {
            "summary": f"Hash found in {pulse_count} malware reports" if pulse_count > 0 else "Hash not found in threat database",
            "risk_level": risk_level,
            "pulses": pulse_count,
            "malware_families": list(set(malware_families))[:5],
            "hash_type": "MD5" if hash_length == 32 else "SHA1" if hash_length == 40 else "SHA256"
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
        logger.error(f"Hash lookup error: {e}")
        return {
            "error": str(e),
            "threat_score": 0,
            "classification": "Unknown",
            "source_count": 0,
            "details": {"summary": f"Error analyzing hash: {str(e)}"},
            "raw": {}
        }