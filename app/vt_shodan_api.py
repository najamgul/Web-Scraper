# vt_shodan_api.py
import os
import requests
import logging

logger = logging.getLogger(__name__)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

VT_BASE_URL = "https://www.virustotal.com/api/v3"
SHODAN_BASE_URL = "https://api.shodan.io"


def vt_lookup_ip(ip):
    """VirusTotal IP lookup with structured response"""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured", "threat_score": 0, "classification": "Unknown", "details": {}}
    
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(f"{VT_BASE_URL}/ip_addresses/{ip}", headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total_engines = sum(stats.values())
            
            # Calculate threat score
            if total_engines > 0:
                threat_score = int(((malicious + suspicious * 0.5) / total_engines) * 100)
            else:
                threat_score = 0
            
            # Classification
            if malicious >= 5:
                classification = "Malicious"
                risk_level = "Critical"
            elif malicious >= 2 or suspicious >= 5:
                classification = "Suspicious"
                risk_level = "High"
            elif malicious > 0 or suspicious > 0:
                classification = "Informational"
                risk_level = "Medium"
            else:
                classification = "Benign"
                risk_level = "Low"
            
            return {
                "threat_score": threat_score,
                "classification": classification,
                "last_analysis_stats": stats,  # ✅ Added for template compatibility
                "details": {
                    "summary": f"{malicious} out of {total_engines} engines flagged this IP as malicious",
                    "risk_level": risk_level,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": total_engines,
                    "country": attributes.get("country", "Unknown"),
                    "as_owner": attributes.get("as_owner", "Unknown"),
                    "reputation": attributes.get("reputation", 0)
                },
                "raw": data
            }
        else:
            return {"error": f"VT API error: {response.status_code}", "threat_score": 0, "classification": "Unknown", "details": {}}
    
    except Exception as e:
        logger.error(f"VirusTotal IP lookup error: {e}")
        return {"error": str(e), "threat_score": 0, "classification": "Unknown", "details": {}}


def vt_lookup_domain(domain):
    """VirusTotal domain lookup"""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured", "threat_score": 0, "classification": "Unknown", "details": {}}
    
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(f"{VT_BASE_URL}/domains/{domain}", headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total_engines = sum(stats.values())
            
            if total_engines > 0:
                threat_score = int(((malicious + suspicious * 0.5) / total_engines) * 100)
            else:
                threat_score = 0
            
            if malicious >= 5:
                classification = "Malicious"
                risk_level = "Critical"
            elif malicious >= 2 or suspicious >= 5:
                classification = "Suspicious"
                risk_level = "High"
            elif malicious > 0 or suspicious > 0:
                classification = "Informational"
                risk_level = "Medium"
            else:
                classification = "Benign"
                risk_level = "Low"
            
            return {
                "threat_score": threat_score,
                "classification": classification,
                "last_analysis_stats": stats,  # ✅ Added for template compatibility
                "details": {
                    "summary": f"{malicious} out of {total_engines} engines flagged this domain as malicious",
                    "risk_level": risk_level,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": total_engines,
                    "reputation": attributes.get("reputation", 0),
                    "categories": attributes.get("categories", {})
                },
                "raw": data
            }
        else:
            return {"error": f"VT API error: {response.status_code}", "threat_score": 0, "classification": "Unknown", "details": {}}
    
    except Exception as e:
        logger.error(f"VirusTotal domain lookup error: {e}")
        return {"error": str(e), "threat_score": 0, "classification": "Unknown", "details": {}}


def vt_lookup_url(url):
    """VirusTotal URL lookup"""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured", "threat_score": 0, "classification": "Unknown", "details": {}}
    
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total_engines = sum(stats.values())
            
            if total_engines > 0:
                threat_score = int(((malicious + suspicious * 0.5) / total_engines) * 100)
            else:
                threat_score = 0
            
            if malicious >= 5:
                classification = "Malicious"
                risk_level = "Critical"
            elif malicious >= 2 or suspicious >= 5:
                classification = "Suspicious"
                risk_level = "High"
            elif malicious > 0 or suspicious > 0:
                classification = "Informational"
                risk_level = "Medium"
            else:
                classification = "Benign"
                risk_level = "Low"
            
            return {
                "threat_score": threat_score,
                "classification": classification,
                "last_analysis_stats": stats,  # ✅ Added for template compatibility
                "details": {
                    "summary": f"{malicious} out of {total_engines} engines flagged this URL as malicious",
                    "risk_level": risk_level,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": total_engines
                },
                "raw": data
            }
        else:
            return {"error": f"VT API error: {response.status_code}", "threat_score": 0, "classification": "Unknown", "details": {}}
    
    except Exception as e:
        logger.error(f"VirusTotal URL lookup error: {e}")
        return {"error": str(e), "threat_score": 0, "classification": "Unknown", "details": {}}


def shodan_lookup(ip):
    """Shodan IP lookup"""
    if not SHODAN_API_KEY:
        return {"error": "Shodan API key not configured", "threat_score": 0, "classification": "Unknown", "details": {}}
    
    try:
        response = requests.get(f"{SHODAN_BASE_URL}/shodan/host/{ip}", params={"key": SHODAN_API_KEY}, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Analyze for suspicious indicators
            open_ports = len(data.get("ports", []))
            vulns = data.get("vulns", [])
            tags = data.get("tags", [])
            
            # Calculate threat score
            threat_score = 0
            if len(vulns) > 10:
                threat_score += 50
            elif len(vulns) > 5:
                threat_score += 30
            elif len(vulns) > 0:
                threat_score += 15
            
            if open_ports > 20:
                threat_score += 20
            elif open_ports > 10:
                threat_score += 10
            
            suspicious_tags = ['malware', 'botnet', 'compromised', 'honeypot']
            if any(tag in suspicious_tags for tag in tags):
                threat_score += 30
            
            threat_score = min(threat_score, 100)
            
            # Classification
            if threat_score >= 60:
                classification = "Malicious"
                risk_level = "Critical"
            elif threat_score >= 30:
                classification = "Suspicious"
                risk_level = "High"
            elif open_ports > 0:
                classification = "Informational"
                risk_level = "Medium"
            else:
                classification = "Benign"
                risk_level = "Low"
            
            return {
                "threat_score": threat_score,
                "classification": classification,
                # ✅ Added for template compatibility
                "ip_str": ip,
                "ip": ip,
                "org": data.get("org", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "ports": data.get("ports", []),
                "vulns": vulns,
                "details": {
                    "summary": f"IP has {open_ports} open ports and {len(vulns)} known vulnerabilities",
                    "risk_level": risk_level,
                    "open_ports": open_ports,
                    "ports": data.get("ports", []),
                    "vulnerabilities": len(vulns),
                    "top_vulns": list(vulns)[:5] if vulns else [],
                    "hostnames": data.get("hostnames", []),
                    "org": data.get("org", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "country": data.get("country_name", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "tags": tags
                },
                "raw": data
            }
        elif response.status_code == 401:
            logger.error("❌ Shodan: Invalid API key")
            return {"error": "Invalid Shodan API key", "threat_score": 0, "classification": "Unknown", "details": {}}
        elif response.status_code == 403:
            logger.error("❌ Shodan: Access denied (insufficient plan or forbidden endpoint)")
            return {"error": "Shodan access denied (check plan permissions)", "threat_score": 0, "classification": "Unknown", "details": {}}
        elif response.status_code == 429:
            logger.error("❌ Shodan: Rate limit exceeded")
            return {"error": "Shodan rate limit exceeded", "threat_score": 0, "classification": "Unknown", "details": {}}
        else:
            logger.error(f"❌ Shodan API error {response.status_code}: {response.text}")
            return {"error": f"Shodan API error: {response.status_code}", "threat_score": 0, "classification": "Unknown", "details": {}}
    
    except Exception as e:
        logger.error(f"Shodan lookup error: {e}")
        return {"error": str(e), "threat_score": 0, "classification": "Unknown", "details": {}}