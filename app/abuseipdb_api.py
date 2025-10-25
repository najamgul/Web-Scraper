"""
AbuseIPDB API Integration
Provides IP reputation checking and abuse reports
"""

import os
import requests
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"  # ✅ Fixed: .com not .io


def abuseipdb_lookup(ip: str) -> Dict:
    """
    Check IP reputation on AbuseIPDB.
    
    Args:
        ip: IP address to check
    
    Returns:
        dict: AbuseIPDB report with abuse confidence score, reports, and details
    
    Free tier limits: 1,000 checks/day
    """
    if not ABUSEIPDB_API_KEY:
        logger.warning("⚠️ AbuseIPDB API key not configured")
        return {
            "error": "AbuseIPDB API key not configured",
            "threat_score": 0,
            "classification": "Unknown",
            "details": {}
        }
    
    try:
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,  # Check reports from last 90 days
            "verbose": ""  # Get detailed report info
        }
        
        logger.info(f"🔍 Checking AbuseIPDB for IP: {ip}")
        response = requests.get(
            f"{ABUSEIPDB_BASE_URL}/check",
            headers=headers,
            params=params,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            
            # Extract key metrics
            abuse_confidence_score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("numDistinctUsers", 0)
            is_whitelisted = data.get("isWhitelisted", False)
            country_code = data.get("countryCode", "Unknown")
            usage_type = data.get("usageType", "Unknown")
            isp = data.get("isp", "Unknown")
            domain = data.get("domain", "Unknown")
            
            # Calculate threat score (0-100)
            threat_score = int(abuse_confidence_score)
            
            # Determine classification based on abuse confidence
            if is_whitelisted:
                classification = "Benign"
                risk_level = "Low"
            elif abuse_confidence_score >= 75:
                classification = "Malicious"
                risk_level = "Critical"
            elif abuse_confidence_score >= 50:
                classification = "Suspicious"
                risk_level = "High"
            elif abuse_confidence_score >= 25:
                classification = "Informational"
                risk_level = "Medium"
            else:
                classification = "Benign"
                risk_level = "Low"
            
            # Get category breakdown
            reports = data.get("reports", [])
            categories = {}
            for report in reports:
                for category in report.get("categories", []):
                    category_name = get_category_name(category)
                    categories[category_name] = categories.get(category_name, 0) + 1
            
            logger.info(f"✅ AbuseIPDB: Confidence {abuse_confidence_score}%, {total_reports} reports")
            
            return {
                "threat_score": threat_score,
                "classification": classification,
                "abuse_confidence_score": abuse_confidence_score,
                "total_reports": total_reports,
                "is_whitelisted": is_whitelisted,
                "country_code": country_code,
                "usage_type": usage_type,
                "isp": isp,
                "domain": domain,
                "ip_address": data.get("ipAddress", ip),
                "is_public": data.get("isPublic", True),
                "ip_version": data.get("ipVersion", 4),
                "last_reported": data.get("lastReportedAt", None),
                "categories": categories,
                "details": {
                    "summary": f"Abuse confidence: {abuse_confidence_score}% based on {total_reports} reports",
                    "risk_level": risk_level,
                    "abuse_confidence": abuse_confidence_score,
                    "total_reports": total_reports,
                    "distinct_reporters": data.get("numDistinctUsers", 0),
                    "whitelisted": is_whitelisted,
                    "country": country_code,
                    "usage_type": usage_type,
                    "isp": isp,
                    "domain": domain,
                    "categories": categories,
                    "top_categories": list(categories.keys())[:5] if categories else []
                },
                "raw": data
            }
            
        elif response.status_code == 401:
            logger.error("❌ AbuseIPDB: Invalid API key")
            return {
                "error": "Invalid AbuseIPDB API key",
                "threat_score": 0,
                "classification": "Unknown",
                "details": {}
            }
            
        elif response.status_code == 429:
            logger.error("❌ AbuseIPDB: Rate limit exceeded")
            return {
                "error": "AbuseIPDB rate limit exceeded (1000/day)",
                "threat_score": 0,
                "classification": "Unknown",
                "details": {}
            }
            
        elif response.status_code == 422:
            logger.error(f"❌ AbuseIPDB: Invalid IP address: {ip}")
            return {
                "error": f"Invalid IP address: {ip}",
                "threat_score": 0,
                "classification": "Unknown",
                "details": {}
            }
            
        else:
            logger.error(f"❌ AbuseIPDB API error: {response.status_code}")
            return {
                "error": f"AbuseIPDB API error: {response.status_code}",
                "threat_score": 0,
                "classification": "Unknown",
                "details": {}
            }
    
    except requests.exceptions.Timeout:
        logger.error("❌ AbuseIPDB: Request timeout")
        return {
            "error": "AbuseIPDB request timeout",
            "threat_score": 0,
            "classification": "Unknown",
            "details": {}
        }
    
    except requests.exceptions.ConnectionError as e:
        logger.warning(f"⚠️ AbuseIPDB: Connection error (DNS/Network issue) - {e}")
        return {
            "error": "AbuseIPDB connection failed (check DNS/network)",
            "threat_score": 0,
            "classification": "Unknown",
            "details": {},
            "network_issue": True
        }
    
    except Exception as e:
        logger.error(f"❌ AbuseIPDB lookup error: {e}", exc_info=True)
        return {
            "error": str(e),
            "threat_score": 0,
            "classification": "Unknown",
            "details": {}
        }


def get_category_name(category_id: int) -> str:
    """
    Convert AbuseIPDB category ID to human-readable name.
    
    Args:
        category_id: Numeric category ID
    
    Returns:
        str: Category name
    """
    categories = {
        3: "Fraud Orders",
        4: "DDoS Attack",
        5: "FTP Brute-Force",
        6: "Ping of Death",
        7: "Phishing",
        8: "Fraud VoIP",
        9: "Open Proxy",
        10: "Web Spam",
        11: "Email Spam",
        12: "Blog Spam",
        13: "VPN IP",
        14: "Port Scan",
        15: "Hacking",
        16: "SQL Injection",
        17: "Spoofing",
        18: "Brute-Force",
        19: "Bad Web Bot",
        20: "Exploited Host",
        21: "Web App Attack",
        22: "SSH",
        23: "IoT Targeted"
    }
    return categories.get(category_id, f"Category {category_id}")


def abuseipdb_report_ip(ip: str, categories: list, comment: str) -> Dict:
    """
    Report an IP to AbuseIPDB (optional feature).
    
    Args:
        ip: IP address to report
        categories: List of category IDs (e.g., [14, 18] for port scan + brute force)
        comment: Description of the abuse
    
    Returns:
        dict: Report submission result
    
    Note: Requires API key with reporting permissions
    """
    if not ABUSEIPDB_API_KEY:
        return {"error": "AbuseIPDB API key not configured"}
    
    try:
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        
        data = {
            "ip": ip,
            "categories": ",".join(map(str, categories)),
            "comment": comment
        }
        
        response = requests.post(
            f"{ABUSEIPDB_BASE_URL}/report",
            headers=headers,
            data=data,
            timeout=10
        )
        
        if response.status_code == 200:
            logger.info(f"✅ Reported IP {ip} to AbuseIPDB")
            return {"success": True, "data": response.json()}
        else:
            logger.error(f"❌ AbuseIPDB report failed: {response.status_code}")
            return {"error": f"Report failed: {response.status_code}"}
    
    except Exception as e:
        logger.error(f"❌ AbuseIPDB report error: {e}")
        return {"error": str(e)}
