import os
import time
import requests
from dotenv import load_dotenv
import shodan

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

REQUEST_TIMEOUT = 12  # match scraper.py timeout

# ---- Helper for safe JSON access ----
def _safe_get(d, *keys, default=None):
    for k in keys:
        if not isinstance(d, dict) or k not in d:
            return default
        d = d[k]
    return d

# ---- VirusTotal: domain lookup ----
def vt_lookup_domain(domain):
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    headers = {"x-apikey": VT_API_KEY}
    url = f"{VT_BASE}/domains/{domain}"
    try:
        r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            return {"error": f"VT domain lookup failed ({r.status_code})", "raw": r.text}
        data = r.json()
        stats = _safe_get(data, "data", "attributes", "last_analysis_stats", default={})
        return {
            "type": "domain",
            "domain": domain,
            "last_analysis_stats": stats,
            "raw": data
        }
    except requests.RequestException as e:
        return {"error": str(e)}

# ---- VirusTotal: IP lookup ----
def vt_lookup_ip(ip):
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    headers = {"x-apikey": VT_API_KEY}
    url = f"{VT_BASE}/ip_addresses/{ip}"
    try:
        r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            return {"error": f"VT IP lookup failed ({r.status_code})", "raw": r.text}
        data = r.json()
        stats = _safe_get(data, "data", "attributes", "last_analysis_stats", default={})
        return {
            "type": "ip",
            "ip": ip,
            "last_analysis_stats": stats,
            "raw": data
        }
    except requests.RequestException as e:
        return {"error": str(e)}

# ---- VirusTotal: URL scan & report (POST then poll) ----
def vt_lookup_url(url_to_check, poll_seconds=2, max_polls=8):
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    headers = {"x-apikey": VT_API_KEY}
    try:
        post = requests.post(f"{VT_BASE}/urls", headers=headers, data={"url": url_to_check}, timeout=REQUEST_TIMEOUT)
        if post.status_code not in (200, 201):
            return {"error": f"VT URL submit failed ({post.status_code})", "raw": post.text}

        j = post.json()
        analysis_id = _safe_get(j, "data", "id")

        for _ in range(max_polls):
            time.sleep(poll_seconds)
            rep = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=REQUEST_TIMEOUT)
            if rep.status_code != 200:
                continue
            rep_json = rep.json()
            status = _safe_get(rep_json, "data", "attributes", "status")
            if status == "completed":
                stats = _safe_get(rep_json, "data", "attributes", "stats", default={})
                return {
                    "type": "url",
                    "url": url_to_check,
                    "analysis_id": analysis_id,
                    "analysis_status": status,
                    "analysis_stats": stats,
                    "raw_analysis": rep_json
                }

        return {"error": "VT analysis not ready in time", "analysis_id": analysis_id}
    except requests.RequestException as e:
        return {"error": str(e)}

# ---- Shodan lookup ----
def shodan_lookup(ip):
    if not SHODAN_API_KEY:
        return {"error": "Shodan API key not configured"}
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)
        vulns = host.get("vulns", []) or []
        return {
            "ip": ip,
            "org": host.get("org"),
            "os": host.get("os"),
            "ports": host.get("ports", []),
            "vulns": vulns,
            "hostnames": host.get("hostnames", []),
            "raw": host
        }
    except shodan.APIError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}
