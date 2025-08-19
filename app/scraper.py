import os
import re
import time
import logging
from typing import List, Dict

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv

from app.vt_shodan_api import vt_lookup_domain, vt_lookup_ip, vt_lookup_url, shodan_lookup

load_dotenv()

# -------------------------
# CONFIG
# -------------------------
REQUEST_TIMEOUT = 12
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115 Safari/537.36"
)
HEADERS = {"User-Agent": USER_AGENT}

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)

IP_RE = re.compile(r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$")
URL_RE = re.compile(r"https?://[^\s/$.?#].[^\s]*", re.IGNORECASE)
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GOOGLE_CSE_ID = os.getenv("GOOGLE_CSE_ID")

# -------------------------
# HELPER FUNCTIONS
# -------------------------
def is_ip(s: str) -> bool:
    return bool(IP_RE.fullmatch(s))

def is_url(s: str) -> bool:
    return bool(re.match(r"^https?://", s, re.IGNORECASE))

def is_hash(s: str) -> bool:
    return bool(HASH_RE.fullmatch(s))

def extract_iocs(text: str) -> Dict[str, List[str]]:
    urls = list({m.group(0) for m in URL_RE.finditer(text or "")})
    ips = list({m.group(0) for m in IP_RE.finditer(text or "")})
    hashes = list({m.group(0) for m in HASH_RE.finditer(text or "")})
    return {"urls": urls, "ips": ips, "hashes": hashes}

def safe_get(url: str, params=None, headers=None) -> requests.Response:
    """Wrapper for requests.get with logging and timeout"""
    try:
        resp = requests.get(url, params=params, headers=headers or HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp
    except requests.RequestException as e:
        LOGGER.warning("Request failed for %s: %s", url, e)
        return None

# -------------------------
# GOOGLE CSE SEARCH
# -------------------------
def google_cse_search(query: str, num_results: int = 5) -> List[Dict]:
    if not GOOGLE_API_KEY or not GOOGLE_CSE_ID:
        LOGGER.warning("Google API Key or CSE ID not set")
        return []

    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": GOOGLE_API_KEY,
        "cx": GOOGLE_CSE_ID,
        "q": query,
        "num": num_results,
    }

    resp = safe_get(url, params=params)
    results: List[Dict] = []
    if resp:
        data = resp.json()
        for item in data.get("items", []):
            results.append({
                "title": item.get("title"),
                "url": item.get("link"),
                "snippet": item.get("snippet", "")
            })
    return results

# -------------------------
# STATIC SCRAPER
# -------------------------
def scrape_static_page(url: str, max_chars: int = 3000) -> Dict:
    resp = safe_get(url)
    if not resp:
        return {"url": url, "text": "", "iocs": {"urls": [], "ips": [], "hashes": []},
                "status": "failed", "reason": "Request failed"}
    
    soup = BeautifulSoup(resp.text, "html.parser")
    for t in soup(["script", "style", "noscript"]):
        t.decompose()
    text = " ".join(soup.stripped_strings)
    return {"url": url, "text": text[:max_chars], "iocs": extract_iocs(text), "status": "success", "reason": ""}

# -------------------------
# OTX SCRAPER
# -------------------------
def scrape_otx_indicator(indicator: str, indicator_type: str) -> List[Dict]:
    url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"
    resp = safe_get(url)
    if not resp:
        return []

    data = resp.json()
    pulses = data.get("pulse_info", {}).get("pulses", [])
    return [{"title": p.get("name") or "Pulse", "context": p.get("description") or ""} for p in pulses]

# -------------------------
# MASTER FUNCTION
# -------------------------
def scrape_and_enrich(input_value: str, max_pages: int = 3, vt: bool = True, sh: bool = True) -> List[Dict]:
    results: List[Dict] = []

    # Case 1: IP
    if is_ip(input_value):
        results.extend(scrape_otx_indicator(input_value, "IPv4"))
        vt_info = vt_lookup_ip(input_value) if vt else None
        sh_info = shodan_lookup(input_value) if sh else None
        results.append({
            "title": input_value,
            "url": f"http://{input_value}",
            "iocs": {},
            "virustotal": vt_info or {},
            "shodan": sh_info or {},
            "status": "success",
            "reason": ""
        })

    # Case 2: URL
    elif is_url(input_value):
        results.extend(scrape_otx_indicator(input_value, "url"))
        vt_info = vt_lookup_url(input_value) if vt else None
        results.append({
            "title": input_value,
            "url": input_value,
            "iocs": {},
            "virustotal": vt_info or {},
            "shodan": {},
            "status": "success",
            "reason": ""
        })
        results.append(scrape_static_page(input_value))

    # Case 3: Hash
    elif is_hash(input_value):
        results.append({
            "title": input_value,
            "url": None,
            "iocs": {},
            "virustotal": {},
            "shodan": {},
            "status": "not_applicable",
            "reason": "Hash search only via ThreatFox (if implemented)"
        })

    # Case 4: Keyword
    else:
        search_results = google_cse_search(input_value, num_results=max_pages)
        if not search_results:
            results.append({
                "title": "No results",
                "url": None,
                "iocs": {},
                "virustotal": {},
                "shodan": {},
                "status": "failed",
                "reason": "Google CSE returned no results"
            })
        else:
            for item in search_results:
                page = scrape_static_page(item["url"])
                results.append({
                    "title": item["title"],
                    "url": item["url"],
                    "snippet": item.get("snippet", ""),
                    "content": page.get("text", ""),
                    "iocs": page.get("iocs", {"urls": [], "ips": [], "hashes": []}),
                    "virustotal": {"note": "Not applicable for keywords"},
                    "shodan": {"note": "Not applicable for keywords"},
                    "status": page.get("status", "success"),
                    "reason": page.get("reason", "")
                })
                time.sleep(1)

    return results
