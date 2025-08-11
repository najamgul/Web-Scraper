import os
import re
import time
import logging
from typing import List, Dict

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# Selenium imports
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

# Import VT and Shodan lookups from vt_shodan_api
from app.vt_shodan_api import vt_lookup_domain, vt_lookup_ip, vt_lookup_url, shodan_lookup

load_dotenv()

# Configuration
REQUEST_TIMEOUT = 12
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115 Safari/537.36"
)

HEADERS = {"User-Agent": USER_AGENT}
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s/$.?#].[^\s]*", re.IGNORECASE)
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def is_ip(s: str) -> bool:
    return bool(IP_RE.fullmatch(s))


def is_url(s: str) -> bool:
    return bool(re.match(r"^https?://", s, re.IGNORECASE))


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """Return unique lists of URLs, IPs, and hashes found in text."""
    urls = list({m.group(0) for m in URL_RE.finditer(text)})
    ips = list({m.group(0) for m in IP_RE.finditer(text)})
    hashes = list({m.group(0) for m in HASH_RE.finditer(text)})
    return {"urls": urls, "ips": ips, "hashes": hashes}


# ---------------------------------------------------------------------
# Google dorking
# ---------------------------------------------------------------------
def google_dork_search(keyword: str, num_results: int = 5, pause: float = 1.0) -> List[Dict]:
    query = f'site:* "{keyword}"'
    q = requests.utils.quote(query)
    search_url = f"https://www.google.com/search?q={q}&num={num_results}"
    try:
        resp = requests.get(search_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
    except Exception as e:
        LOGGER.warning("Google search request failed: %s", e)
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    results = []
    items = soup.select("div.tF2Cxc") or soup.select("div.g")
    for g in items[:num_results]:
        a = g.find("a")
        title_tag = g.find("h3")
        snippet_tag = g.select_one(".VwiC3b") or g.find("span.aCOpRe")
        url = a.get("href") if a else None
        title = title_tag.get_text(strip=True) if title_tag else url or "No title"
        snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""
        if url:
            results.append({"title": title, "url": url, "snippet": snippet})
    time.sleep(pause)
    return results


# ---------------------------------------------------------------------
# Static scraping
# ---------------------------------------------------------------------
def scrape_static_page(url: str, max_chars: int = 3000) -> Dict:
    try:
        resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        for t in soup(["script", "style", "noscript"]):
            t.decompose()
        text = " ".join(soup.stripped_strings)
        iocs = extract_iocs(text)
        return {"url": url, "text": text[:max_chars], "iocs": iocs}
    except Exception as e:
        LOGGER.warning("Static scrape failed for %s: %s", url, e)
        return {"url": url, "error": str(e), "text": "", "iocs": {"urls": [], "ips": [], "hashes": []}}


# ---------------------------------------------------------------------
# Dynamic scraping
# ---------------------------------------------------------------------
def _create_headless_driver():
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument(f"user-agent={USER_AGENT}")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    return webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)


def scrape_dynamic_page(url: str, wait_seconds: float = 3.0, max_chars: int = 3000) -> Dict:
    driver = None
    try:
        driver = _create_headless_driver()
        driver.get(url)
        time.sleep(wait_seconds)
        html = driver.page_source
        soup = BeautifulSoup(html, "html.parser")
        for t in soup(["script", "style", "noscript"]):
            t.decompose()
        text = " ".join(soup.stripped_strings)
        iocs = extract_iocs(text)
        return {"url": url, "text": text[:max_chars], "iocs": iocs}
    except Exception as e:
        LOGGER.warning("Dynamic scrape failed for %s: %s", url, e)
        return {"url": url, "error": str(e), "text": "", "iocs": {"urls": [], "ips": [], "hashes": []}}
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass


# ---------------------------------------------------------------------
# Master function
# ---------------------------------------------------------------------
def scrape_and_enrich(keyword: str, max_pages: int = 3, dynamic: bool = False, vt: bool = True, sh: bool = True) -> List[Dict]:
    results = []
    google_hits = google_dork_search(keyword, num_results=max_pages)
    for hit in google_hits:
        url = hit.get("url")
        title = hit.get("title")
        snippet = hit.get("snippet")

        if dynamic:
            page = scrape_dynamic_page(url)
        else:
            page = scrape_static_page(url)

        content = page.get("text", "")
        iocs = page.get("iocs", {"urls": [], "ips": [], "hashes": []})

        vt_info = None
        sh_info = None

        if vt:
            try:
                target_url = iocs["urls"][0] if iocs["urls"] else url
                if is_url(target_url):
                    vt_info = vt_lookup_url(target_url)
                elif is_ip(target_url):
                    vt_info = vt_lookup_ip(target_url)
                else:
                    vt_info = vt_lookup_domain(target_url)
            except Exception as e:
                vt_info = {"error": str(e)}

        if sh and iocs.get("ips"):
            try:
                sh_info = shodan_lookup(iocs["ips"][0])
            except Exception as e:
                sh_info = {"error": str(e)}

        results.append({
            "title": title,
            "url": url,
            "snippet": snippet,
            "content": content,
            "iocs": iocs,
            "virustotal": vt_info,
            "shodan": sh_info
        })

        time.sleep(1.0)

    return results
