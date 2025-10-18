# scraper.py
import os
import re
import time
import logging
from typing import List, Dict

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv

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

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GOOGLE_CSE_ID = os.getenv("GOOGLE_CSE_ID")


def safe_get(url: str, params=None, headers=None) -> requests.Response:
    """Wrapper for requests.get with logging and timeout"""
    try:
        resp = requests.get(url, params=params, headers=headers or HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp
    except requests.RequestException as e:
        LOGGER.warning("Request failed for %s: %s", url, e)
        return None


def google_cse_search(query: str, num_results: int = 5) -> List[Dict]:
    """
    Google Custom Search Engine - ONLY for displaying scraped data.
    NOT used for threat classification.
    """
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
            # Scrape the page content
            page_content = ""
            page_url = item.get("link")
            
            try:
                page_resp = safe_get(page_url)
                if page_resp:
                    soup = BeautifulSoup(page_resp.text, "html.parser")
                    for tag in soup(["script", "style", "noscript"]):
                        tag.decompose()
                    page_content = " ".join(soup.stripped_strings)[:500]  # First 500 chars
            except:
                page_content = item.get("snippet", "")
            
            results.append({
                "title": item.get("title"),
                "url": page_url,
                "snippet": item.get("snippet", ""),
                "content": page_content,
                "displayLink": item.get("displayLink", "")
            })
            
            time.sleep(0.5)  # Rate limiting
    
    return results