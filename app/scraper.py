# scraper.py
import os
import re
import time
import logging
from typing import List, Dict

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import urllib3
import certifi

load_dotenv()

# -------------------------
# CONFIG
# -------------------------
REQUEST_TIMEOUT = 10
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115 Safari/537.36"
)
HEADERS = {"User-Agent": USER_AGENT}

# ✅ SSL Configuration
SSL_VERIFY = os.getenv("SSL_VERIFY", "false").lower() == "true"

# ✅ Disable SSL warnings for development
if not SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GOOGLE_CSE_ID = os.getenv("GOOGLE_CSE_ID")


def get_ssl_verify():
    """
    Get SSL verification setting
    Returns certifi bundle path for production, False for development
    """
    if SSL_VERIFY:
        try:
            return certifi.where()
        except:
            return True
    return False


def safe_get(url: str, params=None, headers=None) -> requests.Response:
    """
    Wrapper for requests.get with logging, timeout, and SSL handling
    """
    try:
        resp = requests.get(
            url, 
            params=params, 
            headers=headers or HEADERS, 
            timeout=REQUEST_TIMEOUT,
            verify=get_ssl_verify()  # ✅ Use SSL verification setting
        )
        resp.raise_for_status()
        return resp
    except requests.exceptions.SSLError as e:
        LOGGER.warning("SSL Error for %s: %s (Try setting SSL_VERIFY=false in .env)", url, e)
        
        # ✅ Retry without SSL verification for development
        if not SSL_VERIFY:
            try:
                resp = requests.get(
                    url, 
                    params=params, 
                    headers=headers or HEADERS, 
                    timeout=REQUEST_TIMEOUT,
                    verify=False
                )
                resp.raise_for_status()
                return resp
            except Exception as retry_error:
                LOGGER.error("Retry failed for %s: %s", url, retry_error)
                return None
        return None
    except requests.exceptions.Timeout as e:
        LOGGER.warning("Timeout for %s: %s", url, e)
        return None
    except requests.exceptions.ConnectionError as e:
        LOGGER.warning("Connection error for %s: %s", url, e)
        return None
    except requests.RequestException as e:
        LOGGER.warning("Request failed for %s: %s", url, e)
        return None
    except Exception as e:
        LOGGER.error("Unexpected error for %s: %s", url, e)
        return None


def google_cse_search(query: str, num_results: int = 3) -> List[Dict]:  # ← Changed from 5 to 3
    """
    ✅ OPTIMIZED: Reduced results and timeout
    """
    if not GOOGLE_API_KEY or not GOOGLE_CSE_ID:
        return []  # ✅ Skip mock data to save time

    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": GOOGLE_API_KEY,
        "cx": GOOGLE_CSE_ID,
        "q": query,
        "num": num_results,  # ✅ Only 3 results
    }

    resp = safe_get(url, params=params)
    results: List[Dict] = []
    
    if resp:
        try:
            data = resp.json()
            for item in data.get("items", []):
                page_content = item.get("snippet", "")  # ✅ Skip actual page scraping
                
                results.append({
                    "title": item.get("title", "No title"),
                    "url": item.get("link", "#"),
                    "snippet": item.get("snippet", ""),
                    "content": page_content,
                    "displayLink": item.get("displayLink", "")
                })
                
                # ✅ No sleep needed - we're not scraping pages
        except ValueError as json_error:
            LOGGER.error(f"Failed to parse Google CSE response: {json_error}")
    
    return results

def scrape_url(url: str) -> Dict:
    """
    Scrape a single URL and return metadata
    """
    result = {
        "url": url,
        "status": "error",
        "title": "",
        "content": "",
        "error": None
    }
    
    try:
        resp = safe_get(url)
        if resp:
            soup = BeautifulSoup(resp.text, "html.parser")
            
            # Remove unwanted tags
            for tag in soup(["script", "style", "noscript", "iframe"]):
                tag.decompose()
            
            result["status"] = "success"
            result["title"] = soup.title.string if soup.title else "No title"
            result["content"] = " ".join(soup.stripped_strings)[:1000]
        else:
            result["error"] = "Failed to fetch URL"
    except Exception as e:
        LOGGER.error("Error scraping %s: %s", url, e)
        result["error"] = str(e)
    
    return result