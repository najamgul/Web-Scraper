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
REQUEST_TIMEOUT = 12
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


def google_cse_search(query: str, num_results: int = 5) -> List[Dict]:
    """
    Google Custom Search Engine - ONLY for displaying scraped data.
    NOT used for threat classification.
    """
    if not GOOGLE_API_KEY or not GOOGLE_CSE_ID:
        LOGGER.warning("Google API Key or CSE ID not set. Returning mock data.")
        # ✅ Return informational mock data if API not configured
        return [
            {
                "title": f"Threat Intelligence: {query}",
                "url": f"https://example.com/threat/{query}",
                "snippet": f"Threat analysis and intelligence data for {query}",
                "content": f"Comprehensive threat intelligence report for the indicator: {query}. This information is aggregated from multiple security feeds.",
                "displayLink": "example.com"
            },
            {
                "title": f"Security Report: {query}",
                "url": f"https://security.example.com/{query}",
                "snippet": f"Security assessment report for {query}",
                "content": f"Detailed security analysis covering reputation, risk factors, and historical data for {query}.",
                "displayLink": "security.example.com"
            }
        ]

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
        try:
            data = resp.json()
            for item in data.get("items", []):
                # Scrape the page content
                page_content = ""
                page_url = item.get("link")
                
                if page_url:
                    try:
                        page_resp = safe_get(page_url)
                        if page_resp:
                            soup = BeautifulSoup(page_resp.text, "html.parser")
                            
                            # Remove script, style, and noscript tags
                            for tag in soup(["script", "style", "noscript", "iframe"]):
                                tag.decompose()
                            
                            # Extract clean text
                            page_content = " ".join(soup.stripped_strings)[:500]  # First 500 chars
                        else:
                            # Fallback to snippet if scraping fails
                            page_content = item.get("snippet", "")
                    except Exception as scrape_error:
                        LOGGER.debug("Content scraping failed for %s: %s", page_url, scrape_error)
                        page_content = item.get("snippet", "")
                
                results.append({
                    "title": item.get("title", "No title"),
                    "url": page_url or "#",
                    "snippet": item.get("snippet", ""),
                    "content": page_content,
                    "displayLink": item.get("displayLink", "")
                })
                
                time.sleep(0.5)  # Rate limiting
        except ValueError as json_error:
            LOGGER.error("Failed to parse Google CSE response: %s", json_error)
    else:
        LOGGER.warning("No response from Google CSE API")
    
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