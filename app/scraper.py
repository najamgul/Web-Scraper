import requests
from bs4 import BeautifulSoup
import re
import time
from urllib.parse import quote_plus

def detect_input_type(input_str):
    if re.match(r'^https?://', input_str):
        return "url"
    elif re.match(r'^\d{1,3}(\.\d{1,3}){3}$', input_str):
        return "ip"
    else:
        return "keyword"

def google_dorking(keyword):
    query = f"inurl:{quote_plus(keyword)}"
    search_url = f"https://www.google.com/search?q={query}"
    headers = {'User-Agent': 'Mozilla/5.0'}

    try:
        res = requests.get(search_url, headers=headers)
        soup = BeautifulSoup(res.text, "html.parser")
        links = []
        for a in soup.select("a"):
            href = a.get("href", "")
            if "url?q=" in href:
                clean_url = href.split("url?q=")[-1].split("&")[0]
                links.append(clean_url)
        return links[:5]  # Limit to 5 for performance
    except Exception as e:
        return [f"Google Dork failed: {e}"]

def scrape_url(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        res = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
        text = soup.get_text(strip=True)
        return text[:1000]  # Limit characters
    except Exception as e:
        return f"Error scraping {url}: {e}"
