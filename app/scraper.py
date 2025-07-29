import requests
from bs4 import BeautifulSoup
import re
import time
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')
SEARCH_ENGINE_ID = os.getenv('SEARCH_ENGINE_ID')

def detect_input_type(input_str):
    if re.match(r'^https?://', input_str):
        return "url"
    elif re.match(r'^\d{1,3}(\.\d{1,3}){3}$', input_str):
        return "ip"
    elif re.match(r'^[a-fA-F0-9]{32}$', input_str):  # MD5
        return "hash"
    elif re.match(r'^[a-fA-F0-9]{64}$', input_str):  # SHA256
        return "hash"
    else:
        return "keyword"

def google_search_api(keyword):
    """Use Google's Custom Search JSON API"""
    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        'key': "AIzaSyBkSMYZljMx5z47ISQe3uXbwr4ljkqbV7I",
        'cx': "e7179e673eff145e2",
        'q': keyword,
        'num': 5  # Get 5 results
    }
    
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        results = response.json()
        
        links = []
        if 'items' in results:
            for item in results['items']:
                links.append(item['link'])
        return links
    except Exception as e:
        print(f"Google API error: {e}")
        return []

def scrape_url(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        res = requests.get(url, headers=headers, timeout=8)
        res.raise_for_status()
        
        soup = BeautifulSoup(res.text, "html.parser")
        
        # Remove unwanted tags
        for element in soup(["script", "style", "header", "footer", "nav", "aside"]):
            element.decompose()
            
        text = soup.get_text()
        # Clean up whitespace
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = '\n'.join(chunk for chunk in chunks if chunk)
        
        return text[:2000]  # Return more text
    except Exception as e:
        print(f"Scraping error for {url}: {e}")
        return None