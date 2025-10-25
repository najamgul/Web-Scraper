#!/usr/bin/env python3
"""Test Shodan API key and connection"""

import os
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

print("=" * 80)
print("🔍 SHODAN API TEST")
print("=" * 80)

# Check if API key is loaded
print(f"\n1. API Key Status:")
if SHODAN_API_KEY:
    print(f"   ✅ SHODAN_API_KEY loaded: {SHODAN_API_KEY[:10]}...{SHODAN_API_KEY[-4:]}")
else:
    print(f"   ❌ SHODAN_API_KEY is NOT loaded from .env")
    print(f"   Please check your .env file exists and contains SHODAN_API_KEY")
    exit(1)

# Test API key with a simple query
print(f"\n2. Testing API Key with IP: 8.8.8.8")
try:
    url = f"https://api.shodan.io/shodan/host/8.8.8.8"
    params = {"key": SHODAN_API_KEY}
    
    print(f"   Request: GET {url}")
    print(f"   API Key: {SHODAN_API_KEY[:10]}...")
    
    response = requests.get(url, params=params, timeout=10)
    
    print(f"\n3. Response:")
    print(f"   Status Code: {response.status_code}")
    print(f"   Status Text: {response.reason}")
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n   ✅ SUCCESS! Shodan API is working!")
        print(f"   IP: {data.get('ip_str', 'N/A')}")
        print(f"   Organization: {data.get('org', 'N/A')}")
        print(f"   ISP: {data.get('isp', 'N/A')}")
        print(f"   Country: {data.get('country_name', 'N/A')}")
        print(f"   Open Ports: {len(data.get('ports', []))} ports")
        print(f"   Ports: {data.get('ports', [])}")
        
    elif response.status_code == 401:
        print(f"\n   ❌ ERROR: 401 Unauthorized")
        print(f"   Your API key is invalid or has been revoked")
        print(f"   Get a new key at: https://account.shodan.io/")
        
    elif response.status_code == 403:
        print(f"\n   ❌ ERROR: 403 Forbidden")
        print(f"   Response: {response.text}")
        print(f"\n   Possible reasons:")
        print(f"   - API key is invalid")
        print(f"   - API key has expired")
        print(f"   - Rate limit exceeded (free tier: 100 queries/month)")
        print(f"   - IP address is not found in Shodan database")
        print(f"\n   Solutions:")
        print(f"   1. Check your API key at: https://account.shodan.io/")
        print(f"   2. Verify your account is active")
        print(f"   3. Check rate limit usage")
        
    elif response.status_code == 429:
        print(f"\n   ❌ ERROR: 429 Too Many Requests")
        print(f"   You've exceeded the rate limit")
        print(f"   Free tier: 100 queries per month")
        
    else:
        print(f"\n   ❌ ERROR: Unexpected status code")
        print(f"   Response: {response.text}")
        
except Exception as e:
    print(f"\n   ❌ EXCEPTION: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 80)
