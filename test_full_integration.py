#!/usr/bin/env python3
"""Test IP classification with the app"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables FIRST
load_dotenv()

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 80)
print("🧪 TESTING IP CLASSIFICATION & SHODAN API")
print("=" * 80)

# Test 1: Check environment variable
print("\n1. Environment Variable Check:")
shodan_key = os.getenv("SHODAN_API_KEY")
if shodan_key:
    print(f"   ✅ SHODAN_API_KEY: {shodan_key[:10]}...{shodan_key[-4:]}")
else:
    print(f"   ❌ SHODAN_API_KEY not found")

# Test 2: Import and check module
print("\n2. Importing app modules...")
try:
    from app.vt_shodan_api import SHODAN_API_KEY, shodan_lookup
    print(f"   ✅ Module imported successfully")
    print(f"   Module's SHODAN_API_KEY: {SHODAN_API_KEY[:10] + '...' if SHODAN_API_KEY else 'None'}")
except Exception as e:
    print(f"   ❌ Import failed: {e}")
    sys.exit(1)

# Test 3: Call shodan_lookup
print("\n3. Testing shodan_lookup function with IP: 8.8.8.8")
try:
    result = shodan_lookup("8.8.8.8")
    print(f"   Result keys: {list(result.keys())}")
    
    if 'error' in result:
        print(f"   ❌ ERROR: {result['error']}")
        print(f"   Full result: {result}")
    else:
        print(f"   ✅ SUCCESS!")
        print(f"   IP: {result.get('ip_str', result.get('ip', 'N/A'))}")
        print(f"   Organization: {result.get('org', 'N/A')}")
        print(f"   ISP: {result.get('isp', 'N/A')}")
        print(f"   Classification: {result.get('classification', 'N/A')}")
        print(f"   Threat Score: {result.get('threat_score', 'N/A')}")
        print(f"   Open Ports: {len(result.get('ports', []))}")
except Exception as e:
    print(f"   ❌ EXCEPTION: {e}")
    import traceback
    traceback.print_exc()

# Test 4: Test orchestrator
print("\n4. Testing Orchestrator Integration:")
try:
    from app.orchestrator import search_shodan
    result = search_shodan("8.8.8.8", "ip")
    
    if 'error' in result:
        print(f"   ❌ ERROR: {result['error']}")
    else:
        print(f"   ✅ Orchestrator SUCCESS!")
        print(f"   Classification: {result.get('classification', 'N/A')}")
        print(f"   Threat Score: {result.get('threat_score', 'N/A')}")
except Exception as e:
    print(f"   ❌ EXCEPTION: {e}")
    import traceback
    traceback.print_exc()

# Test 5: Test full orchestration
print("\n5. Testing Full Orchestration Pipeline:")
try:
    from app.orchestrator import orchestrate_threat_intelligence
    result = orchestrate_threat_intelligence("8.8.8.8")
    
    print(f"   Input Type: {result.get('input_type', 'N/A')}")
    print(f"   Classification: {result.get('classification', 'N/A')}")
    
    shodan_data = result.get('shodan_data', {})
    if 'error' in shodan_data:
        print(f"   ❌ Shodan Error: {shodan_data['error']}")
    else:
        print(f"   ✅ Shodan Data Present: {bool(shodan_data)}")
        print(f"   Shodan Org: {shodan_data.get('org', 'N/A')}")
        
except Exception as e:
    print(f"   ❌ EXCEPTION: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 80)
print("✅ Test Complete!")
print("\nIf you see errors above, RESTART your Flask server:")
print("  1. Press Ctrl+C in the Flask terminal")
print("  2. Run: .\\venv\\Scripts\\python.exe run.py")
print("=" * 80)
