import requests
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

def scan_with_virustotal(input_data):
    url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        # Submit the URL to VirusTotal
        scan_resp = requests.post(url, headers=headers, data={"url": input_data})
        scan_resp.raise_for_status()
        scan_id = scan_resp.json()["data"]["id"]

        # Retrieve analysis report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        report_resp = requests.get(report_url, headers=headers)
        report_resp.raise_for_status()
        data = report_resp.json()["data"]["attributes"]

        return {
            "positives": data.get("stats", {}).get("malicious", 0),
            "suspicious": data.get("stats", {}).get("suspicious", 0),
            "categories": data.get("results", {})
        }
    except Exception as e:
        return {"error": str(e)}
