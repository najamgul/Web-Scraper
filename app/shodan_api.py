import shodan
import os
from dotenv import load_dotenv

load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

def scan_with_shodan(ip):
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        result = api.host(ip)

        return {
            "ip": result.get("ip_str", ""),
            "org": result.get("org", ""),
            "os": result.get("os", ""),
            "ports": result.get("ports", []),
            "vulns": result.get("vulns", [])
        }
    except Exception as e:
        return {"error": str(e)}
