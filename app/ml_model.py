import joblib
import os

# Load the trained Random Forest model
_here = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.abspath(os.path.join(_here, "..", "rf_model.pkl"))
model = joblib.load(model_path)


def classify_threat(vt_data=None, shodan_data=None, scraped_data=None, ioc_type=None, user_input=None):
    try:
        # --- Special handling for keyword inputs ---
        if ioc_type == "keyword":
            keyword_terms = [
                "breach", "hack", "phishing", "exploit", "malware", "ransomware",
                "trojan", "botnet", "zero-day", "sql injection", "xss",
                "vulnerability", "leak", "attack", "rootkit", "ddos", "keylogger"
            ]

            # Always check the raw keyword itself
            if user_input and any(term in user_input.lower() for term in keyword_terms):
                return "Malicious"

            # If scraped pages exist, check their content too
            if scraped_data and isinstance(scraped_data, list):
                first_page = scraped_data[0] if scraped_data else {}
                content = (first_page.get("content") or "").lower()
                if any(term in content for term in keyword_terms):
                    return "Malicious"

            # If nothing matched, treat it as Informational
            return "Informational"

        # --- Default classification for IP / URL / Domain ---
        vt_data = vt_data or {}
        shodan_data = shodan_data or {}

        stats = vt_data.get("last_analysis_stats", {}) if isinstance(vt_data, dict) else {}
        ports = shodan_data.get("ports", []) if isinstance(shodan_data, dict) else []
        vulns = shodan_data.get("vulns", []) if isinstance(shodan_data, dict) else []

        features = [
            stats.get("malicious", 0),
            stats.get("suspicious", 0),
            len(ports) if isinstance(ports, list) else 0,
            len(vulns) if isinstance(vulns, list) else 0
        ]

        prediction = model.predict([features])[0]
        return "Malicious" if int(prediction) == 1 else "Benign"

    except Exception as e:
        print("Classification error:", e)
        return "Unknown"
