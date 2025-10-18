# ml_model.py
import joblib
import os
import logging
import numpy as np

logger = logging.getLogger(__name__)

# Load the trained Random Forest model
_here = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.abspath(os.path.join(_here, "..", "rf_model.pkl"))

try:
    model = joblib.load(model_path)
    logger.info("Random Forest model loaded successfully")
except FileNotFoundError:
    logger.warning(f"Model file not found at {model_path}. Will create a new one.")
    model = None


def classify_threat(vt_data=None, shodan_data=None, otx_data=None, ioc_type=None, user_input=None):
    """
    Classify threat using reports from VirusTotal, Shodan, and OTX APIs.
    Google CSE data is excluded from classification (used only for display).
    
    For KEYWORDS: Use ONLY OTX classification
    For other IOCs: Use Random Forest with all three APIs
    """
    try:
        vt_data = vt_data or {}
        shodan_data = shodan_data or {}
        otx_data = otx_data or {}

        # ============================================
        # FOR KEYWORDS: Use ONLY OTX classification
        # ============================================
        if ioc_type == "keyword":
            if otx_data and 'classification' in otx_data:
                classification = otx_data.get('classification', 'Unknown')
                logger.info(f"Keyword '{user_input}' classified as '{classification}' based on OTX")
                return classification
            else:
                return "Unknown"

        # ============================================
        # FOR OTHER IOC TYPES: Use Random Forest
        # ============================================
        
        # Extract VirusTotal features
        stats = vt_data.get("last_analysis_stats", {}) if isinstance(vt_data, dict) else {}
        if not stats and isinstance(vt_data, dict):
            # Try nested structure
            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        
        vt_malicious = stats.get("malicious", 0)
        vt_suspicious = stats.get("suspicious", 0)

        # Extract Shodan features
        ports = shodan_data.get("ports", []) if isinstance(shodan_data, dict) else []
        vulns = shodan_data.get("vulns", []) if isinstance(shodan_data, dict) else []
        
        # Also check in data array
        if not ports and "data" in shodan_data:
            ports = [item.get("port") for item in shodan_data.get("data", [])]
        
        port_count = len(ports) if isinstance(ports, list) else 0
        vuln_count = len(vulns) if isinstance(vulns, list) else 0

        # Extract OTX features
        otx_threat_score = otx_data.get("threat_score", 0)
        otx_classification = otx_data.get("classification", "").lower()
        
        # Map OTX classification to binary
        is_otx_malicious = 1 if otx_classification in ["malicious", "suspicious"] else 0

        # Feature vector for model prediction
        # [vt_malicious, vt_suspicious, shodan_ports, shodan_vulns, otx_score, otx_is_malicious]
        features = [
            int(vt_malicious),
            int(vt_suspicious),
            int(port_count),
            int(vuln_count),
            int(otx_threat_score),
            int(is_otx_malicious)
        ]
        
        logger.debug(f"Features for {ioc_type} '{user_input}': {features}")

        # Use Random Forest model if available
        if model is not None:
            try:
                prediction = model.predict([features])[0]
                classification = "Malicious" if int(prediction) == 1 else "Benign"
                logger.info(f"{ioc_type} '{user_input}' classified as '{classification}' by RF model")
                return classification
            except Exception as e:
                logger.error(f"Model prediction error: {e}")
                # Fall through to rule-based

        # Fallback: Rule-based classification
        return rule_based_classification(features, ioc_type)

    except Exception as e:
        logger.error(f"Classification error for '{user_input}': {e}")
        return "Unknown"


def rule_based_classification(features, ioc_type):
    """Rule-based fallback classification"""
    vt_malicious, vt_suspicious, port_count, vuln_count, otx_score, is_otx_malicious = features
    
    # Calculate weighted score
    score = 0
    
    # VirusTotal weight
    if vt_malicious >= 5:
        score += 40
    elif vt_malicious >= 2:
        score += 20
    elif vt_malicious > 0:
        score += 10
    
    # Shodan weight (only for IPs)
    if ioc_type == "ip":
        if vuln_count >= 10:
            score += 30
        elif vuln_count >= 5:
            score += 20
        elif vuln_count > 0:
            score += 10
    
    # OTX weight
    if otx_score >= 70 or is_otx_malicious:
        score += 30
    elif otx_score >= 40:
        score += 20
    
    # Classify
    if score >= 60:
        return "Malicious"
    elif score > 0:
        return "Informational"
    else:
        return "Benign"


def train_model_if_needed():
    """Train model if not found"""
    global model
    
    if model is not None:
        return
    
    from sklearn.ensemble import RandomForestClassifier
    
    logger.info("Training new Random Forest model...")
    
    # Training data: [vt_malicious, vt_suspicious, ports, vulns, otx_score, otx_is_malicious]
    X_malicious = np.array([
        [15, 5, 20, 20, 85, 1],
        [12, 3, 15, 15, 90, 1],
        [20, 8, 18, 25, 88, 1],
        [18, 6, 22, 30, 92, 1],
        [10, 4, 12, 18, 75, 1],
    ])
    
    X_benign = np.array([
        [0, 0, 0, 0, 0, 0],
        [0, 1, 2, 0, 5, 0],
        [1, 0, 5, 1, 3, 0],
        [0, 0, 3, 0, 0, 0],
        [0, 1, 8, 2, 8, 0],
    ])
    
    X = np.vstack([X_malicious, X_benign])
    y = np.array([1] * len(X_malicious) + [0] * len(X_benign))
    
    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    model.fit(X, y)
    
    try:
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        joblib.dump(model, model_path)
        logger.info(f"Model saved to {model_path}")
    except Exception as e:
        logger.error(f"Failed to save model: {e}")


# Train model if needed
if model is None:
    train_model_if_needed()