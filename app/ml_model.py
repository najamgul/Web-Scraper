# app/ml_model.py
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
    
    ✅ IMPROVED: Better handling of missing data
    """
    try:
        vt_data = vt_data or {}
        shodan_data = shodan_data or {}
        otx_data = otx_data or {}

        logger.info(f"\n{'='*80}")
        logger.info(f"🔍 CLASSIFICATION DEBUG for {ioc_type}: {user_input}")
        logger.info(f"{'='*80}")
        logger.info(f"VT Data Keys: {list(vt_data.keys())}")
        logger.info(f"Shodan Data Keys: {list(shodan_data.keys())}")
        logger.info(f"OTX Data Keys: {list(otx_data.keys())}")
        
        # ============================================
        # FOR KEYWORDS: Use OTX or fallback to Informational
        # ============================================
        if ioc_type == "keyword":
            # ✅ Check if OTX has valid data
            if otx_data and 'classification' in otx_data and otx_data.get('classification') != 'Unknown':
                classification = otx_data.get('classification', 'Informational')
                logger.info(f"✅ Keyword '{user_input}' classified as '{classification}' based on OTX")
                return classification
            
            # ✅ Check if OTX has error or empty data
            if 'error' in otx_data or not otx_data or otx_data.get('source_count', 0) == 0:
                logger.info(f"⚠️  No OTX data for keyword '{user_input}', defaulting to Informational")
                return "Informational"  # ← Changed from "Unknown"
            
            # ✅ Fallback: Use OTX threat score
            threat_score = otx_data.get('threat_score', 0)
            if threat_score >= 70:
                classification = "Malicious"
            elif threat_score >= 40:
                classification = "Suspicious"
            elif threat_score > 0:
                classification = "Informational"
            else:
                classification = "Informational"  # ← Changed from "Unknown"
            
            logger.info(f"✅ Keyword classified as '{classification}' (OTX score: {threat_score})")
            return classification

        # ============================================
        # FOR OTHER IOC TYPES: Use Random Forest
        # ============================================
        
        # Extract VirusTotal features
        vt_malicious = 0
        vt_suspicious = 0
        
        if "error" not in vt_data:
            stats = vt_data.get("last_analysis_stats", {})
            if not stats:
                stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            vt_malicious = stats.get("malicious", 0)
            vt_suspicious = stats.get("suspicious", 0)
        
        logger.info(f"📊 VT Stats: Malicious={vt_malicious}, Suspicious={vt_suspicious}")

        # Extract Shodan features
        port_count = 0
        vuln_count = 0
        
        if "error" not in shodan_data:
            ports = shodan_data.get("ports", [])
            if isinstance(ports, list):
                port_count = len(ports)
            
            vulns = shodan_data.get("vulns", [])
            if isinstance(vulns, dict):
                vuln_count = len(vulns.keys())
            elif isinstance(vulns, list):
                vuln_count = len(vulns)
        
        logger.info(f"📊 Shodan Stats: Ports={port_count}, Vulns={vuln_count}")

        # Extract OTX features
        otx_threat_score = 0
        is_otx_malicious = 0
        
        if "error" not in otx_data:
            otx_threat_score = otx_data.get("threat_score", 0)
            otx_classification = otx_data.get("classification", "").lower()
            is_otx_malicious = 1 if otx_classification in ["malicious", "suspicious"] else 0
        
        logger.info(f"📊 OTX Stats: ThreatScore={otx_threat_score}, IsMalicious={is_otx_malicious}")

        # Feature vector
        features = [
            int(vt_malicious),
            int(vt_suspicious),
            int(port_count),
            int(vuln_count),
            int(otx_threat_score),
            int(is_otx_malicious)
        ]
        
        logger.info(f"🔢 Feature Vector: {features}")

        # ✅ IMPROVED: Better handling when all features are zero
        if all(f == 0 for f in features):
            logger.warning(f"⚠️  ALL FEATURES ARE ZERO")
            
            # Check if APIs actually returned data or just errors
            has_vt_data = vt_data and "error" not in vt_data and vt_data.get("last_analysis_stats")
            has_shodan_data = shodan_data and "error" not in shodan_data
            has_otx_data = otx_data and "error" not in otx_data
            
            if has_vt_data or has_shodan_data or has_otx_data:
                # APIs returned data but it's all clean
                logger.info(f"✅ APIs returned clean data - classifying as Benign")
                return "Benign"
            else:
                # APIs didn't return useful data
                logger.warning(f"⚠️  No useful API data - classifying as Informational")
                return "Informational"  # ← Changed from "Unknown"

        # Use Random Forest model
        if model is not None:
            try:
                prediction = model.predict([features])[0]
                proba = model.predict_proba([features])[0]
                classification = "Malicious" if int(prediction) == 1 else "Benign"
                
                logger.info(f"🤖 Model Prediction: {classification}")
                logger.info(f"   Confidence: Benign={proba[0]:.2%}, Malicious={proba[1]:.2%}")
                logger.info(f"{'='*80}\n")
                
                return classification
            except Exception as e:
                logger.error(f"❌ Model prediction error: {e}")

        # Fallback: Rule-based classification
        result = rule_based_classification(features, ioc_type)
        logger.info(f"📋 Rule-Based Result: {result}")
        logger.info(f"{'='*80}\n")
        return result

    except Exception as e:
        logger.error(f"❌ Classification error for '{user_input}': {e}", exc_info=True)
        return "Informational"  # ← Changed from "Unknown"


def rule_based_classification(features, ioc_type):
    """Rule-based fallback classification"""
    vt_malicious, vt_suspicious, port_count, vuln_count, otx_score, is_otx_malicious = features
    
    logger.info(f"📋 Applying rule-based classification...")
    
    score = 0
    
    # VirusTotal weight
    if vt_malicious >= 5:
        score += 40
        logger.info(f"   +40 points: VT malicious >= 5 ({vt_malicious})")
    elif vt_malicious >= 2:
        score += 20
        logger.info(f"   +20 points: VT malicious >= 2 ({vt_malicious})")
    elif vt_malicious > 0:
        score += 10
        logger.info(f"   +10 points: VT malicious > 0 ({vt_malicious})")
    
    # Shodan weight (only for IPs)
    if ioc_type == "ip":
        if vuln_count >= 10:
            score += 30
            logger.info(f"   +30 points: Vulns >= 10 ({vuln_count})")
        elif vuln_count >= 5:
            score += 20
            logger.info(f"   +20 points: Vulns >= 5 ({vuln_count})")
        elif vuln_count > 0:
            score += 10
            logger.info(f"   +10 points: Vulns > 0 ({vuln_count})")
    
    # OTX weight
    if otx_score >= 70 or is_otx_malicious:
        score += 30
        logger.info(f"   +30 points: OTX score >= 70 or is_malicious")
    elif otx_score >= 40:
        score += 20
        logger.info(f"   +20 points: OTX score >= 40 ({otx_score})")
    
    logger.info(f"   Total Score: {score}/100")
    
    # Classify
    if score >= 60:
        return "Malicious"
    elif score >= 20:  # ← Lowered threshold
        return "Suspicious"
    elif score > 0:
        return "Informational"
    else:
        return "Benign"


# ... rest of your ml_model.py code (train_model_if_needed, etc.) ...

def train_model_if_needed():
    """Train model if not found"""
    global model
    
    if model is not None:
        return
    
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, classification_report
    
    logger.info("🔨 Training new Random Forest model...")
    
    # ✅ IMPROVED Training data with more samples
    # [vt_malicious, vt_suspicious, ports, vulns, otx_score, otx_is_malicious]
    
    # MALICIOUS samples (25 examples)
    X_malicious = np.array([
        [15, 5, 20, 20, 85, 1],
        [12, 3, 15, 15, 90, 1],
        [20, 8, 18, 25, 88, 1],
        [18, 6, 22, 30, 92, 1],
        [10, 4, 12, 18, 75, 1],
        [25, 10, 25, 35, 95, 1],
        [8, 2, 10, 12, 70, 1],
        [30, 12, 30, 40, 98, 1],
        [14, 5, 16, 20, 80, 1],
        [22, 9, 20, 28, 85, 1],
        [16, 7, 14, 22, 82, 1],
        [11, 4, 11, 15, 72, 1],
        [19, 8, 19, 26, 87, 1],
        [13, 5, 13, 17, 78, 1],
        [17, 6, 17, 24, 84, 1],
        [21, 9, 21, 29, 89, 1],
        [9, 3, 9, 13, 68, 1],
        [24, 10, 24, 33, 91, 1],
        [15, 6, 15, 21, 81, 1],
        [12, 4, 12, 16, 74, 1],
        [7, 2, 8, 10, 65, 1],
        [28, 11, 28, 38, 94, 1],
        [10, 3, 10, 14, 71, 1],
        [23, 9, 23, 31, 90, 1],
        [14, 5, 14, 19, 77, 1],
    ])
    
    # BENIGN samples (25 examples)
    X_benign = np.array([
        [0, 0, 0, 0, 0, 0],      # Completely clean
        [0, 1, 2, 0, 5, 0],      # Mostly clean
        [1, 0, 5, 1, 3, 0],      # Few detections
        [0, 0, 3, 0, 0, 0],      # Few ports
        [0, 1, 8, 2, 8, 0],      # Some activity
        [2, 1, 4, 0, 10, 0],     # Low detections
        [1, 2, 6, 1, 12, 0],     # Border case benign
        [0, 0, 10, 0, 5, 0],     # Many ports, no threats
        [1, 1, 3, 0, 7, 0],      # Minimal
        [0, 0, 2, 0, 3, 0],      # Clean
        [0, 0, 0, 0, 0, 0],      # Clean duplicate
        [1, 0, 1, 0, 2, 0],      # Minimal
        [0, 1, 4, 0, 6, 0],      # Low risk
        [2, 0, 7, 1, 9, 0],      # Borderline
        [0, 0, 5, 0, 4, 0],      # Clean with ports
        [1, 1, 2, 0, 5, 0],      # Low detections
        [0, 0, 0, 0, 1, 0],      # Nearly clean
        [0, 2, 3, 0, 8, 0],      # Few suspicious
        [1, 0, 6, 0, 5, 0],      # Low threat
        [0, 0, 1, 0, 0, 0],      # Clean
        [0, 0, 4, 0, 2, 0],      # Few ports
        [1, 1, 1, 0, 4, 0],      # Very low
        [0, 0, 7, 1, 6, 0],      # Some activity
        [2, 1, 3, 0, 8, 0],      # Low risk
        [0, 1, 5, 0, 3, 0],      # Clean-ish
    ])
    
    X = np.vstack([X_malicious, X_benign])
    y = np.array([1] * len(X_malicious) + [0] * len(X_benign))
    
    # ✅ Train with balanced class weights
    model = RandomForestClassifier(
        n_estimators=100, 
        max_depth=10, 
        random_state=42,
        class_weight='balanced'
    )
    model.fit(X, y)
    
    # ✅ Evaluate model
    predictions = model.predict(X)
    accuracy = accuracy_score(y, predictions)
    
    logger.info(f"✅ Model training accuracy: {accuracy:.2%}")
    logger.info(f"\n{classification_report(y, predictions, target_names=['Benign', 'Malicious'])}")
    
    # ✅ Test with known cases
    logger.info("\n🧪 Testing model with known cases:")
    test_cases = [
        ([0, 0, 0, 0, 0, 0], "Benign"),      # All zeros should be Benign
        ([15, 5, 20, 20, 85, 1], "Malicious"),  # High values should be Malicious
        ([1, 1, 3, 0, 5, 0], "Benign"),      # Low values should be Benign
    ]
    
    for features, expected in test_cases:
        pred = model.predict([features])[0]
        result = "Malicious" if pred == 1 else "Benign"
        status = "✅" if result == expected else "❌"
        logger.info(f"   {status} {features} -> {result} (expected: {expected})")
    
    # ✅ Save model
    try:
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        joblib.dump(model, model_path)
        logger.info(f"💾 Model saved to {model_path}")
    except Exception as e:
        logger.error(f"❌ Failed to save model: {e}")


# Train model if needed
if model is None:
    train_model_if_needed()