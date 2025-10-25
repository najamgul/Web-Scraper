# app/ml_model_improved.py
"""
IMPROVED Threat Classification System with Context-Aware ML Model

Features:
- TF-IDF with bigrams for text analysis
- SMOTE for dataset balancing
- Prediction confidence thresholds (0.75)
- Weighted API scoring
- Context filtering for educational/preventive phrases
- Detailed logging of confidence, API scores, and final labels
"""

import joblib
import os
import logging
import numpy as np
import re
from typing import Dict, Tuple, Optional

logger = logging.getLogger(__name__)

# Load models and vectorizer
_here = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(_here, "..", "rf_model_improved.pkl")
vectorizer_path = os.path.join(_here, "..", "tfidf_vectorizer.pkl")

try:
    model = joblib.load(model_path)
    vectorizer = joblib.load(vectorizer_path)
    logger.info("✅ Improved Random Forest model and TF-IDF vectorizer loaded successfully")
except FileNotFoundError:
    logger.warning("⚠️ Model files not found. Will create new ones.")
    model = None
    vectorizer = None


# ============================================
# CONTEXT-AWARE TEXT CLASSIFICATION
# ============================================

# Educational/Preventive patterns that should NOT be marked as malicious
BENIGN_CONTEXT_PATTERNS = [
    r'\b(prevent|avoid|protect|defend|secure|safeguard|guard against)\s+\w*\s*(malware|phishing|ransomware|virus|threat|attack|exploit)',
    r'\b(how to\s+(avoid|prevent|stop|protect)|tips\s+to\s+(avoid|prevent)|security\s+tips)',
    r'\b(awareness|training|education|tutorial|guide|learn|understand)\b',
    r'\b(detect|identify|recognize|spot)\s+\w*\s*(phishing|scam|fraud|malware)',
    r'\b(best practices|security measures|security guidelines|safety tips)',
    r'\b(anti[- ]?(virus|malware|phishing|spam)|security\s+software)',
    r'\b(patch|update|upgrade)\s+\w*\s*(system|software|security)',
]

# Malicious intent patterns (high confidence indicators)
MALICIOUS_PATTERNS = [
    r'\b(download|get|buy|purchase)\s+\w*\s*(malware|ransomware|exploit|backdoor|trojan|keylogger)',
    r'\b(hack|crack|bypass|exploit|breach)\s+(tutorial|guide|tool|method)',
    r'\b(zero[- ]?day|0day)\s+(exploit|vulnerability)',
    r'\b(c2|command\s+and\s+control|botnet|rat\s+tool)',
    r'\b(steal|exfiltrate|dump)\s+\w*\s*(credentials|passwords|data)',
    r'\b(lateral\s+movement|privilege\s+escalation|persistence\s+mechanism)',
]


def analyze_text_context(text: str) -> Dict[str, any]:
    """
    Analyze text for benign (educational) vs malicious context
    
    Returns:
        dict with 'is_benign_context', 'is_malicious_context', and 'confidence'
    """
    if not text:
        return {'is_benign_context': False, 'is_malicious_context': False, 'confidence': 0.0}
    
    text_lower = text.lower()
    
    # Check for benign educational context
    benign_matches = 0
    for pattern in BENIGN_CONTEXT_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            benign_matches += 1
    
    # Check for malicious intent
    malicious_matches = 0
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            malicious_matches += 1
    
    # Calculate confidence
    total_matches = benign_matches + malicious_matches
    benign_confidence = benign_matches / max(total_matches, 1)
    malicious_confidence = malicious_matches / max(total_matches, 1)
    
    return {
        'is_benign_context': benign_matches > malicious_matches,
        'is_malicious_context': malicious_matches > benign_matches,
        'benign_score': benign_matches,
        'malicious_score': malicious_matches,
        'confidence': max(benign_confidence, malicious_confidence)
    }


# ============================================
# WEIGHTED API SCORING
# ============================================

def calculate_weighted_api_score(vt_data: Dict, shodan_data: Dict, otx_data: Dict,
                                 abuseipdb_data: Optional[Dict],
                                 ioc_type: str) -> Dict[str, float]:
    """
    Calculate weighted threat score from multiple APIs
    
    Weights:
    - VirusTotal: 40% (most reliable for files/URLs/domains)
    - OTX: 35% (community intelligence)
    - Shodan: 25% (infrastructure/IP specific)
    
    Returns:
        dict with individual scores and weighted total
    """
    scores = {
        'vt_score': 0.0,
        'otx_score': 0.0,
        'shodan_score': 0.0,
        'abuseipdb_score': 0.0,
        'weighted_total': 0.0,
        'details': {}
    }
    
    # VirusTotal Score (0-100)
    if vt_data and 'error' not in vt_data and not vt_data.get('timeout'):
        stats = vt_data.get('last_analysis_stats', {}) or vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        if stats:
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            
            if total > 0:
                # Score based on percentage of engines flagging it
                vt_score = ((malicious + suspicious * 0.5) / total) * 100
                scores['vt_score'] = min(vt_score, 100)
                scores['details']['vt_malicious'] = malicious
                scores['details']['vt_suspicious'] = suspicious
                scores['details']['vt_total_engines'] = total
    
    # OTX Score (already 0-100)
    if otx_data and 'error' not in otx_data and not otx_data.get('timeout'):
        otx_threat_score = otx_data.get('threat_score', 0)
        scores['otx_score'] = min(otx_threat_score, 100)
        scores['details']['otx_pulses'] = otx_data.get('source_count', 0)
        scores['details']['otx_classification'] = otx_data.get('classification', 'Unknown')
    
    # Shodan Score (0-100, only for IPs)
    if ioc_type == 'ip' and shodan_data and 'error' not in shodan_data and not shodan_data.get('timeout'):
        ports = shodan_data.get('ports', [])
        vulns = shodan_data.get('vulns', [])
        
        port_count = len(ports) if isinstance(ports, list) else 0
        vuln_count = len(vulns) if isinstance(vulns, (list, dict)) else 0
        
        # Score based on vulnerabilities and open ports
        shodan_score = 0
        if vuln_count > 10:
            shodan_score += 50
        elif vuln_count > 5:
            shodan_score += 30
        elif vuln_count > 0:
            shodan_score += 15
        
        if port_count > 20:
            shodan_score += 20
        elif port_count > 10:
            shodan_score += 10
        
        # Check for suspicious tags
        tags = shodan_data.get('tags', [])
        suspicious_tags = ['malware', 'botnet', 'compromised', 'honeypot']
        if any(tag in suspicious_tags for tag in tags):
            shodan_score += 30
        
        scores['shodan_score'] = min(shodan_score, 100)
        scores['details']['shodan_ports'] = port_count
        scores['details']['shodan_vulns'] = vuln_count

    # AbuseIPDB Score (confidence already 0-100, IPs only)
    if ioc_type == 'ip' and abuseipdb_data and 'error' not in abuseipdb_data and not abuseipdb_data.get('network_issue'):
        abuse_confidence = abuseipdb_data.get('abuse_confidence_score', 0) or abuseipdb_data.get('threat_score', 0)
        scores['abuseipdb_score'] = min(max(abuse_confidence, 0), 100)
        scores['details']['abuseipdb_confidence'] = abuseipdb_data.get('abuse_confidence_score', 0)
        scores['details']['abuseipdb_reports'] = abuseipdb_data.get('total_reports', 0)
        scores['details']['abuseipdb_whitelisted'] = abuseipdb_data.get('is_whitelisted', False)
    
    # Calculate weighted total
    # Default weights (non-IP)
    weights = {'vt': 0.55, 'otx': 0.45, 'shodan': 0.0, 'abuseipdb': 0.0}
    
    if ioc_type == 'ip':
        # VirusTotal: 30%, OTX: 25%, Shodan: 20%, AbuseIPDB: 25%
        weights = {'vt': 0.30, 'otx': 0.25, 'shodan': 0.20, 'abuseipdb': 0.25}
    
    scores['weighted_total'] = (
        scores['vt_score'] * weights['vt'] +
        scores['otx_score'] * weights['otx'] +
        scores['shodan_score'] * weights['shodan'] +
        scores['abuseipdb_score'] * weights['abuseipdb']
    )
    
    scores['weights_used'] = weights
    
    return scores


# ============================================
# MAIN CLASSIFICATION FUNCTION
# ============================================

def classify_threat_improved(vt_data=None, shodan_data=None, otx_data=None,
                            abuseipdb_data=None, ioc_type=None, user_input=None, google_data=None) -> Tuple[str, Dict]:
    """
    Enhanced threat classification with context awareness and confidence scoring
    
    Returns:
        tuple: (classification, details_dict)
        where details_dict contains confidence, API scores, and reasoning
    """
    vt_data = vt_data or {}
    shodan_data = shodan_data or {}
    otx_data = otx_data or {}
    abuseipdb_data = abuseipdb_data or {}
    
    logger.info(f"\n{'='*80}")
    logger.info(f"🔍 IMPROVED CLASSIFICATION for {ioc_type}: {user_input}")
    logger.info(f"{'='*80}")
    
    # Initialize result details
    result_details = {
        'model_confidence': 0.0,
        'api_scores': {},
        'context_analysis': {},
        'final_classification': 'Unknown',
        'reasoning': [],
        'confidence_threshold_met': False
    }
    
    try:
        # ============================================
        # KEYWORD-SPECIFIC LOGIC WITH CONTEXT AWARENESS
        # ============================================
        if ioc_type == "keyword":
            logger.info(f"📝 Processing keyword with context awareness: {user_input}")
            
            # Analyze text context
            context = analyze_text_context(user_input)
            result_details['context_analysis'] = context
            
            logger.info(f"🧠 Context Analysis:")
            logger.info(f"   Benign patterns: {context['benign_score']}")
            logger.info(f"   Malicious patterns: {context['malicious_score']}")
            logger.info(f"   Context confidence: {context['confidence']:.2%}")
            
            # If strong benign context detected, override
            if context['is_benign_context'] and context['confidence'] >= 0.7:
                result_details['final_classification'] = 'Benign'
                result_details['reasoning'].append(f"Educational/preventive context detected (confidence: {context['confidence']:.2%})")
                result_details['confidence_threshold_met'] = True
                
                logger.info(f"✅ BENIGN CONTEXT OVERRIDE: '{user_input}' is educational/preventive")
                logger.info(f"📊 Result Details: {result_details}")
                logger.info(f"{'='*80}\n")
                return 'Benign', result_details
            
            # Calculate weighted API score
            api_scores = calculate_weighted_api_score(vt_data, shodan_data, otx_data, abuseipdb_data, ioc_type)
            result_details['api_scores'] = api_scores
            
            weighted_score = api_scores['weighted_total']
            logger.info(f"📊 Weighted API Score: {weighted_score:.1f}/100")
            logger.info(f"   VT: {api_scores['vt_score']:.1f}, OTX: {api_scores['otx_score']:.1f}, Shodan: {api_scores['shodan_score']:.1f}, AbuseIPDB: {api_scores['abuseipdb_score']:.1f}")
            
            # Use TF-IDF + ML model for keywords if available
            if model is not None and vectorizer is not None:
                try:
                    # Transform text using TF-IDF
                    X_text = vectorizer.transform([user_input])
                    
                    # Get prediction probabilities
                    proba = model.predict_proba(X_text)[0]
                    benign_conf = proba[0]
                    malicious_conf = proba[1]
                    
                    result_details['model_confidence'] = max(benign_conf, malicious_conf)
                    
                    logger.info(f"🤖 ML Model Prediction:")
                    logger.info(f"   Benign: {benign_conf:.2%}, Malicious: {malicious_conf:.2%}")
                    
                    # Combine ML confidence with API score
                    # If model is confident (>0.75) and agrees with API score, use it
                    if result_details['model_confidence'] >= 0.75:
                        result_details['confidence_threshold_met'] = True
                        
                        if malicious_conf > benign_conf:
                            # Model says malicious
                            if weighted_score >= 40 or context['is_malicious_context']:
                                classification = 'Malicious'
                                result_details['reasoning'].append(f"ML model confident ({malicious_conf:.2%}) + API score {weighted_score:.1f}")
                            else:
                                classification = 'Suspicious'
                                result_details['reasoning'].append(f"ML model suggests malicious but low API score")
                        else:
                            # Model says benign
                            if weighted_score < 30 and not context['is_malicious_context']:
                                classification = 'Benign'
                                result_details['reasoning'].append(f"ML model confident ({benign_conf:.2%}) + low API score")
                            else:
                                classification = 'Informational'
                                result_details['reasoning'].append(f"ML model says benign but API shows activity")
                    else:
                        # Model not confident enough, rely more on API scores
                        result_details['confidence_threshold_met'] = False
                        classification = classify_by_weighted_score(weighted_score, context['is_malicious_context'])
                        result_details['reasoning'].append(f"ML confidence below threshold, using weighted API score: {weighted_score:.1f}")
                    
                    result_details['final_classification'] = classification
                    
                except Exception as e:
                    logger.error(f"❌ ML model error: {e}")
                    classification = classify_by_weighted_score(weighted_score, context['is_malicious_context'])
                    result_details['final_classification'] = classification
                    result_details['reasoning'].append(f"ML error, fallback to API score: {weighted_score:.1f}")
            else:
                # No ML model, use weighted API score
                classification = classify_by_weighted_score(weighted_score, context['is_malicious_context'])
                result_details['final_classification'] = classification
                result_details['reasoning'].append(f"No ML model, using weighted API score: {weighted_score:.1f}")
            
            logger.info(f"✅ Final Classification: {classification}")
            logger.info(f"📊 Result Details: {result_details}")
            logger.info(f"{'='*80}\n")
            return classification, result_details
        
        # ============================================
        # IP/DOMAIN/URL CLASSIFICATION
        # ============================================
        
        # Calculate weighted API scores
        api_scores = calculate_weighted_api_score(vt_data, shodan_data, otx_data, abuseipdb_data, ioc_type)
        result_details['api_scores'] = api_scores
        
        weighted_score = api_scores['weighted_total']
        logger.info(f"📊 Weighted API Score: {weighted_score:.1f}/100")
        logger.info(f"   VT: {api_scores['vt_score']:.1f}, OTX: {api_scores['otx_score']:.1f}, Shodan: {api_scores['shodan_score']:.1f}, AbuseIPDB: {api_scores['abuseipdb_score']:.1f}")

        abuse_confidence = abuseipdb_data.get('abuse_confidence_score', abuseipdb_data.get('threat_score', 0)) or 0
        abuse_reports = abuseipdb_data.get('total_reports', 0)
        abuse_whitelisted = abuseipdb_data.get('is_whitelisted', False)
        result_details['api_scores']['abuseipdb_details'] = {
            'confidence': abuse_confidence,
            'reports': abuse_reports,
            'whitelisted': abuse_whitelisted
        }
        
        # Extract features for ML model
        features = extract_numeric_features(vt_data, shodan_data, otx_data, ioc_type)
        
        # Use ML model if available
        if model is not None:
            try:
                # Get prediction probabilities
                proba = model.predict_proba([features])[0]
                benign_conf = proba[0]
                malicious_conf = proba[1]
                
                result_details['model_confidence'] = max(benign_conf, malicious_conf)
                
                logger.info(f"🤖 ML Model Prediction:")
                logger.info(f"   Benign: {benign_conf:.2%}, Malicious: {malicious_conf:.2%}")
                logger.info(f"   Features: {features}")
                
                # Apply confidence threshold
                if result_details['model_confidence'] >= 0.75:
                    result_details['confidence_threshold_met'] = True
                    
                    # High confidence prediction
                    if malicious_conf > benign_conf:
                        # Double-check with weighted score
                        if weighted_score >= 50 or abuse_confidence >= 75:
                            classification = 'Malicious'
                            reason = f"High confidence malicious ({malicious_conf:.2%})"
                            if abuse_confidence >= 75:
                                reason += f" + AbuseIPDB {abuse_confidence:.0f}%"
                            reason += f" + API score {weighted_score:.1f}"
                            result_details['reasoning'].append(reason)
                        else:
                            classification = 'Suspicious'
                            result_details['reasoning'].append(f"ML says malicious but moderate API score")
                    else:
                        # Benign prediction
                        if abuse_confidence >= 85 and not abuse_whitelisted:
                            classification = 'Malicious'
                            result_details['reasoning'].append(f"AbuseIPDB confidence {abuse_confidence:.0f}% overrides benign prediction")
                        elif abuse_confidence >= 55 and not abuse_whitelisted:
                            classification = 'Suspicious'
                            result_details['reasoning'].append(f"AbuseIPDB shows elevated risk ({abuse_confidence:.0f}%), overriding benign prediction")
                        elif weighted_score < 25:
                            classification = 'Benign'
                            result_details['reasoning'].append(f"High confidence benign ({benign_conf:.2%}) + low API score")
                        else:
                            classification = 'Informational'
                            result_details['reasoning'].append(f"ML says benign but API shows some activity")
                else:
                    # Low confidence, rely on weighted score
                    result_details['confidence_threshold_met'] = False
                    classification = classify_by_weighted_score(weighted_score, False)
                    result_details['reasoning'].append(f"ML confidence below 0.75, using API score: {weighted_score:.1f}")
                
                result_details['final_classification'] = classification
                
            except Exception as e:
                logger.error(f"❌ ML model error: {e}")
                classification = classify_by_weighted_score(weighted_score, False)
                result_details['final_classification'] = classification
                result_details['reasoning'].append(f"ML error, using API score: {weighted_score:.1f}")
        else:
            # No model available
            classification = classify_by_weighted_score(weighted_score, False)
            result_details['final_classification'] = classification
            result_details['reasoning'].append(f"No ML model, using API score: {weighted_score:.1f}")
        
        if ioc_type == 'ip' and abuse_confidence and not abuse_whitelisted:
            if abuse_confidence >= 90 and classification != 'Malicious':
                classification = 'Malicious'
                result_details['final_classification'] = classification
                result_details['reasoning'].append(f"Forced malicious due to AbuseIPDB confidence {abuse_confidence:.0f}% and {abuse_reports} reports")
            elif abuse_confidence >= 60 and classification in ['Benign', 'Informational']:
                classification = 'Suspicious'
                result_details['final_classification'] = classification
                result_details['reasoning'].append(f"Escalated to Suspicious due to AbuseIPDB confidence {abuse_confidence:.0f}%")

        logger.info(f"✅ Final Classification: {classification}")
        logger.info(f"📊 Result Details: {result_details}")
        logger.info(f"{'='*80}\n")
        return classification, result_details
    
    except Exception as e:
        logger.error(f"❌ Classification error: {e}", exc_info=True)
        result_details['final_classification'] = 'Unknown'
        result_details['reasoning'].append(f"Error: {str(e)}")
        return 'Unknown', result_details


def classify_by_weighted_score(weighted_score: float, has_malicious_context: bool) -> str:
    """
    Classify based on weighted API score
    """
    # Adjust thresholds if malicious context detected
    if has_malicious_context:
        weighted_score += 15  # Boost score if malicious patterns found
    
    if weighted_score >= 70:
        return 'Malicious'
    elif weighted_score >= 45:
        return 'Suspicious'
    elif weighted_score >= 15:
        return 'Informational'
    else:
        return 'Benign'


def extract_numeric_features(vt_data: Dict, shodan_data: Dict, otx_data: Dict, ioc_type: str) -> list:
    """
    Extract numeric features for ML model (same as before for compatibility)
    """
    features = [0, 0, 0, 0, 0, 0]
    
    # VirusTotal features
    if vt_data and 'error' not in vt_data:
        stats = vt_data.get('last_analysis_stats', {}) or vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        if stats:
            features[0] = stats.get('malicious', 0)
            features[1] = stats.get('suspicious', 0)
    
    # Shodan features (IPs only)
    if ioc_type == 'ip' and shodan_data and 'error' not in shodan_data:
        ports = shodan_data.get('ports', [])
        vulns = shodan_data.get('vulns', [])
        features[2] = len(ports) if isinstance(ports, list) else 0
        features[3] = len(vulns) if isinstance(vulns, (list, dict)) else 0
    
    # OTX features
    if otx_data and 'error' not in otx_data:
        features[4] = otx_data.get('threat_score', 0)
        otx_class = otx_data.get('classification', '').lower()
        features[5] = 1 if otx_class in ['malicious', 'suspicious'] else 0
    
    return features


# Export the main function with the old name for compatibility
def classify_threat(vt_data=None, shodan_data=None, otx_data=None,
                   abuseipdb_data=None, ioc_type=None, user_input=None, google_data=None):
    """
    Wrapper function for backward compatibility
    Returns only classification (not details)
    """
    classification, details = classify_threat_improved(
        vt_data, shodan_data, otx_data, abuseipdb_data, ioc_type, user_input, google_data
    )
    
    # Log details for transparency
    logger.info(f"📋 Classification Summary:")
    logger.info(f"   Final Label: {classification}")
    logger.info(f"   Model Confidence: {details.get('model_confidence', 0):.2%}")
    logger.info(f"   Confidence Threshold Met: {details.get('confidence_threshold_met', False)}")
    logger.info(f"   Reasoning: {'; '.join(details.get('reasoning', []))}")
    
    return classification


# This will be called from routes.py for detailed logging
def classify_threat_with_details(vt_data=None, shodan_data=None, otx_data=None,
                                 abuseipdb_data=None, ioc_type=None, user_input=None, google_data=None):
    """
    Returns both classification and detailed information
    """
    return classify_threat_improved(
        vt_data, shodan_data, otx_data, abuseipdb_data, ioc_type, user_input, google_data
    )
