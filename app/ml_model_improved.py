# app/ml_model_improved.py
"""
IMPROVED Threat Classification System with Multi-Model ML Pipeline

Features:
- Dedicated ML models for each IOC type (keyword, URL, IP, domain, hash)
- TF-IDF + Random Forest for keyword classification
- XGBoost with lexical/structural/API features for URL/IP/domain/hash
- Prediction confidence thresholds (0.75)
- Weighted API scoring as fallback
- Context filtering for educational/preventive phrases
- Detailed logging of confidence, API scores, and final labels
"""

import joblib
import os
import math
import logging
import numpy as np
import re
from collections import Counter
from typing import Dict, Tuple, Optional

logger = logging.getLogger(__name__)


_here = os.path.dirname(os.path.abspath(__file__))
_models_dir = os.path.join(_here, "..", "models")

def _load_model(name, fallback_path=None):
    """Load a model from the models/ directory with optional fallback."""
    path = os.path.join(_models_dir, name)
    if os.path.exists(path):
        return joblib.load(path)
    if fallback_path and os.path.exists(fallback_path):
        return joblib.load(fallback_path)
    return None

# Keyword model (TF-IDF + Random Forest)
model = _load_model("keyword_model.pkl", os.path.join(_here, "..", "rf_model_improved.pkl"))
vectorizer = _load_model("keyword_vectorizer.pkl", os.path.join(_here, "..", "tfidf_vectorizer.pkl"))

# URL model (Lexical features + XGBoost)
url_model = _load_model("url_model.pkl")
url_scaler = _load_model("url_scaler.pkl")

# IP model (API features + XGBoost)
ip_model = _load_model("ip_model.pkl")
ip_scaler = _load_model("ip_scaler.pkl")

# Domain model (Structural features + XGBoost)
domain_model = _load_model("domain_model.pkl")
domain_scaler = _load_model("domain_scaler.pkl")

# Hash model (API features + XGBoost)
hash_model = _load_model("hash_model.pkl")
hash_scaler = _load_model("hash_scaler.pkl")

# ═══════════════════════════════════════════════════════════════════════════════
# ZERO-DAY ANOMALY DETECTORS (Isolation Forest)
# ═══════════════════════════════════════════════════════════════════════════════

zd_url_model = _load_model("zeroday_url.pkl")
zd_url_scaler = _load_model("zeroday_url_scaler.pkl")

zd_ip_model = _load_model("zeroday_ip.pkl")
zd_ip_scaler = _load_model("zeroday_ip_scaler.pkl")

zd_domain_model = _load_model("zeroday_domain.pkl")
zd_domain_scaler = _load_model("zeroday_domain_scaler.pkl")

zd_hash_model = _load_model("zeroday_hash.pkl")
zd_hash_scaler = _load_model("zeroday_hash_scaler.pkl")

zd_keyword_model = _load_model("zeroday_keyword.pkl")
zd_keyword_scaler = _load_model("zeroday_keyword_scaler.pkl")
zd_keyword_svd = _load_model("zeroday_keyword_svd.pkl")

# Log what loaded
_loaded = []
if model and vectorizer: _loaded.append("keyword")
if url_model and url_scaler: _loaded.append("url")
if ip_model and ip_scaler: _loaded.append("ip")
if domain_model and domain_scaler: _loaded.append("domain")
if hash_model and hash_scaler: _loaded.append("hash")

_zd_loaded = []
if zd_url_model: _zd_loaded.append("url")
if zd_ip_model: _zd_loaded.append("ip")
if zd_domain_model: _zd_loaded.append("domain")
if zd_hash_model: _zd_loaded.append("hash")
if zd_keyword_model: _zd_loaded.append("keyword")

logger.info(f" Loaded ML models: {', '.join(_loaded) if _loaded else 'NONE'}")
logger.info(f" Loaded Zero-Day detectors: {', '.join(_zd_loaded) if _zd_loaded else 'NONE'}")


# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE EXTRACTION FUNCTIONS (must match train_all_models.py)
# ═══════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_TLDS = [".xyz", ".top", ".buzz", ".click", ".link", ".tk", ".ml",
                   ".ga", ".cf", ".gq", ".pw", ".cc", ".icu", ".club",
                   ".work", ".site", ".online", ".fun", ".space", ".info"]
BRAND_NAMES = ["paypal", "apple", "google", "amazon", "microsoft",
               "netflix", "facebook", "instagram", "bank", "secure"]


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def extract_url_features(url: str) -> list:
    """Extract 20 lexical features from a URL (must match training pipeline)."""
    try:
        url_lower = url.lower()
        url_length = len(url)
        hostname = url.split("//")[-1].split("/")[0].split(":")[0].split("@")[-1]
        hostname_length = len(hostname)
        path = "/" + "/".join(url.split("//")[-1].split("/")[1:]) if "/" in url.split("//")[-1] else "/"
        path_length = len(path)
        num_dots = url.count(".")
        num_hyphens = url.count("-")
        num_underscores = url.count("_")
        num_slashes = url.count("/")
        num_at = url.count("@")
        num_digits = sum(c.isdigit() for c in url)
        num_special = sum(not c.isalnum() and c not in "./-_:@" for c in url)
        digit_ratio = num_digits / max(url_length, 1)
        letter_ratio = sum(c.isalpha() for c in url) / max(url_length, 1)
        has_https = 1 if url_lower.startswith("https") else 0
        has_ip = 1 if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", hostname) else 0
        has_port = 1 if re.search(r":\d{2,5}", url.split("//")[-1].split("/")[0]) else 0
        parts = hostname.split(".")
        num_subdomains = max(len(parts) - 2, 0)
        tld = "." + parts[-1] if parts else ""
        has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
        has_brand = 0
        for brand in BRAND_NAMES:
            if brand in hostname and not hostname.endswith(f"{brand}.com") and not hostname.endswith(f"{brand}.org"):
                has_brand = 1
                break
        url_entropy = _entropy(url)
        longest_word = len(max(re.split(r"[^a-zA-Z]", url), key=len)) if url else 0
        return [
            url_length, hostname_length, path_length,
            num_dots, num_hyphens, num_underscores, num_slashes,
            num_at, num_digits, num_special,
            digit_ratio, letter_ratio,
            has_https, has_ip, has_port,
            num_subdomains, has_suspicious_tld, has_brand,
            url_entropy, longest_word,
        ]
    except Exception:
        return [0] * 20


def extract_domain_features(domain: str) -> list:
    """Extract 14 structural features from a domain (must match training pipeline)."""
    try:
        domain = domain.lower().strip()
        length = len(domain)
        num_dots = domain.count(".")
        num_hyphens = domain.count("-")
        num_digits = sum(c.isdigit() for c in domain)
        letters = [c for c in domain if c.isalpha()]
        digit_ratio = num_digits / max(length, 1)
        vowels = sum(1 for c in letters if c in "aeiou")
        consonants = len(letters) - vowels
        consonant_ratio = consonants / max(len(letters), 1)
        vowel_ratio = vowels / max(len(letters), 1)
        parts = domain.split(".")
        tld = "." + parts[-1] if parts else ""
        has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
        has_brand = 0
        for brand in BRAND_NAMES:
            if brand in domain and domain != f"{brand}.com" and domain != f"www.{brand}.com":
                has_brand = 1
                break
        subdomain_depth = max(len(parts) - 2, 0)
        max_label_len = max(len(p) for p in parts) if parts else 0
        avg_label_len = sum(len(p) for p in parts) / max(len(parts), 1)
        dom_entropy = _entropy(domain)
        num_unique = len(set(domain))
        return [
            length, num_dots, num_hyphens, num_digits,
            digit_ratio, consonant_ratio, vowel_ratio,
            has_suspicious_tld, has_brand,
            subdomain_depth, max_label_len, avg_label_len,
            dom_entropy, num_unique,
        ]
    except Exception:
        return [0] * 14


def extract_ip_api_features(vt_data: Dict, shodan_data: Dict, otx_data: Dict,
                            abuseipdb_data: Dict) -> list:
    """Extract 11 API features for IP classification (must match training pipeline)."""
    vt_m, vt_s, vt_h, vt_u = 0, 0, 0, 0
    if vt_data and 'error' not in vt_data:
        stats = vt_data.get('last_analysis_stats', {}) or vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        if stats:
            vt_m = stats.get('malicious', 0)
            vt_s = stats.get('suspicious', 0)
            vt_h = stats.get('harmless', 0)
            vt_u = stats.get('undetected', 0)

    ports, vulns = 0, 0
    if shodan_data and 'error' not in shodan_data:
        p = shodan_data.get('ports', [])
        v = shodan_data.get('vulns', [])
        ports = len(p) if isinstance(p, list) else 0
        vulns = len(v) if isinstance(v, (list, dict)) else 0

    otx_score, otx_pulses = 0, 0
    if otx_data and 'error' not in otx_data:
        otx_score = otx_data.get('threat_score', 0) or 0
        otx_pulses = otx_data.get('source_count', 0) or 0

    abuse_conf, abuse_reps = 0, 0
    if abuseipdb_data and 'error' not in abuseipdb_data:
        abuse_conf = abuseipdb_data.get('abuse_confidence_score', 0) or abuseipdb_data.get('threat_score', 0) or 0
        abuse_reps = abuseipdb_data.get('total_reports', 0) or 0

    is_private = 0
    return [vt_m, vt_s, vt_h, vt_u, ports, vulns,
            otx_score, otx_pulses, abuse_conf, abuse_reps, is_private]


def extract_hash_api_features(vt_data: Dict, otx_data: Dict) -> list:
    """Extract 9 API features for hash classification (must match training pipeline)."""
    vt_m, vt_s, vt_h, vt_u = 0, 0, 0, 0
    if vt_data and 'error' not in vt_data:
        stats = vt_data.get('last_analysis_stats', {}) or vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        if stats:
            vt_m = stats.get('malicious', 0)
            vt_s = stats.get('suspicious', 0)
            vt_h = stats.get('harmless', 0)
            vt_u = stats.get('undetected', 0)

    total = vt_m + vt_s + vt_h + vt_u
    det_ratio = (vt_m + vt_s * 0.5) / max(total, 1)

    otx_score, otx_pulses = 0, 0
    if otx_data and 'error' not in otx_data:
        otx_score = otx_data.get('threat_score', 0) or 0
        otx_pulses = otx_data.get('source_count', 0) or 0

    community = 0
    if vt_data and 'error' not in vt_data:
        community = vt_data.get('community_score', 0) or vt_data.get('data', {}).get('attributes', {}).get('reputation', 0) or 0

    first_seen = 30  # default
    return [vt_m, vt_s, vt_h, vt_u, det_ratio,
            otx_score, otx_pulses, community, first_seen]


# CONTEXT-AWARE TEXT CLASSIFICATION

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


# WEIGHTED API SCORING

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


# MAIN CLASSIFICATION FUNCTION

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
    logger.info(f" IMPROVED CLASSIFICATION for {ioc_type}: {user_input}")
    logger.info(f"{'='*80}")
    
    # Initialize result details
    result_details = {
        'model_confidence': 0.0,
        'api_scores': {},
        'context_analysis': {},
        'final_classification': 'Unknown',
        'reasoning': [],
        'confidence_threshold_met': False,
        'zero_day_analysis': {
            'is_anomaly': False,
            'anomaly_score': 0.0,
            'is_potential_zero_day': False,
        }
    }
    
    try:
        # KEYWORD-SPECIFIC LOGIC WITH CONTEXT AWARENESS
        if ioc_type == "keyword":
            logger.info(f" Processing keyword with context awareness: {user_input}")
            
            # Analyze text context
            context = analyze_text_context(user_input)
            result_details['context_analysis'] = context
            
            logger.info(f" Context Analysis:")
            logger.info(f" Benign patterns: {context['benign_score']}")
            logger.info(f" Malicious patterns: {context['malicious_score']}")
            logger.info(f" Context confidence: {context['confidence']:.2%}")
            
            # If strong benign context detected, override
            if context['is_benign_context'] and context['confidence'] >= 0.7:
                result_details['final_classification'] = 'Benign'
                result_details['reasoning'].append(f"Educational/preventive context detected (confidence: {context['confidence']:.2%})")
                result_details['confidence_threshold_met'] = True
                
                logger.info(f" BENIGN CONTEXT OVERRIDE: '{user_input}' is educational/preventive")
                logger.info(f" Result Details: {result_details}")
                logger.info(f"{'='*80}\n")
                return 'Benign', result_details
            
            # Calculate weighted API score
            api_scores = calculate_weighted_api_score(vt_data, shodan_data, otx_data, abuseipdb_data, ioc_type)
            result_details['api_scores'] = api_scores
            
            weighted_score = api_scores['weighted_total']
            logger.info(f" Weighted API Score: {weighted_score:.1f}/100")
            logger.info(f" VT: {api_scores['vt_score']:.1f}, OTX: {api_scores['otx_score']:.1f}, Shodan: {api_scores['shodan_score']:.1f}, AbuseIPDB: {api_scores['abuseipdb_score']:.1f}")
            
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
                    
                    logger.info(f" ML Model Prediction:")
                    logger.info(f" Benign: {benign_conf:.2%}, Malicious: {malicious_conf:.2%}")
                    
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
                    logger.error(f" ML model error: {e}")
                    classification = classify_by_weighted_score(weighted_score, context['is_malicious_context'])
                    result_details['final_classification'] = classification
                    result_details['reasoning'].append(f"ML error, fallback to API score: {weighted_score:.1f}")
            else:
                # No ML model, use weighted API score
                classification = classify_by_weighted_score(weighted_score, context['is_malicious_context'])
                result_details['final_classification'] = classification
                result_details['reasoning'].append(f"No ML model, using weighted API score: {weighted_score:.1f}")
            
            logger.info(f" Final Classification: {classification}")
            logger.info(f" Result Details: {result_details}")
            logger.info(f"{'='*80}\n")
            return classification, result_details
        
        # ══════════════════════════════════════════════════════════════════
        # IP / URL / DOMAIN / HASH CLASSIFICATION — IOC-SPECIFIC MODELS
        # ══════════════════════════════════════════════════════════════════

        # Calculate weighted API scores (always computed as context)
        api_scores = calculate_weighted_api_score(vt_data, shodan_data, otx_data, abuseipdb_data, ioc_type)
        result_details['api_scores'] = api_scores

        weighted_score = api_scores['weighted_total']
        logger.info(f" Weighted API Score: {weighted_score:.1f}/100")
        logger.info(f" VT: {api_scores['vt_score']:.1f}, OTX: {api_scores['otx_score']:.1f}, Shodan: {api_scores['shodan_score']:.1f}, AbuseIPDB: {api_scores['abuseipdb_score']:.1f}")

        abuse_confidence = abuseipdb_data.get('abuse_confidence_score', abuseipdb_data.get('threat_score', 0)) or 0
        abuse_reports = abuseipdb_data.get('total_reports', 0)
        abuse_whitelisted = abuseipdb_data.get('is_whitelisted', False)
        result_details['api_scores']['abuseipdb_details'] = {
            'confidence': abuse_confidence,
            'reports': abuse_reports,
            'whitelisted': abuse_whitelisted
        }

        # Select the correct IOC-specific model
        ioc_model, ioc_scaler, features = None, None, None

        if ioc_type == 'url' and url_model is not None:
            ioc_model, ioc_scaler = url_model, url_scaler
            features = extract_url_features(user_input)
            logger.info(f" Using URL ML model (20 lexical features)")

        elif ioc_type == 'ip' and ip_model is not None:
            ioc_model, ioc_scaler = ip_model, ip_scaler
            features = extract_ip_api_features(vt_data, shodan_data, otx_data, abuseipdb_data)
            logger.info(f" Using IP ML model (11 API features)")

        elif ioc_type == 'domain' and domain_model is not None:
            ioc_model, ioc_scaler = domain_model, domain_scaler
            features = extract_domain_features(user_input)
            logger.info(f" Using Domain ML model (14 structural features)")

        elif ioc_type == 'hash' and hash_model is not None:
            ioc_model, ioc_scaler = hash_model, hash_scaler
            features = extract_hash_api_features(vt_data, otx_data)
            logger.info(f" Using Hash ML model (9 API features)")

        # ══════════════════════════════════════════════════════════════════
        # ZERO-DAY ANOMALY CHECK (runs alongside classifier)
        # ══════════════════════════════════════════════════════════════════
        if features is not None:
            zd_model_map = {
                'url': (zd_url_model, zd_url_scaler),
                'ip': (zd_ip_model, zd_ip_scaler),
                'domain': (zd_domain_model, zd_domain_scaler),
                'hash': (zd_hash_model, zd_hash_scaler),
            }
            zd_m, zd_s = zd_model_map.get(ioc_type, (None, None))
            if zd_m is not None:
                try:
                    X_zd = np.array([features], dtype=np.float32)
                    if zd_s is not None:
                        X_zd = zd_s.transform(X_zd)
                    anomaly_pred = zd_m.predict(X_zd)[0]  # 1=normal, -1=anomaly
                    anomaly_score = zd_m.decision_function(X_zd)[0]  # lower = more anomalous
                    is_anomaly = anomaly_pred == -1
                    result_details['zero_day_analysis'] = {
                        'is_anomaly': bool(is_anomaly),
                        'anomaly_score': round(float(anomaly_score), 4),
                        'is_potential_zero_day': False,  # set below after classifier runs
                    }
                    logger.info(f" Zero-Day Check: {'⚠️ ANOMALY' if is_anomaly else '✓ Normal'} (score: {anomaly_score:.4f})")
                except Exception as e:
                    logger.warning(f" Zero-day check error: {e}")

        # Run IOC-specific ML model if available
        if ioc_model is not None and features is not None:
            try:
                X = np.array([features], dtype=np.float32)
                if ioc_scaler is not None:
                    X = ioc_scaler.transform(X)

                proba = ioc_model.predict_proba(X)[0]
                benign_conf = proba[0]
                malicious_conf = proba[1]

                result_details['model_confidence'] = max(benign_conf, malicious_conf)
                result_details['model_type'] = f"{ioc_type}_xgboost"

                logger.info(f" ML Model Prediction ({ioc_type}):")
                logger.info(f" Benign: {benign_conf:.2%}, Malicious: {malicious_conf:.2%}")
                logger.info(f" Features: {features}")

                if result_details['model_confidence'] >= 0.75:
                    result_details['confidence_threshold_met'] = True

                    if malicious_conf > benign_conf:
                        if weighted_score >= 50 or abuse_confidence >= 75:
                            classification = 'Malicious'
                            reason = f"{ioc_type.upper()} ML confident malicious ({malicious_conf:.2%})"
                            if abuse_confidence >= 75:
                                reason += f" + AbuseIPDB {abuse_confidence:.0f}%"
                            reason += f" + API score {weighted_score:.1f}"
                            result_details['reasoning'].append(reason)
                        else:
                            classification = 'Suspicious'
                            result_details['reasoning'].append(f"{ioc_type.upper()} ML says malicious ({malicious_conf:.2%}) but moderate API score {weighted_score:.1f}")
                    else:
                        if abuse_confidence >= 85 and not abuse_whitelisted:
                            classification = 'Malicious'
                            result_details['reasoning'].append(f"AbuseIPDB {abuse_confidence:.0f}% overrides benign ML prediction")
                        elif abuse_confidence >= 55 and not abuse_whitelisted:
                            classification = 'Suspicious'
                            result_details['reasoning'].append(f"AbuseIPDB elevated risk ({abuse_confidence:.0f}%) overrides benign ML")
                        elif weighted_score < 25:
                            classification = 'Benign'
                            result_details['reasoning'].append(f"{ioc_type.upper()} ML confident benign ({benign_conf:.2%}) + low API score")
                        else:
                            classification = 'Informational'
                            result_details['reasoning'].append(f"{ioc_type.upper()} ML says benign but API shows some activity")
                else:
                    result_details['confidence_threshold_met'] = False
                    classification = classify_by_weighted_score(weighted_score, False)
                    result_details['reasoning'].append(f"{ioc_type.upper()} ML confidence below 0.75 ({result_details['model_confidence']:.2%}), fallback to API score {weighted_score:.1f}")

                result_details['final_classification'] = classification

            except Exception as e:
                logger.error(f" {ioc_type} ML model error: {e}", exc_info=True)
                classification = classify_by_weighted_score(weighted_score, False)
                result_details['final_classification'] = classification
                result_details['reasoning'].append(f"{ioc_type.upper()} ML error ({e}), fallback to API score {weighted_score:.1f}")
        else:
            # No IOC-specific model available, use weighted scoring
            classification = classify_by_weighted_score(weighted_score, False)
            result_details['final_classification'] = classification
            result_details['reasoning'].append(f"No {ioc_type} ML model, using weighted API score: {weighted_score:.1f}")

        # ══════════════════════════════════════════════════════════════════
        # ZERO-DAY DECISION: Anomaly + Low Confidence = Potential Zero-Day
        # ══════════════════════════════════════════════════════════════════
        zd = result_details.get('zero_day_analysis', {})
        if zd.get('is_anomaly', False):
            model_conf = result_details.get('model_confidence', 0)
            # Zero-day conditions:
            # 1. Isolation Forest flagged as anomaly (-1)
            # 2. Classifier confidence is below threshold OR classification is uncertain
            if model_conf < 0.75 or classification in ['Informational', 'Unknown']:
                result_details['zero_day_analysis']['is_potential_zero_day'] = True
                classification = 'Potential Zero-Day'
                result_details['final_classification'] = classification
                result_details['reasoning'].append(
                    f"⚠️ ZERO-DAY: Anomaly detected (score: {zd.get('anomaly_score', 0):.4f}) "
                    f"+ classifier uncertain ({model_conf:.2%}) → Potential unknown threat"
                )
                logger.info(f" ⚠️ POTENTIAL ZERO-DAY DETECTED!")
            elif model_conf >= 0.75 and classification == 'Malicious':
                # High confidence malicious + anomaly = possibly new variant
                result_details['zero_day_analysis']['is_potential_zero_day'] = True
                result_details['reasoning'].append(
                    f"⚠️ ANOMALY: New malicious pattern detected (anomaly score: {zd.get('anomaly_score', 0):.4f}) "
                    f"— possible new variant of known threat"
                )
                logger.info(f" ⚠️ Anomalous malicious pattern — possible new variant")

        # AbuseIPDB safety net for IPs
        if ioc_type == 'ip' and abuse_confidence and not abuse_whitelisted:
            if abuse_confidence >= 90 and classification != 'Malicious':
                classification = 'Malicious'
                result_details['final_classification'] = classification
                result_details['reasoning'].append(f"Forced malicious: AbuseIPDB {abuse_confidence:.0f}% with {abuse_reports} reports")
            elif abuse_confidence >= 60 and classification in ['Benign', 'Informational']:
                classification = 'Suspicious'
                result_details['final_classification'] = classification
                result_details['reasoning'].append(f"Escalated to Suspicious: AbuseIPDB {abuse_confidence:.0f}%")

        logger.info(f" Final Classification: {classification}")
        logger.info(f" Result Details: {result_details}")
        logger.info(f"{'='*80}\n")
        return classification, result_details
    
    except Exception as e:
        logger.error(f" Classification error: {e}", exc_info=True)
        result_details['final_classification'] = 'Unknown'
        result_details['reasoning'].append(f"Error: {str(e)}")
        return 'Unknown', result_details


def classify_by_weighted_score(weighted_score: float, has_malicious_context: bool) -> str:
    """
    Classify based on weighted API score
    """
    # Adjust thresholds if malicious context detected
    if has_malicious_context:
        weighted_score += 15 # Boost score if malicious patterns found
    
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
    Legacy feature extraction (kept for backward compatibility).
    New code uses IOC-specific extractors above.
    """
    features = [0, 0, 0, 0, 0, 0]
    if vt_data and 'error' not in vt_data:
        stats = vt_data.get('last_analysis_stats', {}) or vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        if stats:
            features[0] = stats.get('malicious', 0)
            features[1] = stats.get('suspicious', 0)
    if ioc_type == 'ip' and shodan_data and 'error' not in shodan_data:
        ports = shodan_data.get('ports', [])
        vulns = shodan_data.get('vulns', [])
        features[2] = len(ports) if isinstance(ports, list) else 0
        features[3] = len(vulns) if isinstance(vulns, (list, dict)) else 0
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
    logger.info(f" Classification Summary:")
    logger.info(f" Final Label: {classification}")
    logger.info(f" Model Confidence: {details.get('model_confidence', 0):.2%}")
    logger.info(f" Confidence Threshold Met: {details.get('confidence_threshold_met', False)}")
    logger.info(f" Reasoning: {'; '.join(details.get('reasoning', []))}")
    
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
