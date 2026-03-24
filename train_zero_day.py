"""
train_zero_day.py
=================
Train Isolation Forest anomaly detection models for Zero-Day threat detection.

Concept:
  - Traditional classifiers say "Is this KNOWN-malicious or KNOWN-benign?"
  - Zero-day detector says "Does this look like ANYTHING I've seen before?"
  - If it doesn't match ANY known pattern → Potential Zero-Day 🔍

For each IOC type, we train an Isolation Forest on COMBINED known data
(both benign + malicious). At inference time:
  - If anomaly score is very low (outlier) → Never-before-seen pattern
  - If classifier confidence is also low  → Can't classify it either
  - Combined: "Potential Zero-Day" flag

Models saved:
  models/zeroday_url.pkl       - URL anomaly detector
  models/zeroday_ip.pkl        - IP anomaly detector
  models/zeroday_domain.pkl    - Domain anomaly detector
  models/zeroday_hash.pkl      - Hash anomaly detector
  models/zeroday_keyword.pkl   - Keyword anomaly detector
"""

import os, sys, json, math, re, random, string, warnings, logging
import numpy as np
import joblib
from collections import Counter
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:
    pass

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "datasets")
os.makedirs(MODELS_DIR, exist_ok=True)

RANDOM_STATE = 42
random.seed(RANDOM_STATE)
np.random.seed(RANDOM_STATE)

# Import feature extractors from existing training scripts
sys.path.insert(0, BASE_DIR)
from train_all_models import (
    extract_url_features, extract_domain_features,
    generate_benign_url, generate_malicious_url,
    generate_edge_case_benign_url, generate_edge_case_malicious_url,
    LEGIT_PATTERNS, MALICIOUS_DOMAIN_PATTERNS,
)


# ═══════════════════════════════════════════════════════════════════════════════
# IP & HASH FEATURE GENERATORS (from train_real_data.py)
# ═══════════════════════════════════════════════════════════════════════════════

def generate_ip_features(label, edge_case=False):
    """Generate IP API features for training."""
    if label == 1:
        if edge_case:
            vt_m, vt_s = random.randint(1, 5), random.randint(0, 3)
            vt_h, vt_u = random.randint(40, 65), random.randint(5, 20)
            ports, vulns = random.randint(1, 6), random.randint(0, 2)
            otx_score, otx_pulses = random.randint(15, 45), random.randint(1, 8)
            abuse_conf, abuse_reps = random.randint(20, 55), random.randint(3, 30)
        else:
            vt_m = random.randint(3, 60); vt_s = random.randint(1, 15)
            vt_h = random.randint(10, 50); vt_u = random.randint(0, 15)
            ports = random.randint(2, 100); vulns = random.randint(0, 8)
            otx_score = random.randint(30, 100); otx_pulses = random.randint(3, 60)
            abuse_conf = random.randint(40, 100); abuse_reps = random.randint(10, 600)
        is_private = 0
    else:
        if edge_case:
            vt_m, vt_s = random.randint(1, 4), random.randint(0, 3)
            vt_h, vt_u = random.randint(45, 70), random.randint(2, 12)
            ports, vulns = random.randint(5, 20), random.randint(0, 3)
            otx_score, otx_pulses = random.randint(10, 35), random.randint(1, 6)
            abuse_conf, abuse_reps = random.randint(5, 35), random.randint(2, 25)
        else:
            vt_m, vt_s = random.randint(0, 2), random.randint(0, 1)
            vt_h, vt_u = random.randint(50, 80), random.randint(0, 10)
            ports = random.randint(1, 15); vulns = random.randint(0, 3)
            otx_score = random.randint(0, 20); otx_pulses = random.randint(0, 5)
            abuse_conf = random.randint(0, 20); abuse_reps = random.randint(0, 15)
        is_private = random.choice([0]*8 + [1]*2)
    return [vt_m, vt_s, vt_h, vt_u, ports, vulns,
            otx_score, otx_pulses, abuse_conf, abuse_reps, is_private]


def generate_hash_features(label, edge_case=False):
    """Generate hash API features for training."""
    if label == 1:
        if edge_case:
            vt_m, vt_s = random.randint(2, 8), random.randint(1, 5)
            vt_h, vt_u = random.randint(30, 55), random.randint(5, 20)
            otx_score, otx_pulses = random.randint(15, 45), random.randint(1, 6)
            community, first_seen = random.randint(-20, 0), random.randint(0, 14)
        else:
            vt_m, vt_s = random.randint(10, 65), random.randint(2, 12)
            vt_h, vt_u = random.randint(5, 30), random.randint(0, 10)
            otx_score, otx_pulses = random.randint(50, 100), random.randint(5, 50)
            community, first_seen = random.randint(-50, -5), random.randint(0, 365)
    else:
        if edge_case:
            vt_m, vt_s = random.randint(1, 5), random.randint(1, 4)
            vt_h, vt_u = random.randint(45, 65), random.randint(3, 15)
            otx_score, otx_pulses = random.randint(5, 25), random.randint(0, 4)
            community, first_seen = random.randint(-5, 15), random.randint(7, 730)
        else:
            vt_m, vt_s = random.randint(0, 2), random.randint(0, 1)
            vt_h, vt_u = random.randint(55, 75), random.randint(0, 10)
            otx_score, otx_pulses = random.randint(0, 15), random.randint(0, 3)
            community, first_seen = random.randint(0, 50), random.randint(30, 3650)

    total = vt_m + vt_s + vt_h + vt_u
    det_ratio = (vt_m + vt_s * 0.5) / max(total, 1)
    return [vt_m, vt_s, vt_h, vt_u, det_ratio, otx_score, otx_pulses, community, first_seen]


# ═══════════════════════════════════════════════════════════════════════════════
# TRAIN ISOLATION FOREST FOR EACH IOC TYPE
# ═══════════════════════════════════════════════════════════════════════════════

def train_zeroday_url():
    """Train Isolation Forest on known URL patterns."""
    logger.info("  Generating known URL patterns (benign + malicious)...")
    urls = []
    for _ in range(3000):
        urls.append(generate_benign_url())
    for _ in range(3000):
        urls.append(generate_malicious_url())
    for _ in range(300):
        urls.append(generate_edge_case_benign_url())
    for _ in range(300):
        urls.append(generate_edge_case_malicious_url())

    # Also add real URLs from URLhaus if available
    urlhaus_path = os.path.join(DATA_DIR, "urlhaus_urls.csv")
    if os.path.exists(urlhaus_path):
        try:
            lines = open(urlhaus_path, 'r', encoding='utf-8', errors='replace').readlines()
            real_urls = [l.strip().split('","')[2].strip('"') for l in lines
                        if not l.startswith('#') and l.strip() and len(l.strip().split('","')) >= 3]
            real_urls = [u for u in real_urls if u.startswith('http')][:2000]
            urls.extend(real_urls)
            logger.info(f"  Added {len(real_urls)} real URLs from URLhaus")
        except Exception as e:
            logger.warning(f"  Could not load URLhaus: {e}")

    X = np.array([extract_url_features(u) for u in urls], dtype=np.float32)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    iso = IsolationForest(
        n_estimators=200,
        contamination=0.03,      # Expect ~3% true anomalies (zero-days)
        max_samples='auto',
        max_features=1.0,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    iso.fit(X_scaled)

    # Test: check anomaly rate on training data
    preds = iso.predict(X_scaled)
    anomaly_rate = sum(preds == -1) / len(preds)
    scores = iso.decision_function(X_scaled)
    logger.info(f"  URL Isolation Forest: {len(X)} samples, anomaly rate: {anomaly_rate:.1%}")
    logger.info(f"  Score range: [{scores.min():.4f}, {scores.max():.4f}], mean: {scores.mean():.4f}")

    joblib.dump(iso, os.path.join(MODELS_DIR, "zeroday_url.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "zeroday_url_scaler.pkl"))
    return {"samples": len(X), "anomaly_rate": round(anomaly_rate, 4)}


def train_zeroday_ip():
    """Train Isolation Forest on known IP API response patterns."""
    logger.info("  Generating known IP patterns...")
    X = []
    for _ in range(3000):
        X.append(generate_ip_features(0)); X.append(generate_ip_features(1))
    for _ in range(500):
        X.append(generate_ip_features(0, True)); X.append(generate_ip_features(1, True))

    X = np.array(X, dtype=np.float32)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    iso = IsolationForest(n_estimators=200, contamination=0.03, random_state=RANDOM_STATE, n_jobs=-1)
    iso.fit(X_scaled)

    preds = iso.predict(X_scaled)
    anomaly_rate = sum(preds == -1) / len(preds)
    logger.info(f"  IP Isolation Forest: {len(X)} samples, anomaly rate: {anomaly_rate:.1%}")

    joblib.dump(iso, os.path.join(MODELS_DIR, "zeroday_ip.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "zeroday_ip_scaler.pkl"))
    return {"samples": len(X), "anomaly_rate": round(anomaly_rate, 4)}


def train_zeroday_domain():
    """Train Isolation Forest on known domain patterns."""
    logger.info("  Generating known domain patterns...")
    domains = []
    for _ in range(3000):
        domains.append(random.choice(LEGIT_PATTERNS)())
    for _ in range(3000):
        domains.append(random.choice(MALICIOUS_DOMAIN_PATTERNS)())

    # Add real domains from Majestic Million
    majestic_path = os.path.join(DATA_DIR, "majestic_million.csv")
    if os.path.exists(majestic_path):
        try:
            import pandas as pd
            df = pd.read_csv(majestic_path, nrows=5000)
            real_domains = df['Domain'].dropna().tolist()[:3000]
            domains.extend(real_domains)
            logger.info(f"  Added {len(real_domains)} real domains from Majestic Million")
        except Exception as e:
            logger.warning(f"  Could not load Majestic: {e}")

    X = np.array([extract_domain_features(d) for d in domains], dtype=np.float32)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    iso = IsolationForest(n_estimators=200, contamination=0.03, random_state=RANDOM_STATE, n_jobs=-1)
    iso.fit(X_scaled)

    preds = iso.predict(X_scaled)
    anomaly_rate = sum(preds == -1) / len(preds)
    logger.info(f"  Domain Isolation Forest: {len(X)} samples, anomaly rate: {anomaly_rate:.1%}")

    joblib.dump(iso, os.path.join(MODELS_DIR, "zeroday_domain.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "zeroday_domain_scaler.pkl"))
    return {"samples": len(X), "anomaly_rate": round(anomaly_rate, 4)}


def train_zeroday_hash():
    """Train Isolation Forest on known hash API feature patterns."""
    logger.info("  Generating known hash patterns...")
    X = []
    for _ in range(3000):
        X.append(generate_hash_features(0)); X.append(generate_hash_features(1))
    for _ in range(500):
        X.append(generate_hash_features(0, True)); X.append(generate_hash_features(1, True))

    X = np.array(X, dtype=np.float32)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    iso = IsolationForest(n_estimators=200, contamination=0.03, random_state=RANDOM_STATE, n_jobs=-1)
    iso.fit(X_scaled)

    preds = iso.predict(X_scaled)
    anomaly_rate = sum(preds == -1) / len(preds)
    logger.info(f"  Hash Isolation Forest: {len(X)} samples, anomaly rate: {anomaly_rate:.1%}")

    joblib.dump(iso, os.path.join(MODELS_DIR, "zeroday_hash.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "zeroday_hash_scaler.pkl"))
    return {"samples": len(X), "anomaly_rate": round(anomaly_rate, 4)}


def train_zeroday_keyword():
    """Train Isolation Forest on known keyword TF-IDF patterns."""
    logger.info("  Loading keyword vectorizer and training data...")
    vectorizer = joblib.load(os.path.join(MODELS_DIR, "keyword_vectorizer.pkl"))

    # Use a subset of known text patterns to build the anomaly baseline
    try:
        from train_improved_model import MALICIOUS_TEXTS, BENIGN_TEXTS
        texts = MALICIOUS_TEXTS + BENIGN_TEXTS
    except ImportError:
        texts = []

    # Add more diverse text to strengthen the baseline
    extra = [
        "ransomware attack encrypt files", "phishing email credentials steal",
        "malware trojan backdoor install", "DDoS flood network packets",
        "exploit vulnerability buffer overflow", "SQL injection database dump",
        "botnet command control server", "keylogger capture passwords",
        "security awareness training program", "firewall configuration best practices",
        "password policy requirements guide", "encryption algorithm comparison",
        "vulnerability scanning assessment", "incident response plan template",
        "network monitoring intrusion detection", "backup disaster recovery plan",
        "patch management system update", "access control authentication setup",
    ]
    texts.extend(extra)

    if not texts:
        logger.warning("  No text data available for keyword anomaly detector")
        return None

    X_tfidf = vectorizer.transform(texts).toarray()

    # Use PCA to reduce dimensionality for Isolation Forest
    from sklearn.decomposition import TruncatedSVD
    n_components = min(50, X_tfidf.shape[1], len(texts) - 1)
    svd = TruncatedSVD(n_components=n_components, random_state=RANDOM_STATE)
    X_reduced = svd.fit_transform(X_tfidf)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_reduced)

    iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=RANDOM_STATE, n_jobs=-1)
    iso.fit(X_scaled)

    preds = iso.predict(X_scaled)
    anomaly_rate = sum(preds == -1) / len(preds)
    logger.info(f"  Keyword Isolation Forest: {len(texts)} samples (reduced to {n_components}D), anomaly rate: {anomaly_rate:.1%}")

    joblib.dump(iso, os.path.join(MODELS_DIR, "zeroday_keyword.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "zeroday_keyword_scaler.pkl"))
    joblib.dump(svd, os.path.join(MODELS_DIR, "zeroday_keyword_svd.pkl"))
    return {"samples": len(texts), "anomaly_rate": round(anomaly_rate, 4)}


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    start = datetime.now()

    logger.info("\n" + "=" * 70)
    logger.info("  ZERO-DAY ANOMALY DETECTION — ISOLATION FOREST TRAINING")
    logger.info("=" * 70)
    logger.info("  Concept: Detect inputs that don't match ANY known pattern")
    logger.info("  Algorithm: Isolation Forest (unsupervised anomaly detection)")
    logger.info("  If anomalous + low classifier confidence → 'Potential Zero-Day'")
    logger.info("")

    results = {}

    logger.info("\n[1/5] URL Zero-Day Detector")
    results["url"] = train_zeroday_url()

    logger.info("\n[2/5] IP Zero-Day Detector")
    results["ip"] = train_zeroday_ip()

    logger.info("\n[3/5] Domain Zero-Day Detector")
    results["domain"] = train_zeroday_domain()

    logger.info("\n[4/5] Hash Zero-Day Detector")
    results["hash"] = train_zeroday_hash()

    logger.info("\n[5/5] Keyword Zero-Day Detector")
    results["keyword"] = train_zeroday_keyword()

    elapsed = (datetime.now() - start).total_seconds()

    logger.info(f"\n\n{'='*70}")
    logger.info(f"  ZERO-DAY TRAINING COMPLETE")
    logger.info(f"{'='*70}")
    logger.info(f"\n  {'IOC Type':<15} {'Samples':>10} {'Anomaly Rate':>15}")
    logger.info(f"  {'-'*42}")
    for name, r in results.items():
        if r:
            logger.info(f"  {name:<15} {r['samples']:>10,} {r['anomaly_rate']:>14.1%}")

    logger.info(f"\n  Time: {elapsed:.1f}s")
    logger.info(f"  Models saved to: {MODELS_DIR}/zeroday_*.pkl")
    logger.info(f"\n{'='*70}\n")


if __name__ == "__main__":
    main()
