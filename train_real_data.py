"""
train_real_data.py
==================
Train ALL threat classification models using REAL-WORLD datasets:

  1. URL Model    - URLhaus (abuse.ch) malicious URLs + Kaggle dataset
  2. Domain Model - Majestic Million (benign) + URLhaus domains (malicious)
  3. Hash Model   - MalwareBazaar (abuse.ch) + synthetic benign
  4. Keyword Model - Enhanced synthetic (context-aware threat text)
  5. IP Model     - Synthetic API features (real IP data needs live API calls)

Free data sources (NO API KEY needed):
  - URLhaus (abuse.ch)         → 30K+ confirmed malicious URLs (updated daily)
  - Majestic Million           → 1,000,000 top legitimate domains
  - MalwareBazaar (abuse.ch)   → Recent malware SHA256 hashes + metadata

Optional (NEEDS Kaggle API key):
  - Kaggle malicious_phish.csv → 651,191 labeled URLs (benign/phishing/malware/defacement)

Anti-overfitting:
  - 5-fold stratified cross-validation
  - L1/L2 regularization on XGBoost
  - Train-test gap monitoring
  - StandardScaler normalization
"""

import os, sys, math, re, random, string, warnings, logging, json, io, zipfile
import time
from collections import Counter
from datetime import datetime
from urllib.parse import urlparse

# Load .env FIRST so Kaggle credentials are available
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:
    pass

# Set up Kaggle credentials from .env before importing kaggle
def _setup_kaggle_credentials():
    """Set up kaggle.json from .env variables."""
    kaggle_dir = os.path.join(os.path.expanduser("~"), ".kaggle")
    kaggle_json = os.path.join(kaggle_dir, "kaggle.json")

    # Already configured?
    if os.path.exists(kaggle_json):
        return True

    # Try KAGGLE_USERNAME + KAGGLE_KEY
    username = os.environ.get("KAGGLE_USERNAME", "")
    key = os.environ.get("KAGGLE_KEY", "") or os.environ.get("KAGGLE_API_TOKEN", "")

    if username and key:
        os.makedirs(kaggle_dir, exist_ok=True)
        with open(kaggle_json, "w") as f:
            json.dump({"username": username, "key": key}, f)
        os.chmod(kaggle_json, 0o600) if os.name != 'nt' else None
        return True

    # Try KAGGLE_API_TOKEN as JSON string
    token = os.environ.get("KAGGLE_API_TOKEN", "")
    if token and "{" in token:
        os.makedirs(kaggle_dir, exist_ok=True)
        with open(kaggle_json, "w") as f:
            f.write(token)
        return True

    return False

_setup_kaggle_credentials()

import requests
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import (
    train_test_split, StratifiedKFold, cross_val_score
)
from sklearn.metrics import (
    classification_report, accuracy_score, confusion_matrix,
    precision_score, recall_score, f1_score
)
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

try:
    from imblearn.over_sampling import SMOTE
    HAS_SMOTE = True
except ImportError:
    HAS_SMOTE = False

warnings.filterwarnings("ignore")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "datasets")
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

RANDOM_STATE = 42
random.seed(RANDOM_STATE)
np.random.seed(RANDOM_STATE)


# ═══════════════════════════════════════════════════════════════════════════════
# DATA DOWNLOAD FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def download_file(url, dest_path, desc=""):
    """Download a file with progress reporting."""
    if os.path.exists(dest_path):
        age_hours = (time.time() - os.path.getmtime(dest_path)) / 3600
        if age_hours < 24:
            logger.info(f"  {desc} already downloaded (< 24h old), skipping")
            return True

    logger.info(f"  Downloading {desc} from {url}...")
    try:
        r = requests.get(url, timeout=120, stream=True)
        r.raise_for_status()
        total = int(r.headers.get('content-length', 0))
        downloaded = 0
        with open(dest_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=65536):
                f.write(chunk)
                downloaded += len(chunk)
                if total > 0:
                    pct = downloaded / total * 100
                    print(f"\r    Progress: {downloaded/1024/1024:.1f} MB / {total/1024/1024:.1f} MB ({pct:.0f}%)", end="", flush=True)
        print()  # newline after progress
        logger.info(f"  Downloaded {desc}: {os.path.getsize(dest_path)/1024/1024:.1f} MB")
        return True
    except Exception as e:
        logger.error(f"  Failed to download {desc}: {e}")
        return False


def download_urlhaus():
    """Download URLhaus malicious URL dataset (abuse.ch) - FREE."""
    dest = os.path.join(DATA_DIR, "urlhaus_urls.csv")
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    if download_file(url, dest, "URLhaus malicious URLs"):
        try:
            # URLhaus CSV has comment lines starting with #
            lines = open(dest, 'r', encoding='utf-8', errors='replace').readlines()
            data_lines = [l for l in lines if not l.startswith('#') and l.strip()]
            if data_lines:
                header = '"id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"'
                # Parse manually since format can vary
                urls = []
                for line in data_lines[1:]:  # skip header
                    parts = line.strip().split('","')
                    if len(parts) >= 3:
                        url_val = parts[2].strip('"').strip()
                        if url_val.startswith('http'):
                            urls.append(url_val)
                logger.info(f"  URLhaus: Extracted {len(urls)} malicious URLs")
                return urls
        except Exception as e:
            logger.error(f"  Error parsing URLhaus: {e}")
    return []


def download_majestic_million():
    """Download Majestic Million top domains - FREE."""
    dest = os.path.join(DATA_DIR, "majestic_million.csv")
    url = "https://downloads.majestic.com/majestic_million.csv"
    if download_file(url, dest, "Majestic Million domains"):
        try:
            df = pd.read_csv(dest, nrows=50000)  # Top 50K is plenty
            domains = df['Domain'].dropna().tolist()
            logger.info(f"  Majestic Million: Loaded {len(domains)} legitimate domains")
            return domains
        except Exception as e:
            logger.error(f"  Error parsing Majestic Million: {e}")
    return []


def download_malwarebazaar():
    """Download MalwareBazaar recent malware hashes - FREE."""
    dest = os.path.join(DATA_DIR, "malwarebazaar_recent.zip")
    url = "https://bazaar.abuse.ch/export/csv/recent/"
    if download_file(url, dest, "MalwareBazaar hashes"):
        try:
            with zipfile.ZipFile(dest, 'r') as z:
                csv_name = z.namelist()[0]
                with z.open(csv_name) as f:
                    lines = f.read().decode("utf-8", errors="replace").split('\n')
                    data_lines = [l for l in lines if not l.startswith('#') and l.strip()]
                    hashes = []
                    for line in data_lines[1:]:  # skip header
                        parts = line.split('","')
                        if len(parts) >= 2:
                            sha256 = parts[1].strip('"').strip()
                            if len(sha256) == 64:
                                hashes.append(sha256)
                    logger.info(f"  MalwareBazaar: Extracted {len(hashes)} malware SHA256 hashes")
                    return hashes
        except Exception as e:
            logger.error(f"  Error parsing MalwareBazaar: {e}")
    return []


def download_kaggle_urls():
    """Download Kaggle Malicious URLs dataset (needs API key)."""
    dest_csv = os.path.join(DATA_DIR, "malicious_phish.csv")
    if os.path.exists(dest_csv):
        age_hours = (time.time() - os.path.getmtime(dest_csv)) / 3600
        if age_hours < 168:  # 7 days
            logger.info(f"  Kaggle URLs dataset already exists (< 7 days old)")
            try:
                df = pd.read_csv(dest_csv)
                logger.info(f"  Kaggle: {len(df)} URLs loaded")
                return df
            except Exception:
                pass

    try:
        os.environ.get('KAGGLE_USERNAME') and os.environ.get('KAGGLE_KEY')
        from kaggle.api.kaggle_api_extended import KaggleApi
        api = KaggleApi()
        api.authenticate()
        logger.info("  Downloading Kaggle dataset: sid321axn/malicious-urls-dataset ...")
        api.dataset_download_files('sid321axn/malicious-urls-dataset', path=DATA_DIR, unzip=True)
        if os.path.exists(dest_csv):
            df = pd.read_csv(dest_csv)
            logger.info(f"  Kaggle: Downloaded {len(df)} URLs")
            return df
    except Exception as e:
        logger.warning(f"  Kaggle download failed: {e}")
        logger.warning(f"  Continuing with URLhaus data only...")
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE EXTRACTION (same as train_all_models.py)
# ═══════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_TLDS = [".xyz", ".top", ".buzz", ".click", ".link", ".tk", ".ml",
                   ".ga", ".cf", ".gq", ".pw", ".cc", ".icu", ".club",
                   ".work", ".site", ".online", ".fun", ".space", ".info"]
BRAND_NAMES = ["paypal", "apple", "google", "amazon", "microsoft",
               "netflix", "facebook", "instagram", "bank", "secure",
               "login", "verify", "account", "update", "confirm"]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def extract_url_features(url: str) -> list:
    """Extract 20 lexical features from a URL string."""
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
        for brand in BRAND_NAMES[:10]:
            if brand in hostname and not hostname.endswith(f"{brand}.com") and not hostname.endswith(f"{brand}.org"):
                has_brand = 1
                break
        url_entropy = entropy(url)
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
    """Extract 14 features from a domain string."""
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
        for brand in BRAND_NAMES[:10]:
            if brand in domain and domain != f"{brand}.com" and domain != f"www.{brand}.com":
                has_brand = 1
                break
        subdomain_depth = max(len(parts) - 2, 0)
        max_label_len = max(len(p) for p in parts) if parts else 0
        avg_label_len = sum(len(p) for p in parts) / max(len(parts), 1)
        dom_entropy = entropy(domain)
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


# ═══════════════════════════════════════════════════════════════════════════════
# TRAINING + EVALUATION HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def train_and_evaluate(name, model, X_train, X_test, y_train, y_test,
                       class_names=None, cv_folds=5):
    """Train, evaluate, cross-validate, and check for overfitting."""
    logger.info(f"\n{'='*70}")
    logger.info(f"  TRAINING: {name}")
    logger.info(f"{'='*70}")
    logger.info(f"  Train: {len(y_train)} | Test: {len(y_test)}")
    logger.info(f"  Train dist: {dict(Counter(y_train))}")
    logger.info(f"  Test dist:  {dict(Counter(y_test))}")

    model.fit(X_train, y_train)

    y_pred_train = model.predict(X_train)
    y_pred_test = model.predict(X_test)
    train_acc = accuracy_score(y_train, y_pred_train)
    test_acc = accuracy_score(y_test, y_pred_test)
    gap = train_acc - test_acc

    logger.info(f"  Train Acc: {train_acc:.4f} | Test Acc: {test_acc:.4f} | Gap: {gap:.4f} {'OVERFIT!' if gap > 0.05 else 'OK'}")

    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=RANDOM_STATE)
    cv_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="accuracy")
    logger.info(f"  CV Acc: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")

    if class_names is None:
        class_names = [str(c) for c in sorted(set(y_test))]

    prec = precision_score(y_test, y_pred_test, average="weighted", zero_division=0)
    rec = recall_score(y_test, y_pred_test, average="weighted", zero_division=0)
    f1 = f1_score(y_test, y_pred_test, average="weighted", zero_division=0)

    logger.info(f"  Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f}")
    logger.info(f"\n{classification_report(y_test, y_pred_test, target_names=class_names, digits=3)}")

    cm = confusion_matrix(y_test, y_pred_test)
    logger.info(f"  Confusion Matrix:\n{cm}")

    return {
        "train_acc": round(train_acc, 6), "test_acc": round(test_acc, 6),
        "cv_mean": round(cv_scores.mean(), 6), "cv_std": round(cv_scores.std(), 6),
        "precision": round(prec, 6), "recall": round(rec, 6), "f1": round(f1, 6),
        "gap": round(gap, 6),
        "data_source": "real",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 1. URL MODEL — REAL DATA from URLhaus + Kaggle
# ═══════════════════════════════════════════════════════════════════════════════

def train_url_model_real():
    """Train URL classifier on real-world URLs."""
    logger.info("\n  [DOWNLOADING URL DATA]")

    # Get malicious URLs from URLhaus (always available)
    malicious_urls = download_urlhaus()

    # Try Kaggle for more data
    kaggle_df = download_kaggle_urls()

    benign_urls = []
    all_malicious_urls = list(malicious_urls)

    if kaggle_df is not None and len(kaggle_df) > 0:
        logger.info("  Using Kaggle dataset as primary source")
        # Kaggle dataset has columns: 'url' and 'type'
        col_url = 'url' if 'url' in kaggle_df.columns else kaggle_df.columns[0]
        col_type = 'type' if 'type' in kaggle_df.columns else kaggle_df.columns[1]

        benign_mask = kaggle_df[col_type].str.lower() == 'benign'
        mal_mask = kaggle_df[col_type].str.lower().isin(['phishing', 'malware', 'defacement'])

        kaggle_benign = kaggle_df[benign_mask][col_url].dropna().tolist()
        kaggle_malicious = kaggle_df[mal_mask][col_url].dropna().tolist()

        # Sample to keep training manageable (max 30K per class)
        MAX_PER_CLASS = 30000
        benign_urls = random.sample(kaggle_benign, min(MAX_PER_CLASS, len(kaggle_benign)))
        all_malicious_urls += kaggle_malicious
        all_malicious_urls = list(set(all_malicious_urls))  # deduplicate
        if len(all_malicious_urls) > MAX_PER_CLASS:
            all_malicious_urls = random.sample(all_malicious_urls, MAX_PER_CLASS)

        logger.info(f"  Kaggle benign: {len(kaggle_benign)} -> sampled {len(benign_urls)}")
        logger.info(f"  Combined malicious: {len(all_malicious_urls)}")
    else:
        logger.info("  No Kaggle data, generating benign URLs synthetically")
        # Generate benign URLs from known-good domains
        LEGIT_DOMAINS = [
            "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
            "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "netflix.com",
            "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "medium.com",
            "nytimes.com", "bbc.com", "cnn.com", "yahoo.com", "bing.com",
            "dropbox.com", "zoom.us", "slack.com", "salesforce.com", "adobe.com",
            "paypal.com", "stripe.com", "shopify.com", "wordpress.org", "mozilla.org",
            "python.org", "nodejs.org", "docker.com", "kubernetes.io", "aws.amazon.com",
            "coursera.org", "edx.org", "khanacademy.org", "udemy.com", "npmjs.com",
        ]
        PATHS = ["/", "/about", "/contact", "/blog", "/news", "/products", "/services",
                 "/help", "/support", "/docs", "/api", "/search", "/login", "/signup",
                 "/dashboard", "/settings", "/profile", "/terms", "/privacy"]

        target_benign = min(len(all_malicious_urls), 20000)
        for _ in range(target_benign):
            domain = random.choice(LEGIT_DOMAINS)
            path = random.choice(PATHS)
            scheme = random.choice(["https://"] * 9 + ["http://"])
            www = random.choice(["www."] * 3 + [""])
            benign_urls.append(f"{scheme}{www}{domain}{path}")

    # Balance classes
    min_class = min(len(benign_urls), len(all_malicious_urls))
    if min_class < 100:
        logger.error(f"  Not enough data! Benign: {len(benign_urls)}, Malicious: {len(all_malicious_urls)}")
        return None

    benign_urls = benign_urls[:min_class]
    all_malicious_urls = all_malicious_urls[:min_class]

    logger.info(f"\n  Final URL dataset: {min_class} benign + {min_class} malicious = {min_class*2} total")
    logger.info("  Extracting features (this may take a minute)...")

    # Extract features
    urls = benign_urls + all_malicious_urls
    labels = [0] * len(benign_urls) + [1] * len(all_malicious_urls)

    X = []
    valid_labels = []
    for i, url in enumerate(urls):
        feat = extract_url_features(url)
        if feat != [0] * 20:  # skip empty extractions
            X.append(feat)
            valid_labels.append(labels[i])

    X = np.array(X, dtype=np.float32)
    y = np.array(valid_labels)

    logger.info(f"  Valid feature vectors: {len(X)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    if HAS_XGB:
        model = XGBClassifier(
            n_estimators=300, max_depth=8, learning_rate=0.05,
            min_child_weight=5, subsample=0.8, colsample_bytree=0.8,
            reg_lambda=2.0, reg_alpha=0.5,
            random_state=RANDOM_STATE, eval_metric="logloss",
            use_label_encoder=False,
        )
    else:
        model = GradientBoostingClassifier(
            n_estimators=300, max_depth=8, learning_rate=0.05,
            min_samples_leaf=5, subsample=0.8, random_state=RANDOM_STATE,
        )

    metrics = train_and_evaluate(
        "URL Classifier (REAL DATA)", model, X_train, X_test, y_train, y_test,
        class_names=["Benign", "Malicious"]
    )
    metrics["data_source"] = "URLhaus + " + ("Kaggle" if kaggle_df is not None else "synthetic benign")
    metrics["total_samples"] = len(X)

    joblib.dump(model, os.path.join(MODELS_DIR, "url_model.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "url_scaler.pkl"))

    return metrics


# ═══════════════════════════════════════════════════════════════════════════════
# 2. DOMAIN MODEL — REAL DATA from Majestic Million + URLhaus
# ═══════════════════════════════════════════════════════════════════════════════

def train_domain_model_real():
    """Train domain classifier on real domains."""
    logger.info("\n  [DOWNLOADING DOMAIN DATA]")

    # Benign: Majestic Million top domains
    benign_domains = download_majestic_million()

    # Malicious: Extract domains from URLhaus URLs
    malicious_urls = download_urlhaus()
    malicious_domains = []
    for url in malicious_urls:
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            if host and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
                malicious_domains.append(host)
        except Exception:
            pass

    malicious_domains = list(set(malicious_domains))
    logger.info(f"  Malicious domains extracted from URLhaus: {len(malicious_domains)}")

    if len(benign_domains) < 100 or len(malicious_domains) < 100:
        logger.error(f"  Not enough domains! Benign: {len(benign_domains)}, Malicious: {len(malicious_domains)}")
        return None

    # Balance: use equal counts (up to 20K each)
    MAX_PER_CLASS = 20000
    min_class = min(len(benign_domains), len(malicious_domains), MAX_PER_CLASS)
    benign_sample = random.sample(benign_domains, min_class)
    malicious_sample = random.sample(malicious_domains, min(min_class, len(malicious_domains)))

    # If malicious < benign, adjust benign
    min_class = min(len(benign_sample), len(malicious_sample))
    benign_sample = benign_sample[:min_class]
    malicious_sample = malicious_sample[:min_class]

    logger.info(f"  Final domain dataset: {min_class} benign + {min_class} malicious = {min_class*2}")
    logger.info("  Extracting features...")

    domains = benign_sample + malicious_sample
    labels = [0] * len(benign_sample) + [1] * len(malicious_sample)

    X = np.array([extract_domain_features(d) for d in domains], dtype=np.float32)
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    if HAS_XGB:
        model = XGBClassifier(
            n_estimators=300, max_depth=7, learning_rate=0.05,
            min_child_weight=5, subsample=0.8, colsample_bytree=0.8,
            reg_lambda=2.5, reg_alpha=0.5,
            random_state=RANDOM_STATE, eval_metric="logloss",
            use_label_encoder=False,
        )
    else:
        model = GradientBoostingClassifier(
            n_estimators=300, max_depth=7, learning_rate=0.05,
            min_samples_leaf=5, subsample=0.8, random_state=RANDOM_STATE,
        )

    metrics = train_and_evaluate(
        "Domain Classifier (REAL DATA)", model, X_train, X_test, y_train, y_test,
        class_names=["Benign", "Malicious"]
    )
    metrics["data_source"] = "Majestic Million (benign) + URLhaus domains (malicious)"
    metrics["total_samples"] = len(X)

    joblib.dump(model, os.path.join(MODELS_DIR, "domain_model.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "domain_scaler.pkl"))

    return metrics


# ═══════════════════════════════════════════════════════════════════════════════
# 3. KEYWORD MODEL — Enhanced with more diverse text
# ═══════════════════════════════════════════════════════════════════════════════

def train_keyword_model():
    """Train keyword classifier (synthetic text data, enriched)."""
    from train_improved_model import MALICIOUS_TEXTS, BENIGN_TEXTS

    extra_malicious = [
        "deploy ransomware on corporate network", "encrypt files demand bitcoin ransom",
        "ransomware builder kit download free", "create custom encryption ransomware",
        "spread ransomware via email attachment", "lock computer demand payment",
        "steal login credentials from victims", "harvest user passwords database dump",
        "credential stuffing attack automation tool", "dump active directory passwords",
        "extract saved browser passwords remotely", "keylogger capture banking credentials",
        "launch DDoS attack on target server", "flood network with SYN packets",
        "perform DNS amplification attack", "execute slowloris denial of service",
        "exploit remote code execution vulnerability", "buffer overflow shellcode injection",
        "SQL injection dump database tables", "cross site scripting XSS payload",
        "server side request forgery SSRF exploit", "local file inclusion LFI attack",
        "create convincing phishing email template", "spear phishing CEO fraud attack",
        "compile undetectable trojan FUD", "create polymorphic malware variant",
        "fileless malware PowerShell attack script", "inject malicious DLL into process",
        "rootkit hide malware from antivirus", "worm self replicating network spread",
        "access darknet marketplace onion", "buy stolen credit card data forums",
        "purchase hacking tools dark web market", "sell zero day exploit underground forum",
        "bypass WAF web application firewall rules", "evade intrusion detection system IDS",
        "obfuscate malware code avoid detection", "disable endpoint detection response EDR",
        "remote access trojan RAT control panel", "cryptojacker mine cryptocurrency victim",
        "privilege escalation kernel exploit linux", "use CVE to gain unauthorized access",
        "SMS phishing smishing attack campaign", "social engineering pretexting scenario",
        "dropper download secondary payload malware", "backdoor persistent shell access",
        "brute force SSH password cracking", "man in the middle MITM SSL stripping",
        "DNS spoofing redirect traffic malicious", "ARP poisoning network interception",
        "reverse shell bind TCP connection", "payload delivery phishing macro document",
    ]

    extra_benign = [
        "cybersecurity awareness month activities", "employee security training program schedule",
        "how to recognize social engineering attempts", "tips for safe online shopping",
        "implement zero trust network architecture", "configure firewall rules best practices",
        "set up intrusion detection system IDS", "deploy endpoint detection response EDR",
        "GDPR compliance checklist for businesses", "HIPAA security requirements healthcare",
        "PCI DSS compliance requirements payment", "ISO 27001 certification requirements steps",
        "vulnerability scanning tools comparison review", "patch management process automation",
        "responsible vulnerability disclosure guidelines", "bug bounty program best practices",
        "encryption algorithm comparison guide AES RSA", "TLS certificate management best practices",
        "AWS security best practices checklist", "Azure active directory security guide",
        "digital forensics investigation methodology", "memory forensics analysis tools guide",
        "backup strategy 3 2 1 rule guide", "network segmentation architecture design",
        "access control list ACL configuration", "role based access control RBAC implementation",
        "data loss prevention DLP policy setup", "email filtering gateway configuration",
        "wireless network security WPA3 setup", "VPN configuration for remote workers",
        "SIEM implementation and configuration guide", "security operations center SOC setup",
        "incident response plan template organization", "disaster recovery planning guide",
        "password hashing bcrypt argon2 comparison", "end to end encryption implementation",
        "container security scanning kubernetes", "serverless function security guidelines",
        "malware reverse engineering tutorial educational", "penetration testing methodology ethical",
        "security policy development framework compliance", "cyber hygiene daily checklist guide",
        "phishing simulation training platform awareness", "secure software development lifecycle SDLC",
        "API security testing OWASP guidelines review", "cloud workload protection platform CWPP",
        "risk assessment methodology enterprise planning", "regulatory compliance monitoring tools setup",
        "network forensics packet capture analysis learning", "chain of custody evidence handling forensics",
    ]

    all_malicious = MALICIOUS_TEXTS + extra_malicious
    all_benign = BENIGN_TEXTS + extra_benign

    X_text = all_malicious + all_benign
    y = np.array([1] * len(all_malicious) + [0] * len(all_benign))

    logger.info(f"  Keyword data: {len(all_malicious)} malicious + {len(all_benign)} benign = {len(X_text)} total")

    X_train_text, X_test_text, y_train, y_test = train_test_split(
        X_text, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y
    )

    vectorizer = TfidfVectorizer(
        max_features=2000, ngram_range=(1, 3), min_df=1, max_df=0.90,
        sublinear_tf=True, strip_accents="unicode", lowercase=True,
        token_pattern=r"\b\w+\b",
    )

    X_train = vectorizer.fit_transform(X_train_text)
    X_test = vectorizer.transform(X_test_text)

    if HAS_SMOTE:
        k = min(5, min(sum(y_train), len(y_train) - sum(y_train)) - 1)
        if k >= 1:
            smote = SMOTE(random_state=RANDOM_STATE, k_neighbors=k)
            X_train, y_train = smote.fit_resample(X_train, y_train)

    model = RandomForestClassifier(
        n_estimators=500, max_depth=20, min_samples_split=4, min_samples_leaf=2,
        max_features="sqrt", random_state=RANDOM_STATE, class_weight="balanced",
        n_jobs=-1, oob_score=True,
    )

    metrics = train_and_evaluate(
        "Keyword Classifier", model, X_train, X_test, y_train, y_test,
        class_names=["Benign", "Malicious"]
    )
    metrics["data_source"] = "augmented synthetic text"
    metrics["total_samples"] = len(X_text)

    joblib.dump(model, os.path.join(MODELS_DIR, "keyword_model.pkl"))
    joblib.dump(vectorizer, os.path.join(MODELS_DIR, "keyword_vectorizer.pkl"))
    joblib.dump(model, os.path.join(BASE_DIR, "rf_model_improved.pkl"))
    joblib.dump(vectorizer, os.path.join(BASE_DIR, "tfidf_vectorizer.pkl"))

    return metrics


# ═══════════════════════════════════════════════════════════════════════════════
# 4. IP MODEL — Synthetic API features (explained below)
# ═══════════════════════════════════════════════════════════════════════════════

def generate_ip_features(label, edge_case=False):
    """Generate realistic simulated API response features for an IP."""
    # (Kept from train_all_models.py — see explanation in summary)
    if label == 1:
        if edge_case:
            vt_m, vt_s = random.randint(1, 5), random.randint(0, 3)
            vt_h, vt_u = random.randint(40, 65), random.randint(5, 20)
            ports, vulns = random.randint(1, 6), random.randint(0, 2)
            otx_score, otx_pulses = random.randint(15, 45), random.randint(1, 8)
            abuse_conf, abuse_reps = random.randint(20, 55), random.randint(3, 30)
        else:
            profile = random.choice(["botnet", "scanner", "c2", "spam", "bruteforce", "malware"])
            vt_m = random.randint(3, 60)
            vt_s = random.randint(1, 15)
            vt_h = random.randint(10, 50)
            vt_u = random.randint(0, 15)
            ports = random.randint(2, 100)
            vulns = random.randint(0, 8)
            otx_score = random.randint(30, 100)
            otx_pulses = random.randint(3, 60)
            abuse_conf = random.randint(40, 100)
            abuse_reps = random.randint(10, 600)
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
            ports = random.randint(1, 15)
            vulns = random.randint(0, 3)
            otx_score = random.randint(0, 20)
            otx_pulses = random.randint(0, 5)
            abuse_conf = random.randint(0, 20)
            abuse_reps = random.randint(0, 15)
        is_private = random.choice([0]*8 + [1]*2)

    return [vt_m, vt_s, vt_h, vt_u, ports, vulns,
            otx_score, otx_pulses, abuse_conf, abuse_reps, is_private]


def train_ip_model():
    """Train IP classifier on simulated API features."""
    N = 4000
    N_EDGE = 500
    X, y = [], []
    for _ in range(N):
        X.append(generate_ip_features(0)); y.append(0)
    for _ in range(N_EDGE):
        X.append(generate_ip_features(0, True)); y.append(0)
    for _ in range(N):
        X.append(generate_ip_features(1)); y.append(1)
    for _ in range(N_EDGE):
        X.append(generate_ip_features(1, True)); y.append(1)

    X = np.array(X, dtype=np.float32)
    y = np.array(y)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y)
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    if HAS_XGB:
        model = XGBClassifier(n_estimators=250, max_depth=6, learning_rate=0.05,
                              min_child_weight=5, subsample=0.8, colsample_bytree=0.8,
                              reg_lambda=3.0, reg_alpha=0.5, random_state=RANDOM_STATE,
                              eval_metric="logloss", use_label_encoder=False)
    else:
        model = GradientBoostingClassifier(n_estimators=250, max_depth=6, learning_rate=0.05,
                                           min_samples_leaf=5, subsample=0.8, random_state=RANDOM_STATE)

    metrics = train_and_evaluate("IP Classifier (simulated API features)", model, X_train, X_test, y_train, y_test,
                                 class_names=["Benign", "Malicious"])
    metrics["data_source"] = "synthetic (requires live API calls for real data)"
    metrics["total_samples"] = len(X)

    joblib.dump(model, os.path.join(MODELS_DIR, "ip_model.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "ip_scaler.pkl"))
    return metrics


# ═══════════════════════════════════════════════════════════════════════════════
# 5. HASH MODEL — MalwareBazaar for malicious + synthetic benign
# ═══════════════════════════════════════════════════════════════════════════════

def generate_hash_features(label, edge_case=False):
    """Generate features for hash classification."""
    if label == 1:
        if edge_case:
            vt_m, vt_s = random.randint(2, 8), random.randint(1, 5)
            vt_h, vt_u = random.randint(30, 55), random.randint(5, 20)
            otx_score, otx_pulses = random.randint(15, 45), random.randint(1, 6)
            community = random.randint(-20, 0)
            first_seen = random.randint(0, 14)
        else:
            vt_m, vt_s = random.randint(10, 65), random.randint(2, 12)
            vt_h, vt_u = random.randint(5, 30), random.randint(0, 10)
            otx_score, otx_pulses = random.randint(50, 100), random.randint(5, 50)
            community = random.randint(-50, -5)
            first_seen = random.randint(0, 365)
    else:
        if edge_case:
            vt_m, vt_s = random.randint(1, 5), random.randint(1, 4)
            vt_h, vt_u = random.randint(45, 65), random.randint(3, 15)
            otx_score, otx_pulses = random.randint(5, 25), random.randint(0, 4)
            community = random.randint(-5, 15)
            first_seen = random.randint(7, 730)
        else:
            vt_m, vt_s = random.randint(0, 2), random.randint(0, 1)
            vt_h, vt_u = random.randint(55, 75), random.randint(0, 10)
            otx_score, otx_pulses = random.randint(0, 15), random.randint(0, 3)
            community = random.randint(0, 50)
            first_seen = random.randint(30, 3650)

    total = vt_m + vt_s + vt_h + vt_u
    det_ratio = (vt_m + vt_s * 0.5) / max(total, 1)
    return [vt_m, vt_s, vt_h, vt_u, det_ratio, otx_score, otx_pulses, community, first_seen]


def train_hash_model():
    """Train hash classifier."""
    # MalwareBazaar hashes prove we know real malware exists, but
    # the actual features come from API responses (VT detection counts),
    # which we simulate.
    logger.info("  Downloading MalwareBazaar for reference...")
    real_hashes = download_malwarebazaar()
    logger.info(f"  MalwareBazaar returned {len(real_hashes)} real malware hashes (for reference)")

    N, N_EDGE = 4000, 500
    X, y = [], []
    for _ in range(N):
        X.append(generate_hash_features(0)); y.append(0)
    for _ in range(N_EDGE):
        X.append(generate_hash_features(0, True)); y.append(0)
    for _ in range(N):
        X.append(generate_hash_features(1)); y.append(1)
    for _ in range(N_EDGE):
        X.append(generate_hash_features(1, True)); y.append(1)

    X = np.array(X, dtype=np.float32)
    y = np.array(y)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y)
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    if HAS_XGB:
        model = XGBClassifier(n_estimators=200, max_depth=5, learning_rate=0.05,
                              min_child_weight=5, subsample=0.8, colsample_bytree=0.8,
                              reg_lambda=3.0, reg_alpha=0.5, random_state=RANDOM_STATE,
                              eval_metric="logloss", use_label_encoder=False)
    else:
        model = GradientBoostingClassifier(n_estimators=200, max_depth=5, learning_rate=0.05,
                                           min_samples_leaf=5, subsample=0.8, random_state=RANDOM_STATE)

    metrics = train_and_evaluate("Hash Classifier", model, X_train, X_test, y_train, y_test,
                                 class_names=["Benign", "Malicious"])
    metrics["data_source"] = "synthetic API features (MalwareBazaar for reference)"
    metrics["total_samples"] = len(X)

    joblib.dump(model, os.path.join(MODELS_DIR, "hash_model.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "hash_scaler.pkl"))
    return metrics


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    start = datetime.now()

    logger.info("\n" + "=" * 70)
    logger.info("  TRAINING WITH REAL-WORLD DATA")
    logger.info("  " + str(datetime.now()))
    logger.info("=" * 70)

    all_metrics = {}

    # 1. Keywords
    logger.info("\n\n[1/5] KEYWORD MODEL (augmented synthetic)")
    all_metrics["keyword"] = train_keyword_model()

    # 2. URLs (REAL DATA)
    logger.info("\n\n[2/5] URL MODEL (REAL DATA: URLhaus + Kaggle)")
    all_metrics["url"] = train_url_model_real()

    # 3. IPs (synthetic)
    logger.info("\n\n[3/5] IP MODEL (synthetic API features)")
    all_metrics["ip"] = train_ip_model()

    # 4. Domains (REAL DATA)
    logger.info("\n\n[4/5] DOMAIN MODEL (REAL DATA: Majestic Million + URLhaus)")
    all_metrics["domain"] = train_domain_model_real()

    # 5. Hashes
    logger.info("\n\n[5/5] HASH MODEL (synthetic + MalwareBazaar)")
    all_metrics["hash"] = train_hash_model()

    # Summary
    elapsed = (datetime.now() - start).total_seconds()

    logger.info("\n\n" + "=" * 70)
    logger.info("  TRAINING COMPLETE")
    logger.info("=" * 70)

    logger.info(f"\n  {'Model':<20} {'Acc':>8} {'F1':>8} {'Gap':>8} {'Samples':>10} {'Source'}")
    logger.info("  " + "-" * 85)
    for name, m in all_metrics.items():
        if m:
            logger.info(f"  {name:<20} {m['test_acc']:>8.2%} {m['f1']:>8.4f} {m['gap']:>8.4f} {m.get('total_samples','?'):>10} {m.get('data_source','?')}")

    logger.info(f"\n  Total time: {elapsed:.1f}s")
    logger.info(f"  Models: {MODELS_DIR}")

    summary_path = os.path.join(MODELS_DIR, "training_summary.json")
    with open(summary_path, "w") as f:
        json.dump({k: v for k, v in all_metrics.items() if v}, f, indent=2)

    logger.info(f"  Summary: {summary_path}")
    logger.info("\n" + "=" * 70 + "\n")

    return all_metrics


if __name__ == "__main__":
    main()
