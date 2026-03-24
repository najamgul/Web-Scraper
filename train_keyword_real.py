"""
train_keyword_real.py
=====================
Train keyword classifier on REAL-WORLD text datasets from Kaggle + public sources.

Datasets downloaded:
  1. ramoliyafenil/text-based-cyber-threat-detection   → Cyber threat text classification
  2. hussainsheikh03/nlp-based-cyber-security-dataset  → NLP cybersecurity dataset
  3. akshatsharma2/the-biggest-spam-ham-phish-email-dataset-300000 → 300K emails
  4. naserabdullahalam/phishing-email-dataset           → Phishing emails
  5. tapakah68/spam-text-messages-dataset               → Spam SMS messages
  6. uciml/sms-spam-collection-dataset                  → UCI SMS spam
  7. kuladeep19/phishing-and-legitimate-emails-dataset  → Phish vs legit emails
  8. subhajournal/phishingemails                        → Phishing email collection
  + MITRE ATT&CK technique descriptions (free, no API)
  + NVD CVE vulnerability descriptions (free, no API)
  + Our existing hand-crafted cybersecurity text samples
"""

import os, sys, json, re, random, warnings, logging, glob, zipfile
import numpy as np
import pandas as pd
import joblib
import requests

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:
    pass

# Set up Kaggle credentials
def _setup_kaggle():
    kaggle_dir = os.path.join(os.path.expanduser("~"), ".kaggle")
    kaggle_json = os.path.join(kaggle_dir, "kaggle.json")
    if os.path.exists(kaggle_json):
        return
    username = os.environ.get("KAGGLE_USERNAME", "")
    key = os.environ.get("KAGGLE_KEY", "") or os.environ.get("KAGGLE_API_TOKEN", "")
    if username and key:
        os.makedirs(kaggle_dir, exist_ok=True)
        with open(kaggle_json, "w") as f:
            json.dump({"username": username, "key": key}, f)

_setup_kaggle()

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

try:
    from imblearn.over_sampling import SMOTE
    HAS_SMOTE = True
except ImportError:
    HAS_SMOTE = False

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.StreamHandler(sys.stdout)])
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
# KAGGLE DATASET DOWNLOADER
# ═══════════════════════════════════════════════════════════════════════════════

def download_kaggle_dataset(dataset_ref, dest_subdir):
    """Download a Kaggle dataset. Returns path to extracted folder."""
    dest = os.path.join(DATA_DIR, dest_subdir)
    if os.path.exists(dest) and len(os.listdir(dest)) > 0:
        logger.info(f"  ✓ {dataset_ref} already downloaded")
        return dest

    try:
        from kaggle.api.kaggle_api_extended import KaggleApi
        api = KaggleApi()
        api.authenticate()
        os.makedirs(dest, exist_ok=True)
        logger.info(f"  ↓ Downloading {dataset_ref}...")
        api.dataset_download_files(dataset_ref, path=dest, unzip=True)
        files = os.listdir(dest)
        logger.info(f"  ✓ Downloaded {dataset_ref}: {len(files)} files")
        return dest
    except Exception as e:
        logger.warning(f"  ✗ Failed to download {dataset_ref}: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# DATASET PARSERS — Each returns (texts, labels) where 1=malicious, 0=benign
# ═══════════════════════════════════════════════════════════════════════════════

def clean_text(text):
    """Clean email/message text for TF-IDF."""
    if not isinstance(text, str):
        return ""
    text = re.sub(r'<[^>]+>', ' ', text)  # strip HTML
    text = re.sub(r'http\S+', '', text)   # strip URLs
    text = re.sub(r'[^\w\s]', ' ', text)  # strip special chars
    text = re.sub(r'\s+', ' ', text).strip()
    return text.lower()


def parse_cyber_threat_detection(path):
    """Parse ramoliyafenil/text-based-cyber-threat-detection"""
    texts, labels = [], []
    if not path:
        return texts, labels
    for f in glob.glob(os.path.join(path, "*.csv")):
        try:
            df = pd.read_csv(f, encoding='utf-8', on_bad_lines='skip')
            # Look for text and label columns
            text_cols = [c for c in df.columns if any(x in c.lower() for x in ['text', 'content', 'message', 'description', 'tweet'])]
            label_cols = [c for c in df.columns if any(x in c.lower() for x in ['label', 'class', 'type', 'category', 'target'])]
            if text_cols and label_cols:
                tc, lc = text_cols[0], label_cols[0]
                for _, row in df.iterrows():
                    t = clean_text(str(row[tc]))
                    if len(t) > 10:
                        lab = str(row[lc]).lower().strip()
                        if lab in ['1', 'malicious', 'threat', 'attack', 'spam', 'phishing', 'positive', 'yes', 'true']:
                            texts.append(t); labels.append(1)
                        elif lab in ['0', 'benign', 'safe', 'normal', 'ham', 'legitimate', 'negative', 'no', 'false']:
                            texts.append(t); labels.append(0)
        except Exception as e:
            logger.warning(f"    Error parsing {f}: {e}")
    logger.info(f"    Cyber threat detection: {len(texts)} samples ({sum(labels)} malicious, {len(labels)-sum(labels)} benign)")
    return texts, labels


def parse_nlp_cybersecurity(path):
    """Parse hussainsheikh03/nlp-based-cyber-security-dataset"""
    texts, labels = [], []
    if not path:
        return texts, labels
    for f in glob.glob(os.path.join(path, "**/*.csv"), recursive=True):
        try:
            df = pd.read_csv(f, encoding='utf-8', on_bad_lines='skip')
            text_cols = [c for c in df.columns if any(x in c.lower() for x in ['text', 'content', 'message', 'description', 'tweet', 'sentence'])]
            label_cols = [c for c in df.columns if any(x in c.lower() for x in ['label', 'class', 'type', 'category', 'target'])]
            if text_cols and label_cols:
                tc, lc = text_cols[0], label_cols[0]
                for _, row in df.iterrows():
                    t = clean_text(str(row[tc]))
                    if len(t) > 10:
                        lab = str(row[lc]).lower().strip()
                        if any(x in lab for x in ['malicious', 'threat', 'attack', 'spam', 'phish', '1', 'positive', 'cyber']):
                            texts.append(t); labels.append(1)
                        elif any(x in lab for x in ['benign', 'safe', 'normal', 'ham', 'legit', '0', 'negative', 'non']):
                            texts.append(t); labels.append(0)
        except Exception as e:
            logger.warning(f"    Error parsing {f}: {e}")
    logger.info(f"    NLP cybersecurity: {len(texts)} samples ({sum(labels)} mal, {len(labels)-sum(labels)} ben)")
    return texts, labels


def parse_spam_email_300k(path):
    """Parse akshatsharma2/the-biggest-spam-ham-phish-email-dataset-300000"""
    texts, labels = [], []
    if not path:
        return texts, labels
    for f in glob.glob(os.path.join(path, "**/*.csv"), recursive=True):
        try:
            df = pd.read_csv(f, encoding='utf-8', on_bad_lines='skip', nrows=100000)
            for col_pair in [('text', 'label'), ('body', 'label'), ('content', 'type'),
                             ('email_text', 'label'), ('Message', 'Category')]:
                tc = [c for c in df.columns if col_pair[0].lower() in c.lower()]
                lc = [c for c in df.columns if col_pair[1].lower() in c.lower()]
                if tc and lc:
                    tc, lc = tc[0], lc[0]
                    sample = df.sample(min(50000, len(df)), random_state=RANDOM_STATE)
                    for _, row in sample.iterrows():
                        t = clean_text(str(row[tc]))
                        if len(t) > 15:
                            lab = str(row[lc]).lower().strip()
                            if any(x in lab for x in ['spam', 'phish', 'malicious', '1', 'scam', 'fraud']):
                                texts.append(t); labels.append(1)
                            elif any(x in lab for x in ['ham', 'legit', 'safe', 'benign', '0', 'normal']):
                                texts.append(t); labels.append(0)
                    break
        except Exception as e:
            logger.warning(f"    Error parsing {f}: {e}")
    logger.info(f"    300K emails: {len(texts)} samples ({sum(labels)} mal, {len(labels)-sum(labels)} ben)")
    return texts, labels


def parse_phishing_emails(path):
    """Parse naserabdullahalam/phishing-email-dataset"""
    texts, labels = [], []
    if not path:
        return texts, labels
    for f in glob.glob(os.path.join(path, "**/*.csv"), recursive=True):
        try:
            df = pd.read_csv(f, encoding='utf-8', on_bad_lines='skip')
            text_cols = [c for c in df.columns if any(x in c.lower() for x in ['text', 'body', 'content', 'email', 'message', 'subject'])]
            label_cols = [c for c in df.columns if any(x in c.lower() for x in ['label', 'class', 'type', 'category', 'phishing'])]
            if text_cols and label_cols:
                tc, lc = text_cols[0], label_cols[0]
                for _, row in df.iterrows():
                    t = clean_text(str(row[tc]))
                    if len(t) > 15:
                        lab = str(row[lc]).lower().strip()
                        if any(x in lab for x in ['phish', 'spam', 'malicious', '1', 'yes', 'true', 'scam']):
                            texts.append(t); labels.append(1)
                        elif any(x in lab for x in ['legit', 'ham', 'safe', 'benign', '0', 'no', 'false', 'normal']):
                            texts.append(t); labels.append(0)
        except Exception as e:
            logger.warning(f"    Error parsing {f}: {e}")
    logger.info(f"    Phishing emails: {len(texts)} samples ({sum(labels)} mal, {len(labels)-sum(labels)} ben)")
    return texts, labels


def parse_sms_spam(path):
    """Parse tapakah68/spam-text-messages-dataset or uciml/sms-spam-collection-dataset"""
    texts, labels = [], []
    if not path:
        return texts, labels
    for f in glob.glob(os.path.join(path, "**/*.csv"), recursive=True):
        try:
            # Try different encodings and separators
            for enc in ['utf-8', 'latin-1', 'cp1252']:
                for sep in [',', '\t']:
                    try:
                        df = pd.read_csv(f, encoding=enc, sep=sep, on_bad_lines='skip')
                        if len(df.columns) >= 2:
                            break
                    except Exception:
                        continue
                else:
                    continue
                break

            if len(df.columns) >= 2:
                # Common formats: (label, text) or (text, label)
                col0_vals = df.iloc[:, 0].astype(str).str.lower().unique()
                if any(x in str(col0_vals) for x in ['spam', 'ham']):
                    lc, tc = df.columns[0], df.columns[1]
                else:
                    tc, lc = df.columns[0], df.columns[1]

                text_cols = [c for c in df.columns if any(x in c.lower() for x in ['message', 'text', 'content', 'sms'])]
                label_cols = [c for c in df.columns if any(x in c.lower() for x in ['label', 'category', 'class', 'type'])]
                if text_cols:
                    tc = text_cols[0]
                if label_cols:
                    lc = label_cols[0]

                for _, row in df.iterrows():
                    t = clean_text(str(row[tc]))
                    if len(t) > 10:
                        lab = str(row[lc]).lower().strip()
                        if 'spam' in lab or lab == '1':
                            texts.append(t); labels.append(1)
                        elif 'ham' in lab or lab == '0':
                            texts.append(t); labels.append(0)
        except Exception as e:
            logger.warning(f"    Error parsing {f}: {e}")
    logger.info(f"    SMS spam: {len(texts)} samples ({sum(labels)} spam, {len(labels)-sum(labels)} ham)")
    return texts, labels


def parse_generic_csv(path, dataset_name="generic"):
    """Generic parser for email/text CSV datasets."""
    texts, labels = [], []
    if not path:
        return texts, labels
    for f in glob.glob(os.path.join(path, "**/*.csv"), recursive=True):
        try:
            df = pd.read_csv(f, encoding='utf-8', on_bad_lines='skip', nrows=100000)
            text_cols = [c for c in df.columns if any(x in c.lower() for x in
                        ['text', 'body', 'content', 'email', 'message', 'subject', 'description', 'sentence'])]
            label_cols = [c for c in df.columns if any(x in c.lower() for x in
                         ['label', 'class', 'type', 'category', 'target', 'spam', 'phishing', 'is_'])]
            if not text_cols or not label_cols:
                # Try first two columns
                if len(df.columns) >= 2:
                    text_cols = [df.columns[-1]]  # last col usually text
                    label_cols = [df.columns[0]]  # first col usually label
                else:
                    continue

            tc, lc = text_cols[0], label_cols[0]
            unique_labels = df[lc].astype(str).str.lower().str.strip().unique()
            logger.info(f"    File {os.path.basename(f)}: cols={df.columns.tolist()}, labels={unique_labels[:10]}")

            for _, row in df.iterrows():
                t = clean_text(str(row[tc]))
                if len(t) > 10:
                    lab = str(row[lc]).lower().strip()
                    if any(x in lab for x in ['spam', 'phish', 'malicious', '1', 'yes', 'true', 'scam', 'fraud', 'threat', 'attack']):
                        texts.append(t); labels.append(1)
                    elif any(x in lab for x in ['ham', 'legit', 'safe', 'benign', '0', 'no', 'false', 'normal', 'not']):
                        texts.append(t); labels.append(0)
        except Exception as e:
            logger.warning(f"    Error parsing {f}: {e}")
    logger.info(f"    {dataset_name}: {len(texts)} samples ({sum(labels)} mal, {len(labels)-sum(labels)} ben)")
    return texts, labels


# ═══════════════════════════════════════════════════════════════════════════════
# FREE PUBLIC DATA (no API key needed)
# ═══════════════════════════════════════════════════════════════════════════════

def download_mitre_attack():
    """Download MITRE ATT&CK technique descriptions (malicious context)."""
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    dest = os.path.join(DATA_DIR, "mitre_attack.json")
    texts = []

    if not os.path.exists(dest):
        logger.info("  ↓ Downloading MITRE ATT&CK framework...")
        try:
            r = requests.get(url, timeout=60)
            r.raise_for_status()
            with open(dest, 'wb') as f:
                f.write(r.content)
            logger.info(f"  ✓ MITRE ATT&CK: {len(r.content)/1024/1024:.1f} MB")
        except Exception as e:
            logger.warning(f"  ✗ MITRE download failed: {e}")
            return texts
    else:
        logger.info("  ✓ MITRE ATT&CK already downloaded")

    try:
        with open(dest, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for obj in data.get('objects', []):
            if obj.get('type') in ['attack-pattern', 'malware', 'tool']:
                desc = obj.get('description', '')
                name = obj.get('name', '')
                if desc and len(desc) > 20:
                    # Clean markdown
                    desc = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', desc)
                    desc = re.sub(r'<[^>]+>', '', desc)
                    # Take first 500 chars to keep it focused
                    texts.append(clean_text(desc[:500]))
                if name:
                    texts.append(clean_text(name))
        logger.info(f"  MITRE ATT&CK: {len(texts)} attack technique descriptions")
    except Exception as e:
        logger.warning(f"  Error parsing MITRE: {e}")

    return texts


def download_nvd_cves():
    """Download recent CVE descriptions from NVD (malicious context)."""
    texts = []
    dest = os.path.join(DATA_DIR, "nvd_cves.json")

    if os.path.exists(dest):
        logger.info("  ✓ NVD CVEs already downloaded")
    else:
        logger.info("  ↓ Downloading NVD CVE descriptions...")
        all_cves = []
        # Download in batches (NVD API allows 2000 per request)
        for start in range(0, 10000, 2000):
            try:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&startIndex={start}"
                r = requests.get(url, timeout=60, headers={'Accept': 'application/json'})
                if r.status_code == 200:
                    data = r.json()
                    vulns = data.get('vulnerabilities', [])
                    all_cves.extend(vulns)
                    logger.info(f"    Batch {start//2000 + 1}: {len(vulns)} CVEs")
                    if len(vulns) < 2000:
                        break
                else:
                    logger.warning(f"    NVD API returned {r.status_code}")
                    break
                import time; time.sleep(2)  # Rate limit
            except Exception as e:
                logger.warning(f"    NVD batch error: {e}")
                break

        if all_cves:
            with open(dest, 'w') as f:
                json.dump(all_cves, f)
            logger.info(f"  ✓ NVD: Saved {len(all_cves)} CVEs")

    # Parse
    try:
        if os.path.exists(dest):
            with open(dest, 'r', encoding='utf-8') as f:
                cves = json.load(f)
            for cve in cves:
                try:
                    descs = cve.get('cve', {}).get('descriptions', [])
                    for d in descs:
                        if d.get('lang') == 'en':
                            t = clean_text(d.get('value', ''))
                            if len(t) > 20:
                                texts.append(t)
                except Exception:
                    pass
            logger.info(f"  NVD CVEs: {len(texts)} vulnerability descriptions")
    except Exception as e:
        logger.warning(f"  Error parsing NVD: {e}")

    return texts


def get_benign_tech_texts():
    """Generate benign technology/security education texts."""
    benign_texts = [
        # General tech
        "cloud computing enables businesses to scale infrastructure dynamically",
        "machine learning algorithms improve with more training data over time",
        "agile methodology emphasizes iterative development and customer feedback",
        "version control systems like git help teams collaborate on code",
        "containerization with docker simplifies application deployment",
        "microservices architecture breaks applications into smaller services",
        "continuous integration automates testing and code quality checks",
        "database indexing improves query performance significantly",
        "load balancing distributes traffic across multiple servers",
        "API design should follow RESTful principles for consistency",
        # Security education
        "multi factor authentication adds an extra layer of security to accounts",
        "regular software updates patch known security vulnerabilities",
        "strong passwords should contain uppercase lowercase numbers and symbols",
        "security awareness training helps employees identify social engineering",
        "encrypting data at rest and in transit protects sensitive information",
        "network segmentation limits lateral movement in case of a breach",
        "backup your data regularly using the three two one backup strategy",
        "implement least privilege access control for all user accounts",
        "security information and event management SIEM centralizes logging",
        "vulnerability scanning should be performed on a regular schedule",
        "incident response plans should be tested through tabletop exercises",
        "zero trust architecture assumes no user or device should be trusted by default",
        "endpoint detection and response EDR monitors devices for threats",
        "data loss prevention DLP policies help protect sensitive information",
        "web application firewalls WAF protect against common web attacks",
        "penetration testing identifies vulnerabilities before attackers do",
        "security operations center SOC monitors threats around the clock",
        "certificate management ensures TLS certificates are renewed on time",
        "secure software development lifecycle integrates security into every phase",
        "compliance frameworks like SOC2 help organizations meet security standards",
        # General communication
        "please review the attached document and provide your feedback",
        "the meeting has been rescheduled to next tuesday at two pm",
        "congratulations on the successful project launch this quarter",
        "the quarterly report shows positive growth in all departments",
        "thank you for attending the conference and sharing your insights",
        "our new product launch is scheduled for the first quarter",
        "the team building event was a great success this year",
        "please complete the employee satisfaction survey by friday",
        "the office will be closed for the holiday next monday",
        "welcome aboard we are excited to have you join our team",
        "customer satisfaction scores have improved by fifteen percent",
        "the new office space will be ready for occupancy next month",
        "annual performance reviews will begin in the second week of january",
        "the company picnic is scheduled for the last saturday of july",
        "registration is now open for the annual technology conference",
    ]
    return benign_texts


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN TRAINING
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    logger.info("\n" + "=" * 70)
    logger.info("  KEYWORD MODEL — REAL DATA TRAINING PIPELINE")
    logger.info("=" * 70)

    all_texts = []
    all_labels = []

    # ─── KAGGLE DATASETS ──────────────────────────────────────────────────
    kaggle_datasets = [
        ("ramoliyafenil/text-based-cyber-threat-detection", "cyber_threat_text", parse_cyber_threat_detection),
        ("hussainsheikh03/nlp-based-cyber-security-dataset", "nlp_cybersecurity", parse_nlp_cybersecurity),
        ("akshatsharma2/the-biggest-spam-ham-phish-email-dataset-300000", "spam_300k", parse_spam_email_300k),
        ("naserabdullahalam/phishing-email-dataset", "phishing_emails", parse_phishing_emails),
        ("tapakah68/spam-text-messages-dataset", "spam_sms_tapakah", parse_sms_spam),
        ("uciml/sms-spam-collection-dataset", "sms_spam_uci", parse_sms_spam),
        ("kuladeep19/phishing-and-legitimate-emails-dataset", "phish_legit_emails", parse_generic_csv),
        ("subhajournal/phishingemails", "phish_emails_subha", parse_generic_csv),
        ("charlottehall/phishing-email-data-by-type", "phish_by_type", parse_generic_csv),
        ("devildyno/email-spam-or-not-classification", "email_spam_class", parse_generic_csv),
    ]

    logger.info(f"\n  Downloading {len(kaggle_datasets)} Kaggle datasets...")
    for i, (ref, subdir, parser) in enumerate(kaggle_datasets, 1):
        logger.info(f"\n  [{i}/{len(kaggle_datasets)}] {ref}")
        path = download_kaggle_dataset(ref, subdir)
        texts, labels = parser(path)
        if texts:
            all_texts.extend(texts)
            all_labels.extend(labels)
            logger.info(f"    → Running total: {len(all_texts)} samples")

    # ─── FREE PUBLIC DATA ──────────────────────────────────────────────────
    logger.info(f"\n\n  Downloading free public datasets...")

    # MITRE ATT&CK (all malicious context)
    mitre_texts = download_mitre_attack()
    all_texts.extend(mitre_texts)
    all_labels.extend([1] * len(mitre_texts))

    # NVD CVEs (all malicious/vulnerability context)
    nvd_texts = download_nvd_cves()
    all_texts.extend(nvd_texts)
    all_labels.extend([1] * len(nvd_texts))

    # Benign tech texts
    benign_tech = get_benign_tech_texts()
    all_texts.extend(benign_tech)
    all_labels.extend([0] * len(benign_tech))

    # ─── OUR EXISTING DATA ──────────────────────────────────────────────────
    try:
        from train_improved_model import MALICIOUS_TEXTS, BENIGN_TEXTS
        all_texts.extend(MALICIOUS_TEXTS)
        all_labels.extend([1] * len(MALICIOUS_TEXTS))
        all_texts.extend(BENIGN_TEXTS)
        all_labels.extend([0] * len(BENIGN_TEXTS))
        logger.info(f"  Added {len(MALICIOUS_TEXTS)+len(BENIGN_TEXTS)} existing hand-crafted samples")
    except ImportError:
        logger.warning("  Could not import existing training data")

    # ─── FINAL DATASET STATS ──────────────────────────────────────────────
    total = len(all_texts)
    n_mal = sum(all_labels)
    n_ben = total - n_mal

    logger.info(f"\n\n{'='*70}")
    logger.info(f"  COMBINED DATASET STATISTICS")
    logger.info(f"{'='*70}")
    logger.info(f"  Total samples:   {total:,}")
    logger.info(f"  Malicious:       {n_mal:,} ({n_mal/total*100:.1f}%)")
    logger.info(f"  Benign:          {n_ben:,} ({n_ben/total*100:.1f}%)")

    if total < 100:
        logger.error(f"  NOT ENOUGH DATA ({total} samples). Cannot train.")
        return

    # ─── BALANCE CLASSES ──────────────────────────────────────────────────
    # If heavily imbalanced, subsample the larger class
    MAX_PER_CLASS = 150000
    if n_mal > MAX_PER_CLASS or n_ben > MAX_PER_CLASS:
        mal_indices = [i for i, l in enumerate(all_labels) if l == 1]
        ben_indices = [i for i, l in enumerate(all_labels) if l == 0]
        random.shuffle(mal_indices)
        random.shuffle(ben_indices)
        mal_indices = mal_indices[:MAX_PER_CLASS]
        ben_indices = ben_indices[:MAX_PER_CLASS]
        selected = mal_indices + ben_indices
        all_texts = [all_texts[i] for i in selected]
        all_labels = [all_labels[i] for i in selected]
        logger.info(f"  Capped to {MAX_PER_CLASS:,} per class = {len(all_texts):,} total")

    # ─── TRAIN/TEST SPLIT ──────────────────────────────────────────────────
    y = np.array(all_labels)
    X_train_text, X_test_text, y_train, y_test = train_test_split(
        all_texts, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y
    )

    logger.info(f"\n  Train: {len(y_train):,} | Test: {len(y_test):,}")
    logger.info(f"  Train distribution: mal={sum(y_train):,} ben={len(y_train)-sum(y_train):,}")

    # ─── TF-IDF VECTORIZATION ──────────────────────────────────────────────
    logger.info("  Vectorizing with TF-IDF...")
    vectorizer = TfidfVectorizer(
        max_features=10000,       # More features for larger dataset
        ngram_range=(1, 3),       # Unigrams, bigrams, trigrams
        min_df=2,                 # Must appear in at least 2 documents
        max_df=0.85,              # Remove very common words
        sublinear_tf=True,
        strip_accents="unicode",
        lowercase=True,
        token_pattern=r"\b\w+\b",
    )

    X_train = vectorizer.fit_transform(X_train_text)
    X_test = vectorizer.transform(X_test_text)

    logger.info(f"  TF-IDF features: {X_train.shape[1]:,}")

    # ─── SMOTE (if imbalanced) ──────────────────────────────────────────────
    if HAS_SMOTE:
        mal_count = sum(y_train)
        ben_count = len(y_train) - mal_count
        ratio = min(mal_count, ben_count) / max(mal_count, ben_count)
        if ratio < 0.8:
            logger.info(f"  Class imbalance detected (ratio: {ratio:.2f}), applying SMOTE...")
            k = min(5, min(mal_count, ben_count) - 1)
            if k >= 1:
                smote = SMOTE(random_state=RANDOM_STATE, k_neighbors=k)
                X_train, y_train = smote.fit_resample(X_train, y_train)
                logger.info(f"  After SMOTE: {len(y_train):,} samples")

    # ─── TRAIN MODEL ──────────────────────────────────────────────────────
    logger.info("  Training Random Forest (500 trees)...")
    model = RandomForestClassifier(
        n_estimators=500,
        max_depth=30,
        min_samples_split=4,
        min_samples_leaf=2,
        max_features="sqrt",
        random_state=RANDOM_STATE,
        class_weight="balanced",
        n_jobs=-1,
        oob_score=True,
    )

    model.fit(X_train, y_train)

    # ─── EVALUATE ──────────────────────────────────────────────────────
    y_pred_train = model.predict(X_train)
    y_pred_test = model.predict(X_test)
    train_acc = accuracy_score(y_train, y_pred_train)
    test_acc = accuracy_score(y_test, y_pred_test)
    gap = train_acc - test_acc

    prec = precision_score(y_test, y_pred_test, average='weighted', zero_division=0)
    rec = recall_score(y_test, y_pred_test, average='weighted', zero_division=0)
    f1 = f1_score(y_test, y_pred_test, average='weighted', zero_division=0)

    logger.info(f"\n{'='*70}")
    logger.info(f"  RESULTS — KEYWORD MODEL (REAL DATA)")
    logger.info(f"{'='*70}")
    logger.info(f"  Train Accuracy:  {train_acc:.2%}")
    logger.info(f"  Test Accuracy:   {test_acc:.2%}")
    logger.info(f"  Overfit Gap:     {gap:.4f} {'⚠️ OVERFIT' if gap > 0.05 else '✅ OK'}")
    logger.info(f"  Precision:       {prec:.2%}")
    logger.info(f"  Recall:          {rec:.2%}")
    logger.info(f"  F1-Score:        {f1:.4f}")

    if hasattr(model, 'oob_score_'):
        logger.info(f"  OOB Score:       {model.oob_score_:.2%}")

    # Cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    cv_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="accuracy")
    logger.info(f"  5-Fold CV:       {cv_scores.mean():.2%} (+/- {cv_scores.std()*2:.4f})")

    logger.info(f"\n{classification_report(y_test, y_pred_test, target_names=['Benign', 'Malicious'], digits=3)}")

    # ─── SAVE ──────────────────────────────────────────────────────
    joblib.dump(model, os.path.join(MODELS_DIR, "keyword_model.pkl"))
    joblib.dump(vectorizer, os.path.join(MODELS_DIR, "keyword_vectorizer.pkl"))
    joblib.dump(model, os.path.join(BASE_DIR, "rf_model_improved.pkl"))
    joblib.dump(vectorizer, os.path.join(BASE_DIR, "tfidf_vectorizer.pkl"))

    logger.info(f"\n  ✓ Keyword model saved to {MODELS_DIR}")
    logger.info(f"  ✓ Total training samples: {len(all_texts):,} from {len(kaggle_datasets)} Kaggle + 2 public datasets")

    # Update training summary
    summary_path = os.path.join(MODELS_DIR, "training_summary.json")
    try:
        with open(summary_path) as f:
            summary = json.load(f)
    except Exception:
        summary = {}

    summary["keyword"] = {
        "train_acc": round(train_acc, 6),
        "test_acc": round(test_acc, 6),
        "cv_mean": round(cv_scores.mean(), 6),
        "cv_std": round(cv_scores.std(), 6),
        "precision": round(prec, 6),
        "recall": round(rec, 6),
        "f1": round(f1, 6),
        "gap": round(gap, 6),
        "data_source": f"{len(kaggle_datasets)} Kaggle datasets + MITRE ATT&CK + NVD CVEs",
        "total_samples": len(all_texts),
    }

    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    logger.info(f"\n{'='*70}\n")


if __name__ == "__main__":
    main()
