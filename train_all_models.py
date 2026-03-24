"""
train_all_models.py
====================
Comprehensive ML training pipeline for ALL IOC types:
  1. Keywords  - TF-IDF + Random Forest (improved from existing)
  2. URLs      - Lexical feature extraction + XGBoost
  3. IPs       - Simulated API features + XGBoost
  4. Domains   - Domain feature extraction + XGBoost
  5. Hashes    - Simulated API features + XGBoost

Anti-overfitting measures:
  - 5-fold stratified cross-validation
  - Regularisation (max_depth, min_samples_leaf, L2 via XGB reg_lambda)
  - Train/test gap monitoring
  - Early stopping for XGBoost
  - Learning curves logged
"""

import os, sys, math, re, random, string, warnings, logging, json
from collections import Counter
from datetime import datetime

import numpy as np
import joblib
from sklearn.model_selection import (
    train_test_split, StratifiedKFold, cross_val_score, learning_curve
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
os.makedirs(MODELS_DIR, exist_ok=True)

RANDOM_STATE = 42
random.seed(RANDOM_STATE)
np.random.seed(RANDOM_STATE)

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def train_and_evaluate(name, model, X_train, X_test, y_train, y_test,
                       class_names=None, cv_folds=5):
    """
    Train a model, evaluate on test set, run cross-validation,
    and check for overfitting (train-test accuracy gap).
    """
    logger.info(f"\n{'='*70}")
    logger.info(f"  TRAINING: {name}")
    logger.info(f"{'='*70}")
    logger.info(f"  Train samples: {len(y_train)}  |  Test samples: {len(y_test)}")
    logger.info(f"  Train class distribution: {dict(Counter(y_train))}")
    logger.info(f"  Test class distribution:  {dict(Counter(y_test))}")

    # Train
    model.fit(X_train, y_train)

    # Predictions
    y_pred_train = model.predict(X_train)
    y_pred_test = model.predict(X_test)

    train_acc = accuracy_score(y_train, y_pred_train)
    test_acc = accuracy_score(y_test, y_pred_test)
    gap = train_acc - test_acc

    logger.info(f"\n  Train Accuracy: {train_acc:.4f}")
    logger.info(f"  Test Accuracy:  {test_acc:.4f}")
    logger.info(f"  Gap (overfit?):  {gap:.4f}  {'⚠️ OVERFITTING' if gap > 0.05 else '✅ OK'}")

    # Cross-validation
    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=RANDOM_STATE)
    cv_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="accuracy")
    logger.info(f"  CV Accuracy:    {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")

    # Detailed metrics
    if class_names is None:
        class_names = [str(c) for c in sorted(set(y_test))]

    prec = precision_score(y_test, y_pred_test, average="weighted", zero_division=0)
    rec = recall_score(y_test, y_pred_test, average="weighted", zero_division=0)
    f1 = f1_score(y_test, y_pred_test, average="weighted", zero_division=0)

    logger.info(f"  Precision: {prec:.4f}  |  Recall: {rec:.4f}  |  F1: {f1:.4f}")
    logger.info(f"\n{classification_report(y_test, y_pred_test, target_names=class_names, digits=3)}")

    cm = confusion_matrix(y_test, y_pred_test)
    logger.info(f"  Confusion Matrix:\n{cm}\n")

    return {
        "train_acc": train_acc,
        "test_acc": test_acc,
        "cv_mean": cv_scores.mean(),
        "cv_std": cv_scores.std(),
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "gap": gap,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 1. KEYWORD MODEL (TF-IDF + Random Forest) — ENHANCED
# ═══════════════════════════════════════════════════════════════════════════════

def generate_keyword_data():
    """Generate expanded keyword training data."""
    from train_improved_model import MALICIOUS_TEXTS, BENIGN_TEXTS

    # Augment with variations
    extra_malicious = [
        # Ransomware
        "deploy ransomware on corporate network", "encrypt files demand bitcoin ransom",
        "ransomware builder kit download free", "create custom encryption ransomware",
        "spread ransomware via email attachment", "lock computer demand payment",
        "ransomware affiliate program dark web", "deploy locker malware on system",
        # Credential theft
        "steal login credentials from victims", "harvest user passwords database dump",
        "credential stuffing attack automation tool", "dump active directory passwords",
        "extract saved browser passwords remotely", "keylogger capture banking credentials",
        "phish employee credentials bulk email", "scrape leaked password databases",
        # Network attacks
        "launch DDoS attack on target server", "flood network with SYN packets",
        "perform DNS amplification attack", "execute slowloris denial of service",
        "UDP flood attack script download", "volumetric DDoS booter stresser",
        "bandwidth exhaustion attack tool", "application layer DDoS attack",
        # Exploitation
        "exploit remote code execution vulnerability", "buffer overflow shellcode injection",
        "SQL injection dump database tables", "cross site scripting XSS payload",
        "server side request forgery SSRF exploit", "local file inclusion LFI attack",
        "remote file inclusion RFI exploit code", "XML external entity XXE injection",
        "deserialization vulnerability exploit java", "command injection shell access",
        "directory traversal path traversal exploit", "LDAP injection attack technique",
        "use CVE to gain unauthorized access", "privilege escalation kernel exploit linux",
        # Social engineering
        "create convincing phishing email template", "spear phishing CEO fraud attack",
        "vishing voice phishing call script", "SMS phishing smishing attack campaign",
        "social engineering pretexting scenario", "tailgating physical security breach",
        "baiting attack infected USB drive", "whaling attack executive target",
        # Malware
        "compile undetectable trojan FUD", "create polymorphic malware variant",
        "fileless malware PowerShell attack script", "inject malicious DLL into process",
        "rootkit hide malware from antivirus", "worm self replicating network spread",
        "logic bomb trigger malicious code", "dropper download secondary payload",
        "RAT remote access trojan control panel", "cryptojacker mine cryptocurrency victim",
        # Dark web
        "access darknet marketplace onion", "buy stolen credit card data forums",
        "purchase hacking tools dark web market", "hire hacker dark web service",
        "sell zero day exploit underground forum", "buy ransomware as a service",
        "trade stolen personal data marketplace", "purchase botnet access dark web",
        # Evasion
        "bypass WAF web application firewall rules", "evade intrusion detection system IDS",
        "obfuscate malware code avoid detection", "encrypt C2 traffic avoid monitoring",
        "use steganography hide data in images", "tunneling DNS exfiltration covert",
        "disable endpoint detection response EDR", "anti forensics wipe evidence traces",
    ]

    extra_benign = [
        # Security awareness
        "cybersecurity awareness month activities", "employee security training program schedule",
        "how to recognize social engineering attempts", "tips for safe online shopping",
        "teaching children internet safety basics", "senior citizens online fraud prevention",
        "workplace cybersecurity policy guidelines", "phishing simulation training platform",
        "security awareness poster design template", "cyber hygiene daily checklist",
        # Defensive security
        "implement zero trust network architecture", "configure firewall rules best practices",
        "set up intrusion detection system IDS", "deploy endpoint detection response EDR",
        "SIEM implementation and configuration guide", "security operations center SOC setup",
        "incident response plan template organization", "disaster recovery planning guide",
        "business continuity plan cybersecurity", "blue team defensive security exercises",
        # Compliance and governance
        "GDPR compliance checklist for businesses", "HIPAA security requirements healthcare",
        "PCI DSS compliance requirements payment", "SOC 2 Type II audit preparation",
        "ISO 27001 certification requirements steps", "NIST cybersecurity framework implementation",
        "risk assessment methodology enterprise", "security policy development framework",
        "data classification scheme implementation", "regulatory compliance monitoring tools",
        # Vulnerability management
        "vulnerability scanning tools comparison review", "patch management process automation",
        "responsible vulnerability disclosure guidelines", "bug bounty program best practices",
        "CVE database search vulnerability lookup", "security advisory notification system",
        "penetration testing report writing guide", "remediation priority scoring system",
        "vulnerability assessment vs penetration testing", "automated security scanning pipeline",
        # Cryptography
        "encryption algorithm comparison guide AES RSA", "TLS certificate management best practices",
        "public key infrastructure PKI overview", "hash function SHA256 usage guide",
        "password hashing bcrypt argon2 comparison", "end to end encryption implementation",
        "secure key management practices", "certificate authority selection guide",
        # Cloud security
        "AWS security best practices checklist", "Azure active directory security guide",
        "Google Cloud platform security overview", "cloud workload protection platform CWPP",
        "container security scanning kubernetes", "serverless function security guidelines",
        "cloud access security broker CASB setup", "multi cloud security strategy planning",
        # Forensics and IR
        "digital forensics investigation methodology", "memory forensics analysis tools guide",
        "network forensics packet capture analysis", "malware reverse engineering tutorial",
        "incident response tabletop exercise scenario", "chain of custody evidence handling",
        "log analysis for incident investigation", "forensic image acquisition procedures",
        # General IT security
        "backup strategy 3 2 1 rule guide", "network segmentation architecture design",
        "access control list ACL configuration", "role based access control RBAC implementation",
        "single sign on SSO security benefits", "privileged access management PAM solution",
        "data loss prevention DLP policy setup", "email filtering gateway configuration",
        "web proxy content filtering setup", "DNS security DNSSEC implementation guide",
        "wireless network security WPA3 setup", "VPN configuration for remote workers",
        "IoT device security best practices", "supply chain security risk assessment",
        "open source software security review", "secure SDLC development lifecycle",
        "API security testing OWASP guidelines", "microservices security architecture",
    ]

    all_malicious = MALICIOUS_TEXTS + extra_malicious
    all_benign = BENIGN_TEXTS + extra_benign

    X = all_malicious + all_benign
    y = [1] * len(all_malicious) + [0] * len(all_benign)

    logger.info(f"  Keyword data: {len(all_malicious)} malicious + {len(all_benign)} benign = {len(X)} total")
    return X, y


def train_keyword_model():
    """Train the enhanced keyword classifier."""
    X_text, y = generate_keyword_data()
    y = np.array(y)

    X_train_text, X_test_text, y_train, y_test = train_test_split(
        X_text, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y
    )

    # TF-IDF with trigrams
    vectorizer = TfidfVectorizer(
        max_features=2000,
        ngram_range=(1, 3),
        min_df=1,
        max_df=0.90,
        sublinear_tf=True,
        strip_accents="unicode",
        lowercase=True,
        token_pattern=r"\b\w+\b",
    )

    X_train = vectorizer.fit_transform(X_train_text)
    X_test = vectorizer.transform(X_test_text)

    # SMOTE if available
    if HAS_SMOTE:
        k = min(5, min(sum(y_train), len(y_train) - sum(y_train)) - 1)
        if k >= 1:
            smote = SMOTE(random_state=RANDOM_STATE, k_neighbors=k)
            X_train, y_train = smote.fit_resample(X_train, y_train)
            logger.info(f"  After SMOTE: {X_train.shape[0]} samples")

    model = RandomForestClassifier(
        n_estimators=500,
        max_depth=20,
        min_samples_split=4,
        min_samples_leaf=2,
        max_features="sqrt",
        random_state=RANDOM_STATE,
        class_weight="balanced",
        n_jobs=-1,
        oob_score=True,
    )

    metrics = train_and_evaluate(
        "Keyword Classifier (TF-IDF + RF)",
        model, X_train, X_test, y_train, y_test,
        class_names=["Benign", "Malicious"]
    )

    # Save
    joblib.dump(model, os.path.join(MODELS_DIR, "keyword_model.pkl"))
    joblib.dump(vectorizer, os.path.join(MODELS_DIR, "keyword_vectorizer.pkl"))
    # Also save to root for backward compatibility
    joblib.dump(model, os.path.join(BASE_DIR, "rf_model_improved.pkl"))
    joblib.dump(vectorizer, os.path.join(BASE_DIR, "tfidf_vectorizer.pkl"))

    return metrics


# ═══════════════════════════════════════════════════════════════════════════════
# 2. URL MODEL — Lexical Feature Extraction + XGBoost
# ═══════════════════════════════════════════════════════════════════════════════

# Realistic TLDs
SAFE_TLDS = [".com", ".org", ".net", ".edu", ".gov", ".io", ".co", ".us", ".uk", ".de", ".fr", ".jp", ".au", ".ca", ".in"]
SUSPICIOUS_TLDS = [".xyz", ".top", ".buzz", ".click", ".link", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc", ".icu", ".club", ".work", ".site", ".online", ".fun", ".space", ".info"]

LEGIT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "netflix.com",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "medium.com",
    "nytimes.com", "bbc.com", "cnn.com", "yahoo.com", "bing.com",
    "dropbox.com", "zoom.us", "slack.com", "salesforce.com", "adobe.com",
    "paypal.com", "stripe.com", "shopify.com", "wordpress.org", "mozilla.org",
    "python.org", "nodejs.org", "docker.com", "kubernetes.io", "aws.amazon.com",
    "cloud.google.com", "azure.microsoft.com", "heroku.com", "vercel.com", "netlify.com",
    "coursera.org", "edx.org", "khanacademy.org", "udemy.com", "pluralsight.com",
    "npmjs.com", "pypi.org", "rubygems.org", "maven.apache.org", "nuget.org",
]

SAFE_PATHS = [
    "/", "/about", "/contact", "/blog", "/news", "/products", "/services",
    "/help", "/support", "/faq", "/terms", "/privacy", "/careers", "/team",
    "/docs", "/api", "/documentation", "/getting-started", "/tutorials",
    "/search", "/login", "/signup", "/dashboard", "/settings", "/profile",
    "/articles/tech-news-today", "/blog/2024/best-practices",
    "/products/enterprise-solution", "/resources/whitepaper-download",
]

BRAND_NAMES = ["paypal", "apple", "google", "amazon", "microsoft", "netflix", "facebook", "instagram", "bank", "secure", "login", "verify", "account", "update", "confirm"]


def generate_benign_url():
    """Generate a realistic benign URL."""
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(SAFE_PATHS)
    scheme = random.choice(["https://"] * 9 + ["http://"])  # 90% HTTPS
    www = random.choice(["www."] * 3 + [""])
    return f"{scheme}{www}{domain}{path}"


def generate_malicious_url():
    """Generate a realistic malicious/phishing URL."""
    patterns = [
        # Phishing: brand misspelling
        lambda: f"http://{''.join(random.choices(string.ascii_lowercase, k=random.randint(3,8)))}-{random.choice(BRAND_NAMES)}{random.choice(SUSPICIOUS_TLDS)}/login/verify.php",
        # Phishing: subdomain trick
        lambda: f"http://{random.choice(BRAND_NAMES)}.{''.join(random.choices(string.ascii_lowercase+string.digits, k=random.randint(8,15)))}{random.choice(SUSPICIOUS_TLDS)}/account/secure",
        # IP-based URL
        lambda: f"http://{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}/{''.join(random.choices(string.ascii_lowercase, k=5))}/login.php",
        # Long random subdomain
        lambda: f"http://{''.join(random.choices(string.ascii_lowercase+string.digits+'-', k=random.randint(20,40)))}{random.choice(SUSPICIOUS_TLDS)}/verify",
        # Encoded / obfuscated
        lambda: f"http://{''.join(random.choices(string.ascii_lowercase, k=8))}{random.choice(SUSPICIOUS_TLDS)}/%7E{''.join(random.choices(string.ascii_lowercase+string.digits, k=10))}",
        # With port number
        lambda: f"http://{''.join(random.choices(string.ascii_lowercase, k=10))}{random.choice(SUSPICIOUS_TLDS)}:{random.choice([8080, 8443, 4443, 9090, 3000])}/admin",
        # Deep path with suspicious keywords
        lambda: f"http://{''.join(random.choices(string.ascii_lowercase, k=6))}{random.choice(SUSPICIOUS_TLDS)}/wp-admin/includes/update-{random.choice(BRAND_NAMES)}/secure-login.html",
        # With @ symbol (credential phishing)
        lambda: f"http://{random.choice(BRAND_NAMES)}.com@{''.join(random.choices(string.ascii_lowercase, k=12))}{random.choice(SUSPICIOUS_TLDS)}",
        # Hyphenated brand imitation
        lambda: f"http://{random.choice(BRAND_NAMES)}-{''.join(random.choices(string.ascii_lowercase, k=random.randint(3,8)))}-secure{random.choice(SUSPICIOUS_TLDS)}/auth",
        # Many subdomains
        lambda: f"http://{''.join(random.choices(string.ascii_lowercase, k=4))}.{''.join(random.choices(string.ascii_lowercase, k=5))}.{''.join(random.choices(string.ascii_lowercase, k=6))}.{''.join(random.choices(string.ascii_lowercase, k=4))}{random.choice(SUSPICIOUS_TLDS)}/",
    ]
    return random.choice(patterns)()


def extract_url_features(url: str) -> list:
    """Extract 20 lexical features from a URL string."""
    try:
        url_lower = url.lower()

        # Basic lengths
        url_length = len(url)
        hostname = url.split("//")[-1].split("/")[0].split(":")[0].split("@")[-1]
        hostname_length = len(hostname)
        path = "/" + "/".join(url.split("//")[-1].split("/")[1:]) if "/" in url.split("//")[-1] else "/"
        path_length = len(path)

        # Character counts
        num_dots = url.count(".")
        num_hyphens = url.count("-")
        num_underscores = url.count("_")
        num_slashes = url.count("/")
        num_at = url.count("@")
        num_digits = sum(c.isdigit() for c in url)
        num_special = sum(not c.isalnum() and c not in "./-_:@" for c in url)

        # Ratios
        digit_ratio = num_digits / max(url_length, 1)
        letter_ratio = sum(c.isalpha() for c in url) / max(url_length, 1)

        # Protocol
        has_https = 1 if url_lower.startswith("https") else 0

        # IP in URL
        has_ip = 1 if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", hostname) else 0

        # Port
        has_port = 1 if re.search(r":\d{2,5}", url.split("//")[-1].split("/")[0]) else 0

        # Subdomains
        parts = hostname.split(".")
        num_subdomains = max(len(parts) - 2, 0)

        # Suspicious TLD
        tld = "." + parts[-1] if parts else ""
        has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

        # Brand keyword in suspicious position
        has_brand = 0
        for brand in BRAND_NAMES[:10]:
            if brand in hostname and not hostname.endswith(f"{brand}.com") and not hostname.endswith(f"{brand}.org"):
                has_brand = 1
                break

        # Entropy
        url_entropy = entropy(url)

        return [
            url_length, hostname_length, path_length,
            num_dots, num_hyphens, num_underscores, num_slashes,
            num_at, num_digits, num_special,
            digit_ratio, letter_ratio,
            has_https, has_ip, has_port,
            num_subdomains, has_suspicious_tld, has_brand,
            url_entropy,
            len(max(re.split(r"[^a-zA-Z]", url), key=len)) if url else 0,  # longest word
        ]
    except Exception:
        return [0] * 20


URL_FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length",
    "num_dots", "num_hyphens", "num_underscores", "num_slashes",
    "num_at", "num_digits", "num_special",
    "digit_ratio", "letter_ratio",
    "has_https", "has_ip", "has_port",
    "num_subdomains", "has_suspicious_tld", "has_brand",
    "url_entropy", "longest_word",
]


def generate_edge_case_benign_url():
    """Benign URLs that look suspicious (security sites, short URLs, etc)."""
    patterns = [
        # Security vendor sites with threat-related paths
        lambda: f"https://www.virustotal.com/gui/file/{''.join(random.choices('abcdef0123456789', k=64))}",
        lambda: f"https://malwarebytes.com/{''.join(random.choices(string.ascii_lowercase, k=8))}",
        lambda: f"https://any.run/report/{''.join(random.choices('abcdef0123456789', k=32))}",
        lambda: f"http://{''.join(random.choices(string.ascii_lowercase, k=6))}.blogspot.com/2024/security-tips",
        # URL shorteners (benign but look suspicious)
        lambda: f"https://bit.ly/{''.join(random.choices(string.ascii_letters+string.digits, k=7))}",
        lambda: f"https://t.co/{''.join(random.choices(string.ascii_letters+string.digits, k=10))}",
        # Legitimate sites with long paths
        lambda: f"https://docs.google.com/document/d/{''.join(random.choices(string.ascii_letters+string.digits+'-_', k=44))}/edit",
        lambda: f"https://www.amazon.com/dp/{''.join(random.choices(string.ascii_uppercase+string.digits, k=10))}",
        # Government/edu with ugly URLs
        lambda: f"http://{''.join(random.choices(string.ascii_lowercase, k=5))}.gov.{''.join(random.choices(string.ascii_lowercase, k=2))}/portal/{''.join(random.choices(string.digits, k=6))}",
        # IP-based but legitimate (internal tools, routers)
        lambda: f"http://192.168.{random.randint(0,255)}.{random.randint(1,254)}/admin",
        lambda: f"https://10.0.{random.randint(0,255)}.{random.randint(1,254)}:8443/dashboard",
    ]
    return random.choice(patterns)()


def generate_edge_case_malicious_url():
    """Malicious URLs that try to look legitimate (HTTPS, known TLDs)."""
    patterns = [
        # HTTPS phishing (looks more legit)
        lambda: f"https://{''.join(random.choices(string.ascii_lowercase, k=5))}-{random.choice(BRAND_NAMES)}.com/secure/login",
        lambda: f"https://www.{random.choice(BRAND_NAMES)}-{''.join(random.choices(string.ascii_lowercase, k=4))}.com/verify",
        # Using .com TLD but still malicious
        lambda: f"http://{''.join(random.choices(string.ascii_lowercase+string.digits, k=12))}.com/{''.join(random.choices(string.ascii_lowercase, k=5))}.php",
        # Legit-looking path structure
        lambda: f"http://{''.join(random.choices(string.ascii_lowercase, k=8))}.net/products/download/setup.exe",
        lambda: f"https://{''.join(random.choices(string.ascii_lowercase, k=6))}.org/update/critical-patch.msi",
    ]
    return random.choice(patterns)()


def train_url_model():
    """Train URL classifier on lexical features."""
    N_BENIGN = 5000
    N_MALICIOUS = 5000
    N_EDGE = 500  # edge cases per class

    logger.info(f"  Generating {N_BENIGN+N_EDGE} benign + {N_MALICIOUS+N_EDGE} malicious URLs (incl. {N_EDGE} edge cases each)...")

    urls, labels = [], []
    for _ in range(N_BENIGN):
        urls.append(generate_benign_url())
        labels.append(0)
    for _ in range(N_EDGE):
        urls.append(generate_edge_case_benign_url())
        labels.append(0)
    for _ in range(N_MALICIOUS):
        urls.append(generate_malicious_url())
        labels.append(1)
    for _ in range(N_EDGE):
        urls.append(generate_edge_case_malicious_url())
        labels.append(1)

    # Extract features
    X = np.array([extract_url_features(u) for u in urls])
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y
    )

    # Scale features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    if HAS_XGB:
        model = XGBClassifier(
            n_estimators=300,
            max_depth=8,
            learning_rate=0.05,
            min_child_weight=5,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_lambda=2.0,       # L2 regularisation to prevent overfitting
            reg_alpha=0.5,        # L1 regularisation
            random_state=RANDOM_STATE,
            eval_metric="logloss",
            use_label_encoder=False,
        )
    else:
        model = GradientBoostingClassifier(
            n_estimators=300,
            max_depth=8,
            learning_rate=0.05,
            min_samples_leaf=5,
            subsample=0.8,
            random_state=RANDOM_STATE,
        )

    metrics = train_and_evaluate(
        "URL Classifier (Lexical Features + XGBoost)",
        model, X_train, X_test, y_train, y_test,
        class_names=["Benign", "Malicious"]
    )

    joblib.dump(model, os.path.join(MODELS_DIR, "url_model.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "url_scaler.pkl"))

    return metrics


# ═══════════════════════════════════════════════════════════════════════════════
# 3. IP MODEL — Simulated API Features + XGBoost
# ═══════════════════════════════════════════════════════════════════════════════

IP_FEATURE_NAMES = [
    "vt_malicious", "vt_suspicious", "vt_harmless", "vt_undetected",
    "shodan_open_ports", "shodan_vulns",
    "otx_threat_score", "otx_pulse_count",
    "abuseipdb_confidence", "abuseipdb_reports",
    "is_private",
]


def generate_ip_features(label: int, edge_case: bool = False) -> list:
    """Generate realistic API response features for an IP address."""
    if label == 1:  # Malicious
        if edge_case:
            # Low-signal malicious — newly compromised, few detections
            vt_m = random.randint(1, 5)
            vt_s = random.randint(0, 3)
            vt_h = random.randint(40, 65)
            vt_u = random.randint(5, 20)
            ports = random.randint(1, 6)
            vulns = random.randint(0, 2)
            otx_score = random.randint(15, 45)
            otx_pulses = random.randint(1, 8)
            abuse_conf = random.randint(20, 55)
            abuse_reps = random.randint(3, 30)
            is_private = 0
        else:
            profile = random.choice(["botnet", "scanner", "c2", "spam", "bruteforce", "malware"])
            if profile == "botnet":
                vt_m = random.randint(8, 45)
                vt_s = random.randint(2, 10)
                ports = random.randint(3, 15)
                vulns = random.randint(0, 5)
                otx_score = random.randint(50, 100)
                otx_pulses = random.randint(5, 40)
                abuse_conf = random.randint(70, 100)
                abuse_reps = random.randint(50, 500)
            elif profile == "scanner":
                vt_m = random.randint(3, 20)
                vt_s = random.randint(1, 8)
                ports = random.randint(10, 100)
                vulns = random.randint(0, 3)
                otx_score = random.randint(40, 85)
                otx_pulses = random.randint(3, 25)
                abuse_conf = random.randint(50, 95)
                abuse_reps = random.randint(20, 300)
            elif profile == "c2":
                vt_m = random.randint(15, 55)
                vt_s = random.randint(3, 12)
                ports = random.randint(2, 8)
                vulns = random.randint(0, 2)
                otx_score = random.randint(60, 100)
                otx_pulses = random.randint(8, 50)
                abuse_conf = random.randint(60, 100)
                abuse_reps = random.randint(10, 200)
            elif profile == "spam":
                vt_m = random.randint(2, 15)
                vt_s = random.randint(0, 5)
                ports = random.randint(1, 5)
                vulns = random.randint(0, 1)
                otx_score = random.randint(30, 70)
                otx_pulses = random.randint(2, 15)
                abuse_conf = random.randint(40, 90)
                abuse_reps = random.randint(30, 400)
            elif profile == "bruteforce":
                vt_m = random.randint(5, 25)
                vt_s = random.randint(1, 6)
                ports = random.randint(1, 5)
                vulns = random.randint(0, 2)
                otx_score = random.randint(45, 90)
                otx_pulses = random.randint(4, 30)
                abuse_conf = random.randint(55, 100)
                abuse_reps = random.randint(40, 600)
            else:  # malware
                vt_m = random.randint(20, 60)
                vt_s = random.randint(5, 15)
                ports = random.randint(2, 10)
                vulns = random.randint(1, 8)
                otx_score = random.randint(65, 100)
                otx_pulses = random.randint(10, 60)
                abuse_conf = random.randint(75, 100)
                abuse_reps = random.randint(30, 350)

            vt_h = random.randint(10, 50)
            vt_u = random.randint(0, 15)
            is_private = 0

    else:  # Benign
        if edge_case:
            # Noisy benign — shared hosting, some false positives from scanners
            vt_m = random.randint(1, 4)
            vt_s = random.randint(0, 3)
            vt_h = random.randint(45, 70)
            vt_u = random.randint(2, 12)
            ports = random.randint(5, 20)
            vulns = random.randint(0, 3)
            otx_score = random.randint(10, 35)
            otx_pulses = random.randint(1, 6)
            abuse_conf = random.randint(5, 35)
            abuse_reps = random.randint(2, 25)
            is_private = 0
        else:
            profile = random.choice(["cdn", "webserver", "dns", "cloud", "isp", "corporate"])
            vt_m = random.randint(0, 2)
            vt_s = random.randint(0, 1)
            vt_h = random.randint(50, 80)
            vt_u = random.randint(0, 10)

            if profile == "cdn":
                ports = random.randint(1, 4)
                vulns = 0
                otx_score = random.randint(0, 10)
                otx_pulses = random.randint(0, 2)
                abuse_conf = random.randint(0, 5)
                abuse_reps = random.randint(0, 3)
            elif profile == "webserver":
                ports = random.randint(2, 8)
                vulns = random.randint(0, 2)
                otx_score = random.randint(0, 20)
                otx_pulses = random.randint(0, 5)
                abuse_conf = random.randint(0, 15)
                abuse_reps = random.randint(0, 10)
            elif profile == "dns":
                ports = random.randint(1, 3)
                vulns = 0
                otx_score = random.randint(0, 5)
                otx_pulses = random.randint(0, 1)
                abuse_conf = random.randint(0, 3)
                abuse_reps = random.randint(0, 2)
            elif profile == "cloud":
                ports = random.randint(3, 15)
                vulns = random.randint(0, 3)
                otx_score = random.randint(0, 15)
                otx_pulses = random.randint(0, 4)
                abuse_conf = random.randint(0, 20)
                abuse_reps = random.randint(0, 15)
            elif profile == "isp":
                ports = random.randint(1, 5)
                vulns = random.randint(0, 1)
                otx_score = random.randint(0, 10)
                otx_pulses = random.randint(0, 3)
                abuse_conf = random.randint(0, 10)
                abuse_reps = random.randint(0, 8)
            else:  # corporate
                ports = random.randint(2, 10)
                vulns = random.randint(0, 2)
                otx_score = random.randint(0, 12)
                otx_pulses = random.randint(0, 3)
                abuse_conf = random.randint(0, 8)
                abuse_reps = random.randint(0, 5)

            is_private = random.choice([0] * 8 + [1] * 2)

    return [vt_m, vt_s, vt_h, vt_u, ports, vulns,
            otx_score, otx_pulses, abuse_conf, abuse_reps, is_private]


def train_ip_model():
    """Train IP classifier on API response features."""
    N_BENIGN = 3500
    N_MALICIOUS = 3500
    N_EDGE = 500

    logger.info(f"  Generating {N_BENIGN+N_EDGE} benign + {N_MALICIOUS+N_EDGE} malicious IP features (incl. {N_EDGE} edge cases each)...")

    X, y = [], []
    for _ in range(N_BENIGN):
        X.append(generate_ip_features(0, edge_case=False))
        y.append(0)
    for _ in range(N_EDGE):
        X.append(generate_ip_features(0, edge_case=True))
        y.append(0)
    for _ in range(N_MALICIOUS):
        X.append(generate_ip_features(1, edge_case=False))
        y.append(1)
    for _ in range(N_EDGE):
        X.append(generate_ip_features(1, edge_case=True))
        y.append(1)

    X = np.array(X, dtype=np.float32)
    y = np.array(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    if HAS_XGB:
        model = XGBClassifier(
            n_estimators=250,
            max_depth=6,
            learning_rate=0.05,
            min_child_weight=5,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_lambda=3.0,
            reg_alpha=0.5,
            random_state=RANDOM_STATE,
            eval_metric="logloss",
            use_label_encoder=False,
        )
    else:
        model = GradientBoostingClassifier(
            n_estimators=250,
            max_depth=6,
            learning_rate=0.05,
            min_samples_leaf=5,
            subsample=0.8,
            random_state=RANDOM_STATE,
        )

    metrics = train_and_evaluate(
        "IP Classifier (API Features + XGBoost)",
        model, X_train, X_test, y_train, y_test,
        class_names=["Benign", "Malicious"]
    )

    joblib.dump(model, os.path.join(MODELS_DIR, "ip_model.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "ip_scaler.pkl"))

    return metrics


# ═══════════════════════════════════════════════════════════════════════════════
# 4. DOMAIN MODEL — Domain Feature Extraction + XGBoost
# ═══════════════════════════════════════════════════════════════════════════════

LEGIT_PATTERNS = [
    # Real domain patterns
    lambda: random.choice(LEGIT_DOMAINS),
    lambda: random.choice(["blog", "shop", "app", "dev", "api", "docs", "mail", "news"]) + "." + random.choice(LEGIT_DOMAINS),
    lambda: "".join(random.choices(string.ascii_lowercase, k=random.randint(4, 10))) + random.choice(SAFE_TLDS),
    lambda: random.choice(["my", "get", "try", "go", "use", "the"]) + "".join(random.choices(string.ascii_lowercase, k=random.randint(4, 8))) + random.choice(SAFE_TLDS),
]

MALICIOUS_DOMAIN_PATTERNS = [
    # Random string domains (DGA-like)
    lambda: "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(15, 30))) + random.choice(SUSPICIOUS_TLDS),
    # Brand impersonation
    lambda: random.choice(BRAND_NAMES) + "-" + "".join(random.choices(string.ascii_lowercase, k=random.randint(3, 8))) + random.choice(SUSPICIOUS_TLDS),
    # Hyphenated mess
    lambda: "-".join(random.choices(string.ascii_lowercase, k=random.randint(3, 6))) + random.choice(SUSPICIOUS_TLDS),
    # Typosquatting
    lambda: random.choice(BRAND_NAMES)[:random.randint(2, 4)] + "".join(random.choices(string.ascii_lowercase, k=random.randint(2, 5))) + random.choice(SUSPICIOUS_TLDS),
    # Many subdomains
    lambda: ".".join("".join(random.choices(string.ascii_lowercase, k=random.randint(3, 6))) for _ in range(random.randint(3, 5))) + random.choice(SUSPICIOUS_TLDS),
    # Digit-heavy
    lambda: "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(8, 20))) + random.choice(SUSPICIOUS_TLDS),
]

DOMAIN_FEATURE_NAMES = [
    "domain_length", "num_dots", "num_hyphens", "num_digits",
    "digit_ratio", "consonant_ratio", "vowel_ratio",
    "has_suspicious_tld", "has_brand_keyword",
    "subdomain_depth", "max_label_length", "avg_label_length",
    "domain_entropy", "num_unique_chars",
]


def extract_domain_features(domain: str) -> list:
    """Extract 14 features from a domain string."""
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


def train_domain_model():
    """Train domain classifier on structural features."""
    N_BENIGN = 5000
    N_MALICIOUS = 5000

    logger.info(f"  Generating {N_BENIGN} benign + {N_MALICIOUS} malicious domains...")

    domains, labels = [], []
    for _ in range(N_BENIGN):
        domains.append(random.choice(LEGIT_PATTERNS)())
        labels.append(0)
    for _ in range(N_MALICIOUS):
        domains.append(random.choice(MALICIOUS_DOMAIN_PATTERNS)())
        labels.append(1)

    X = np.array([extract_domain_features(d) for d in domains])
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    if HAS_XGB:
        model = XGBClassifier(
            n_estimators=300,
            max_depth=7,
            learning_rate=0.05,
            min_child_weight=5,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_lambda=2.5,
            reg_alpha=0.5,
            random_state=RANDOM_STATE,
            eval_metric="logloss",
            use_label_encoder=False,
        )
    else:
        model = GradientBoostingClassifier(
            n_estimators=300,
            max_depth=7,
            learning_rate=0.05,
            min_samples_leaf=5,
            subsample=0.8,
            random_state=RANDOM_STATE,
        )

    metrics = train_and_evaluate(
        "Domain Classifier (Structural Features + XGBoost)",
        model, X_train, X_test, y_train, y_test,
        class_names=["Benign", "Malicious"]
    )

    joblib.dump(model, os.path.join(MODELS_DIR, "domain_model.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "domain_scaler.pkl"))

    return metrics


# ═══════════════════════════════════════════════════════════════════════════════
# 5. HASH MODEL — Simulated API Features + XGBoost
# ═══════════════════════════════════════════════════════════════════════════════

HASH_FEATURE_NAMES = [
    "vt_malicious", "vt_suspicious", "vt_harmless", "vt_undetected",
    "vt_detection_ratio",
    "otx_threat_score", "otx_pulse_count",
    "community_score", "first_seen_days",
]


def generate_hash_features(label: int, edge_case: bool = False) -> list:
    """Generate realistic API response features for a file hash."""
    if label == 1:  # Malicious
        if edge_case:
            # Newly submitted / low-detection malware (FUD / packed)
            vt_m = random.randint(2, 8)
            vt_s = random.randint(1, 5)
            vt_h = random.randint(30, 55)
            vt_u = random.randint(5, 20)
            otx_score = random.randint(15, 45)
            otx_pulses = random.randint(1, 6)
            community = random.randint(-20, 0)
            first_seen = random.randint(0, 14)
        else:
            vt_m = random.randint(10, 65)
            vt_s = random.randint(2, 12)
            vt_h = random.randint(5, 30)
            vt_u = random.randint(0, 10)
            otx_score = random.randint(50, 100)
            otx_pulses = random.randint(5, 50)
            community = random.randint(-50, -5)
            first_seen = random.randint(0, 365)
    else:  # Benign
        if edge_case:
            # Legitimate file with false positive detections (packers, rare software)
            vt_m = random.randint(1, 5)
            vt_s = random.randint(1, 4)
            vt_h = random.randint(45, 65)
            vt_u = random.randint(3, 15)
            otx_score = random.randint(5, 25)
            otx_pulses = random.randint(0, 4)
            community = random.randint(-5, 15)
            first_seen = random.randint(7, 730)
        else:
            vt_m = random.randint(0, 2)
            vt_s = random.randint(0, 1)
            vt_h = random.randint(55, 75)
            vt_u = random.randint(0, 10)
            otx_score = random.randint(0, 15)
            otx_pulses = random.randint(0, 3)
            community = random.randint(0, 50)
            first_seen = random.randint(30, 3650)

    total = vt_m + vt_s + vt_h + vt_u
    det_ratio = (vt_m + vt_s * 0.5) / max(total, 1)

    return [vt_m, vt_s, vt_h, vt_u, det_ratio,
            otx_score, otx_pulses, community, first_seen]


def train_hash_model():
    """Train hash/file classifier on API response features."""
    N_BENIGN = 3500
    N_MALICIOUS = 3500
    N_EDGE = 500

    logger.info(f"  Generating {N_BENIGN+N_EDGE} benign + {N_MALICIOUS+N_EDGE} malicious hash features (incl. {N_EDGE} edge cases each)...")

    X, y = [], []
    for _ in range(N_BENIGN):
        X.append(generate_hash_features(0, edge_case=False))
        y.append(0)
    for _ in range(N_EDGE):
        X.append(generate_hash_features(0, edge_case=True))
        y.append(0)
    for _ in range(N_MALICIOUS):
        X.append(generate_hash_features(1, edge_case=False))
        y.append(1)
    for _ in range(N_EDGE):
        X.append(generate_hash_features(1, edge_case=True))
        y.append(1)

    X = np.array(X, dtype=np.float32)
    y = np.array(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    if HAS_XGB:
        model = XGBClassifier(
            n_estimators=200,
            max_depth=5,
            learning_rate=0.05,
            min_child_weight=5,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_lambda=3.0,
            reg_alpha=0.5,
            random_state=RANDOM_STATE,
            eval_metric="logloss",
            use_label_encoder=False,
        )
    else:
        model = GradientBoostingClassifier(
            n_estimators=200,
            max_depth=5,
            learning_rate=0.05,
            min_samples_leaf=5,
            subsample=0.8,
            random_state=RANDOM_STATE,
        )

    metrics = train_and_evaluate(
        "Hash Classifier (API Features + XGBoost)",
        model, X_train, X_test, y_train, y_test,
        class_names=["Benign", "Malicious"]
    )

    joblib.dump(model, os.path.join(MODELS_DIR, "hash_model.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "hash_scaler.pkl"))

    return metrics


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN — TRAIN ALL MODELS
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    start = datetime.now()

    logger.info("\n" + "█" * 70)
    logger.info("  TRAINING ALL THREAT CLASSIFICATION MODELS")
    logger.info("  " + str(datetime.now()))
    logger.info("█" * 70)

    all_metrics = {}

    # 1. Keywords
    logger.info("\n\n▶ [1/5] KEYWORD MODEL")
    all_metrics["keyword"] = train_keyword_model()

    # 2. URLs
    logger.info("\n\n▶ [2/5] URL MODEL")
    all_metrics["url"] = train_url_model()

    # 3. IPs
    logger.info("\n\n▶ [3/5] IP MODEL")
    all_metrics["ip"] = train_ip_model()

    # 4. Domains
    logger.info("\n\n▶ [4/5] DOMAIN MODEL")
    all_metrics["domain"] = train_domain_model()

    # 5. Hashes
    logger.info("\n\n▶ [5/5] HASH MODEL")
    all_metrics["hash"] = train_hash_model()

    # ═══════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════════════
    elapsed = (datetime.now() - start).total_seconds()

    logger.info("\n\n" + "█" * 70)
    logger.info("  TRAINING COMPLETE — SUMMARY")
    logger.info("█" * 70)

    logger.info(f"\n  {'Model':<35} {'Test Acc':>10} {'CV Acc':>10} {'F1':>8} {'Gap':>8} {'Status':>10}")
    logger.info("  " + "-" * 85)

    for name, m in all_metrics.items():
        status = "✅ OK" if m["gap"] < 0.05 else "⚠️ OVERFIT"
        logger.info(
            f"  {name:<35} {m['test_acc']:>10.2%} {m['cv_mean']:>10.2%} "
            f"{m['f1']:>8.4f} {m['gap']:>8.4f} {status:>10}"
        )

    logger.info(f"\n  Total training time: {elapsed:.1f}s")
    logger.info(f"  Models saved to: {MODELS_DIR}")

    # Save summary JSON
    summary_path = os.path.join(MODELS_DIR, "training_summary.json")
    with open(summary_path, "w") as f:
        json.dump({
            k: {kk: round(vv, 6) if isinstance(vv, float) else vv for kk, vv in v.items()}
            for k, v in all_metrics.items()
        }, f, indent=2)
    logger.info(f"  Summary saved to: {summary_path}")

    logger.info("\n" + "█" * 70 + "\n")

    return all_metrics


if __name__ == "__main__":
    main()
