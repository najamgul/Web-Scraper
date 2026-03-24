# train_improved_model.py
"""
Random Forest threat classifier with TF-IDF vectorization and SMOTE oversampling.
Trains on labeled threat/benign text samples and exports the model + vectorizer.
"""

import numpy as np
import joblib
import os
import sys
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# Malicious / offensive-intent phrases
MALICIOUS_TEXTS = [
    # Malware distribution
    "download malware free",
    "ransomware attack tools",
    "backdoor trojan download",
    "keylogger software free",
    "download free ransomware builder",
    "get rootkit installer",
    "trojan horse virus download",
    "free malware builder tool",
    "download botnet builder",
    "get spyware for android free",
    "install remote access trojan",
    "download cryptominer payload",
    "free virus creation kit",
    "malware dropper download link",
    "download fileless malware toolkit",

    # Hacking and cracking
    "how to hack facebook account",
    "crack windows password",
    "hack wifi password tool",
    "brute force password cracker",
    "crack software serial keys",
    "hack instagram password online",
    "bypass login authentication",
    "crack database password hash",
    "hack email account password",
    "how to hack bank account online",
    "crack WPA2 wifi password fast",
    "hack snapchat account free",
    "bypass two factor authentication hack",
    "decode encrypted passwords tool",
    "crack zip file password online",

    # Exploits and vulnerabilities
    "exploit vulnerability CVE",
    "zero day exploit for sale",
    "privilege escalation exploit",
    "exploit development tutorial",
    "buy exploit kit online",
    "remote code execution exploit",
    "buffer overflow exploit code",
    "kernel exploit download",
    "browser zero day exploit sale",
    "use metasploit to exploit target",
    "weaponize CVE proof of concept",
    "exploit unpatched server vulnerability",
    "shellcode injection payload",
    "heap spray exploit technique",
    "exploit chain for privilege escalation",

    # Botnets and C2
    "botnet control panel",
    "command and control server setup",
    "botnet rental service",
    "build your own botnet",
    "c2 server configuration guide",
    "deploy command and control infrastructure",
    "botnet DDoS for hire service",
    "zombie network control dashboard",
    "rent botnet for spam campaign",
    "set up IRC botnet controller",

    # Data theft and exfiltration
    "steal credentials tutorial",
    "data exfiltration methods",
    "credit card dumping tool",
    "bank account hacking method",
    "stolen data marketplace dark web",
    "dump database credentials",
    "exfiltrate sensitive data covertly",
    "steal browser saved passwords",
    "harvest credit card numbers tool",
    "scrape personal data for fraud",
    "extract cookies for session hijack",
    "clone credit card magnetic strip",
    "sniff network traffic for passwords",

    # Attack tools and techniques
    "ddos attack tool",
    "sql injection tool automated",
    "bypass antivirus detection method",
    "lateral movement techniques attack",
    "remote access trojan rat tool",
    "cryptojacking script deploy",
    "phishing kit download ready",
    "social engineering toolkit attack",
    "man in the middle attack tool",
    "network sniffing tools hacking",
    "malicious payload generator",
    "reverse shell backdoor create",
    "webshell upload exploit",
    "persistence mechanism windows backdoor",
    "rootkit installation guide tutorial",

    # Dark web and underground markets
    "dark web hacking forum access",
    "carding forum access login",
    "credential stuffing wordlist",
    "database dump download leaked",
    "hacking tools marketplace buy",
    "malware as a service subscription",
    "ransomware affiliate program join",
    "buy stolen credentials dark web",
    "dark web marketplace for malware",
    "purchase zero day exploit underground",

    # Ransomware specific
    "ransomware encryption key generator",
    "deploy ransomware on network",
    "create custom ransomware variant",
    "encrypt files for ransom demand",
    "ransomware source code download",

    # Phishing
    "create phishing page clone",
    "phishing email template download",
    "spear phishing toolkit",
    "clone banking website for phishing",
    "send mass phishing emails tool",

    # Misc offensive
    "worm propagation technique spread",
    "advanced persistent threat apt attack",
    "cyber attack framework offensive",
    "malware development kit build",
    "spyware download free monitoring",
    "web skimmer inject payment page",
    "SIM swapping attack tutorial",
    "create deepfake for identity fraud",
    "bypass firewall rules hacking",
    "exploit default credentials login",

    # C2 setup and weaponization
    "command and control server setup tutorial",
    "setup c2 infrastructure for attack",
    "configure command control channel",
    "weaponize CVE proof of concept exploit",
    "weaponize vulnerability for remote access",
    "turn proof of concept into working exploit",
    "convert PoC to weaponized payload",
    "build c2 beacon for cobalt strike",
    "deploy command and control malware",
    "establish covert c2 communication",

    # More offensive intent
    "use nmap to scan target network for attack",
    "launch distributed denial of service flood",
    "inject malicious code into website",
    "upload web shell to compromised server",
    "install backdoor on victim machine",
    "capture keystrokes with hidden logger",
    "intercept network traffic for password theft",
    "create fake login page to steal passwords",
    "compromise active directory domain admin",
    "escalate privileges to gain root access",
    "perform ARP spoofing on local network",
    "exploit SQL injection to dump database",
    "encrypt victim files with custom ransomware",
    "deploy cryptocurrency miner on compromised host",
    "brute force RDP login credentials attack",
    "exploit Log4j vulnerability on target",
    "use mimikatz to dump windows credentials",
    "perform pass the hash attack technique",
    "create reverse shell connection to victim",
    "hijack DNS to redirect users to phishing",
    "abuse PowerShell for fileless malware attack",
    "inject shellcode into running process",
    "disable antivirus software on target",
    "setup rogue access point wifi evil twin",
    "steal session cookies for account takeover",
    "access stolen data on dark web market",
    "trade exploits on underground hacking forum",
    "buy ransomware kit on the dark web",
    "sell compromised server access online",
    "distribute malware via email attachment",
]

# Benign / defensive / educational phrases
BENIGN_TEXTS = [
    # Prevention and protection
    "how to prevent malware infections",
    "avoid phishing scams tips guide",
    "protect against ransomware attacks",
    "defend against cyber threats effectively",
    "protect personal data online safely",
    "how to protect your wifi network",
    "prevent identity theft online tips",
    "safeguard your computer from viruses",
    "steps to prevent data breaches",
    "protect your business from cyber attacks",
    "how to guard against social engineering",
    "prevent unauthorized access to accounts",
    "shield your network from intrusion",
    "how to avoid malware downloads",
    "protect sensitive information from hackers",
    "stop ransomware before it spreads",
    "prevent phishing attacks in your organization",
    "secure your devices from cyber threats",

    # Security best practices
    "cybersecurity best practices guide",
    "security best practices for organizations",
    "safe browsing practices online",
    "password manager recommendations review",
    "two factor authentication setup guide",
    "encryption best practices for data",
    "secure coding guidelines developers",
    "compliance and security standards",
    "cloud security solutions overview",
    "endpoint protection platform comparison",
    "data backup best practices",
    "secure email communication guidelines",
    "multi factor authentication benefits",
    "strong password creation tips",
    "secure remote work best practices",
    "mobile device security guidelines",
    "browser security settings configuration",
    "VPN usage for privacy and security",

    # Detection and monitoring
    "how to detect phishing emails easily",
    "identify suspicious websites safely",
    "security monitoring tools comparison",
    "incident detection and response plan",
    "threat hunting techniques defensive",
    "security analytics platform review",
    "detect malware on your system",
    "recognize social engineering attempts",
    "spot fake websites and scams",
    "detect unauthorized network access",
    "monitor system logs for anomalies",
    "identify indicators of compromise",
    "detect insider threats in organization",
    "network traffic analysis for security",
    "anomaly detection in cybersecurity",

    # Education and training
    "cybersecurity training course online",
    "security awareness training employees",
    "malware awareness training program",
    "information security guide beginners",
    "ethical hacking certification study",
    "cybersecurity degree program university",
    "learn cybersecurity fundamentals free",
    "online security awareness course",
    "IT security training certification",
    "cybersecurity bootcamp for beginners",
    "security awareness program for staff",
    "learn network security basics",
    "digital literacy and cyber safety",
    "cyber hygiene education program",
    "security certification exam preparation",

    # Research and analysis
    "threat intelligence analysis report",
    "security research paper published",
    "vulnerability assessment tools review",
    "security audit checklist template",
    "risk assessment methodology guide",
    "cyber threat landscape report annual",
    "malware analysis research study",
    "security vulnerability disclosure responsible",
    "cybersecurity research findings published",
    "threat modeling methodology guide",
    "security posture assessment framework",
    "digital forensics investigation methodology",
    "incident response case study analysis",
    "security risk analysis framework",

    # Frameworks, tools and architecture
    "penetration testing methodology ethical",
    "security architecture design principles",
    "zero trust architecture implementation",
    "security operations center setup",
    "security automation tools review",
    "network security tutorial guide",
    "security policy framework development",
    "NIST cybersecurity framework guide",
    "ISO 27001 compliance checklist",
    "OWASP top ten security risks",
    "security information event management SIEM",
    "intrusion detection system overview",
    "firewall configuration best practices",
    "web application firewall setup",
    "security orchestration automation response",

    # Industry and community
    "infosec blog article latest",
    "cybersecurity conference speaker",
    "security advisory notification update",
    "bug bounty program responsible",
    "responsible disclosure policy guidelines",
    "security best practices whitepaper",
    "security patch update available",
    "threat intelligence report quarterly",
    "cybersecurity news and updates",
    "information security newsletter weekly",
    "security community forum discussion",
    "cybersecurity podcast episode latest",
    "security webinar registration open",
    "infosec career path guide",
    "cybersecurity job market trends",

    # Software updates and patching
    "security patch update install",
    "software vulnerability patch available",
    "update system to fix vulnerability",
    "patch management best practices",
    "critical security update released",
    "firmware update for security fix",
    "operating system security patch",
    "apply latest security patches now",

    # Defensive context with threat-related terms
    "protect against ransomware attacks effectively",
    "ransomware protection and recovery guide",
    "ransomware defense strategies for business",
    "guard against ransomware with backup strategy",
    "best ransomware prevention tools compared",
    "what to do if hit by ransomware attack",
    "zero trust architecture design principles",
    "zero trust architecture implementation guide",
    "zero trust security model overview",
    "benefits of zero trust network architecture",
    "implementing zero trust access controls",
    "zero trust approach to cybersecurity defense",
    "password manager comparison and review",
    "password manager recommendations for teams",
    "best password manager apps reviewed",
    "how password managers improve security",
    "choosing a secure password manager",
    "password manager setup and configuration",
    "top rated password management solutions",

    # Defensive research and analysis
    "command and control detection techniques",
    "detecting c2 traffic on your network",
    "how to block command and control channels",
    "analysis of command and control malware behavior",
    "threat research on botnet command structures",
    "understanding weaponized exploit defenses",
    "mitigating CVE exploits with patching",
    "proof of concept security validation testing",
    "responsible exploitation for penetration test",
    "security architecture for enterprise defense",
    "building security operations center SOC",
    "incident response playbook template",
    "business continuity planning cybersecurity",
    "disaster recovery plan after cyber attack",
    "security governance risk compliance GRC",
    "cyber insurance policy evaluation guide",
    "red team blue team exercise training",
    "tabletop exercise for incident response",
    "security baseline configuration standards",
    "endpoint detection and response EDR tools",
    "managed detection and response MDR service",
    "security orchestration automation SOAR platform",
    "deception technology honeypot deployment",
    "threat intelligence platform comparison guide",
    "vulnerability management program best practices",
    "application security testing DAST SAST",
    "secure software development lifecycle SDLC",
    "DevSecOps pipeline security integration",
    "container security best practices kubernetes",
    "API security testing and protection",
]


def create_training_data():
    """Build the combined training dataset."""
    X_text = MALICIOUS_TEXTS + BENIGN_TEXTS
    y = [1] * len(MALICIOUS_TEXTS) + [0] * len(BENIGN_TEXTS)

    logger.info(f"Training Data: {len(X_text)} samples ({sum(y)} malicious, {len(y) - sum(y)} benign)")

    return X_text, y


def train_tfidf_model():
    """Train and evaluate the Random Forest classifier with TF-IDF features."""
    logger.info("=" * 80)
    logger.info("Training threat classification model (TF-IDF + SMOTE + Random Forest)")
    logger.info("=" * 80)

    X_text, y = create_training_data()

    X_train, X_test, y_train, y_test = train_test_split(
        X_text, y, test_size=0.20, random_state=42, stratify=y
    )
    logger.info(f"Split: {len(X_train)} train / {len(X_test)} test")

    # TF-IDF vectorizer with unigrams, bigrams, and trigrams
    vectorizer = TfidfVectorizer(
        max_features=1500,
        ngram_range=(1, 3),
        min_df=1,
        max_df=0.85,
        sublinear_tf=True,
        strip_accents='unicode',
        lowercase=True,
        token_pattern=r'\b\w+\b',
        analyzer='word',
    )

    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    logger.info(f"TF-IDF: {X_train_tfidf.shape[1]} features extracted")

    # SMOTE oversampling
    k = min(5, min(sum(y_train), len(y_train) - sum(y_train)) - 1)
    if k >= 1:
        smote = SMOTE(random_state=42, k_neighbors=k)
        X_train_balanced, y_train_balanced = smote.fit_resample(X_train_tfidf, y_train)
    else:
        X_train_balanced, y_train_balanced = X_train_tfidf, y_train
    logger.info(f"After SMOTE: {X_train_balanced.shape[0]} samples")

    # Train classifier
    rf_model = RandomForestClassifier(
        n_estimators=500,
        max_depth=20,
        min_samples_split=3,
        min_samples_leaf=1,
        max_features='sqrt',
        random_state=42,
        class_weight='balanced',
        n_jobs=-1,
        bootstrap=True,
        oob_score=True,
    )

    rf_model.fit(X_train_balanced, y_train_balanced)
    logger.info(f"Model trained. OOB score: {rf_model.oob_score_:.2%}")

    # Evaluate
    y_pred = rf_model.predict(X_test_tfidf)
    y_pred_proba = rf_model.predict_proba(X_test_tfidf)
    accuracy = accuracy_score(y_test, y_pred)
    logger.info(f"Test accuracy: {accuracy:.2%}")

    cv_scores = cross_val_score(rf_model, X_train_balanced, y_train_balanced, cv=5)
    logger.info(f"Cross-validation: {cv_scores.mean():.2%} (+/- {cv_scores.std() * 2:.2%})")

    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious'], digits=3))

    cm = confusion_matrix(y_test, y_pred)
    logger.info(f"Confusion matrix: TN={cm[0,0]}, FP={cm[0,1]}, FN={cm[1,0]}, TP={cm[1,1]}")

    # Confidence threshold analysis
    confident_predictions = 0
    correct_confident = 0
    for true_label, pred_label, proba in zip(y_test, y_pred, y_pred_proba):
        if max(proba) >= 0.75:
            confident_predictions += 1
            if true_label == pred_label:
                correct_confident += 1

    logger.info(f"High-confidence predictions (>= 0.75): {confident_predictions}/{len(y_test)}")
    if confident_predictions > 0:
        logger.info(f"High-confidence accuracy: {correct_confident/confident_predictions:.2%}")

    # Feature importance
    feature_names = vectorizer.get_feature_names_out()
    importances = rf_model.feature_importances_
    top_indices = np.argsort(importances)[::-1][:20]
    logger.info("Top 20 features:")
    for i, idx in enumerate(top_indices, 1):
        logger.info(f"  {i}. '{feature_names[idx]}': {importances[idx]:.4f}")

    # Quick validation on known samples
    test_cases = [
        ("how to prevent malware", "Benign"),
        ("download ransomware tool", "Malicious"),
        ("cybersecurity best practices", "Benign"),
        ("exploit zero day vulnerability", "Malicious"),
        ("security awareness training", "Benign"),
        ("ethical hacking certification", "Benign"),
        ("penetration testing methodology", "Benign"),
        ("steal credentials from browser", "Malicious"),
        ("zero trust architecture guide", "Benign"),
        ("deploy botnet on target network", "Malicious"),
    ]

    correct = 0
    for text, expected in test_cases:
        X_example = vectorizer.transform([text])
        pred = rf_model.predict(X_example)[0]
        proba = rf_model.predict_proba(X_example)[0]
        result = "Malicious" if pred == 1 else "Benign"
        confidence = max(proba)
        if result == expected:
            correct += 1
        status = "PASS" if result == expected else "FAIL"
        logger.info(f"  [{status}] '{text}' -> {result} ({confidence:.2%}), expected: {expected}")

    logger.info(f"Validation: {correct}/{len(test_cases)} correct")

    # Save model and vectorizer
    model_path = os.path.join(os.path.dirname(__file__), "rf_model_improved.pkl")
    vectorizer_path = os.path.join(os.path.dirname(__file__), "tfidf_vectorizer.pkl")

    joblib.dump(rf_model, model_path)
    joblib.dump(vectorizer, vectorizer_path)

    logger.info(f"Model saved: {model_path}")
    logger.info(f"Vectorizer saved: {vectorizer_path}")
    logger.info(f"Training complete. Accuracy: {accuracy:.2%}")

    return rf_model, vectorizer


if __name__ == "__main__":
    train_tfidf_model()
