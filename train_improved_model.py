# train_improved_model.py
"""
Train Improved Random Forest Model with:
- TF-IDF vectorization with bigrams
- SMOTE for dataset balancing
- Enhanced feature engineering
- Model evaluation and persistence
"""

import numpy as np
import joblib
import os
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# ============================================
# TRAINING DATA
# ============================================

# Malicious keywords and phrases
MALICIOUS_TEXTS = [
    "download malware free",
    "ransomware attack tools",
    "how to hack facebook account",
    "crack windows password",
    "exploit vulnerability CVE",
    "zero day exploit for sale",
    "backdoor trojan download",
    "keylogger software free",
    "botnet control panel",
    "phishing kit download",
    "steal credentials tutorial",
    "remote access trojan rat",
    "cryptojacking script",
    "ddos attack tool",
    "brute force password cracker",
    "sql injection tool",
    "bypass antivirus detection",
    "command and control server",
    "privilege escalation exploit",
    "lateral movement techniques",
    "data exfiltration methods",
    "persistence mechanism windows",
    "rootkit installation guide",
    "spyware download free",
    "credit card dumping tool",
    "bank account hacking",
    "social engineering toolkit",
    "man in the middle attack",
    "wifi password cracker",
    "network sniffing tools",
    "malicious payload generator",
    "reverse shell backdoor",
    "webshell upload exploit",
    "ransomware encryption key",
    "trojan horse virus",
    "worm propagation technique",
    "advanced persistent threat apt",
    "cyber attack framework",
    "malware development kit",
    "exploit development tutorial",
]

# Benign/Educational keywords and phrases
BENIGN_TEXTS = [
    "how to prevent malware infections",
    "avoid phishing scams tips",
    "protect against ransomware attacks",
    "cybersecurity best practices",
    "malware awareness training",
    "security vulnerability patch",
    "antivirus software comparison",
    "how to detect phishing emails",
    "secure your online accounts",
    "password manager recommendations",
    "two factor authentication setup",
    "security awareness education",
    "identify suspicious websites",
    "safe browsing practices",
    "protect personal data online",
    "cybersecurity training course",
    "information security guide",
    "network security tutorial",
    "defend against cyber threats",
    "security incident response",
    "threat intelligence analysis",
    "vulnerability assessment tools",
    "penetration testing methodology",
    "ethical hacking certification",
    "security audit checklist",
    "compliance and security",
    "encryption best practices",
    "secure coding guidelines",
    "security monitoring tools",
    "incident detection and response",
    "security policy framework",
    "risk assessment methodology",
    "security architecture design",
    "cloud security solutions",
    "endpoint protection platform",
    "security operations center",
    "threat hunting techniques",
    "security analytics platform",
    "zero trust architecture",
    "security automation tools",
]

# Additional context-specific examples
MALICIOUS_TEXTS_EXTENDED = MALICIOUS_TEXTS + [
    "buy exploit kit",
    "malware as a service",
    "hacking tools marketplace",
    "dark web hacking forum",
    "stolen data marketplace",
    "carding forum access",
    "botnet rental service",
    "ransomware affiliate program",
    "credential stuffing list",
    "database dump download",
]

BENIGN_TEXTS_EXTENDED = BENIGN_TEXTS + [
    "cybersecurity conference",
    "infosec blog article",
    "security research paper",
    "vulnerability disclosure",
    "security patch update",
    "threat intelligence report",
    "security advisory notification",
    "bug bounty program",
    "responsible disclosure policy",
    "security best practices whitepaper",
]


def create_training_data():
    """
    Create balanced training dataset
    """
    # Combine texts
    X_text = MALICIOUS_TEXTS_EXTENDED + BENIGN_TEXTS_EXTENDED
    y = [1] * len(MALICIOUS_TEXTS_EXTENDED) + [0] * len(BENIGN_TEXTS_EXTENDED)
    
    logger.info(f"📊 Training Data:")
    logger.info(f"   Total samples: {len(X_text)}")
    logger.info(f"   Malicious: {sum(y)}")
    logger.info(f"   Benign: {len(y) - sum(y)}")
    
    return X_text, y


def train_tfidf_model():
    """
    Train Random Forest model with TF-IDF and SMOTE
    """
    logger.info("="*80)
    logger.info("🚀 TRAINING IMPROVED ML MODEL")
    logger.info("="*80)
    
    # Get training data
    X_text, y = create_training_data()
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_text, y, test_size=0.25, random_state=42, stratify=y
    )
    
    logger.info(f"\n📊 Data Split:")
    logger.info(f"   Training samples: {len(X_train)}")
    logger.info(f"   Test samples: {len(X_test)}")
    
    # Create TF-IDF vectorizer with bigrams
    logger.info(f"\n🔤 Creating TF-IDF vectorizer with bigrams...")
    vectorizer = TfidfVectorizer(
        max_features=500,
        ngram_range=(1, 2),  # Unigrams and bigrams
        min_df=1,
        max_df=0.8,
        sublinear_tf=True,
        strip_accents='unicode',
        lowercase=True,
        token_pattern=r'\b\w+\b'
    )
    
    # Transform training data
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    
    logger.info(f"✅ TF-IDF features created: {X_train_tfidf.shape[1]} features")
    
    # Apply SMOTE for balancing
    logger.info(f"\n⚖️ Applying SMOTE for dataset balancing...")
    smote = SMOTE(random_state=42, k_neighbors=min(5, sum(y_train) - 1))
    X_train_balanced, y_train_balanced = smote.fit_resample(X_train_tfidf, y_train)
    
    logger.info(f"✅ After SMOTE:")
    logger.info(f"   Training samples: {X_train_balanced.shape[0]}")
    logger.info(f"   Malicious: {sum(y_train_balanced)}")
    logger.info(f"   Benign: {len(y_train_balanced) - sum(y_train_balanced)}")
    
    # Train Random Forest
    logger.info(f"\n🌲 Training Random Forest Classifier...")
    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features='sqrt',
        random_state=42,
        class_weight='balanced',
        n_jobs=-1
    )
    
    rf_model.fit(X_train_balanced, y_train_balanced)
    logger.info(f"✅ Model trained successfully")
    
    # Evaluate on test set
    logger.info(f"\n📈 Model Evaluation:")
    y_pred = rf_model.predict(X_test_tfidf)
    y_pred_proba = rf_model.predict_proba(X_test_tfidf)
    
    accuracy = accuracy_score(y_test, y_pred)
    logger.info(f"   Accuracy: {accuracy:.2%}")
    
    # Cross-validation
    cv_scores = cross_val_score(rf_model, X_train_balanced, y_train_balanced, cv=5)
    logger.info(f"   Cross-validation scores: {cv_scores}")
    logger.info(f"   Mean CV accuracy: {cv_scores.mean():.2%} (+/- {cv_scores.std() * 2:.2%})")
    
    # Classification report
    logger.info(f"\n📋 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious'], digits=3))
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    logger.info(f"\n🔢 Confusion Matrix:")
    logger.info(f"   [[TN={cm[0,0]}, FP={cm[0,1]}],")
    logger.info(f"    [FN={cm[1,0]}, TP={cm[1,1]}]]")
    
    # Test with confidence threshold
    logger.info(f"\n🎯 Testing with 0.75 confidence threshold:")
    confident_predictions = 0
    correct_confident = 0
    
    for i, (true_label, pred_label, proba) in enumerate(zip(y_test, y_pred, y_pred_proba)):
        max_confidence = max(proba)
        if max_confidence >= 0.75:
            confident_predictions += 1
            if true_label == pred_label:
                correct_confident += 1
    
    logger.info(f"   Confident predictions (>= 0.75): {confident_predictions}/{len(y_test)}")
    logger.info(f"   Accuracy on confident predictions: {correct_confident/max(confident_predictions, 1):.2%}")
    
    # Feature importance
    logger.info(f"\n🏆 Top 20 Important Features:")
    feature_names = vectorizer.get_feature_names_out()
    importances = rf_model.feature_importances_
    indices = np.argsort(importances)[::-1][:20]
    
    for i, idx in enumerate(indices, 1):
        logger.info(f"   {i}. '{feature_names[idx]}': {importances[idx]:.4f}")
    
    # Test specific examples
    logger.info(f"\n🧪 Testing Specific Examples:")
    test_cases = [
        ("how to prevent malware", "Benign"),
        ("download ransomware tool", "Malicious"),
        ("cybersecurity best practices", "Benign"),
        ("exploit zero day vulnerability", "Malicious"),
        ("security awareness training", "Benign"),
    ]
    
    for text, expected in test_cases:
        X_example = vectorizer.transform([text])
        pred = rf_model.predict(X_example)[0]
        proba = rf_model.predict_proba(X_example)[0]
        
        result = "Malicious" if pred == 1 else "Benign"
        confidence = max(proba)
        status = "✅" if result == expected else "❌"
        
        logger.info(f"   {status} '{text}'")
        logger.info(f"      → {result} (confidence: {confidence:.2%}, expected: {expected})")
    
    # Save models
    logger.info(f"\n💾 Saving models...")
    model_path = os.path.join(os.path.dirname(__file__), "rf_model_improved.pkl")
    vectorizer_path = os.path.join(os.path.dirname(__file__), "tfidf_vectorizer.pkl")
    
    joblib.dump(rf_model, model_path)
    joblib.dump(vectorizer, vectorizer_path)
    
    logger.info(f"✅ Model saved to: {model_path}")
    logger.info(f"✅ Vectorizer saved to: {vectorizer_path}")
    
    logger.info(f"\n{'='*80}")
    logger.info(f"✅ MODEL TRAINING COMPLETE!")
    logger.info(f"{'='*80}\n")
    
    return rf_model, vectorizer


if __name__ == "__main__":
    train_tfidf_model()
