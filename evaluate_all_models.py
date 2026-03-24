"""
evaluate_all_models.py
======================
Generates confusion matrices and evaluation reports for ALL trained models.
"""

import os, sys, json
import numpy as np
import joblib

if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.metrics import (
    confusion_matrix, classification_report, accuracy_score,
    precision_score, recall_score, f1_score, ConfusionMatrixDisplay
)
from sklearn.model_selection import train_test_split

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")

sys.path.insert(0, BASE_DIR)
from train_all_models import (
    generate_keyword_data,
    generate_ip_features, generate_hash_features,
    extract_url_features, extract_domain_features,
    generate_benign_url, generate_malicious_url,
    generate_edge_case_benign_url, generate_edge_case_malicious_url,
    LEGIT_PATTERNS, MALICIOUS_DOMAIN_PATTERNS,
    RANDOM_STATE
)

import random
random.seed(RANDOM_STATE)
np.random.seed(RANDOM_STATE)


def evaluate_model(name, model, X_test, y_test, class_names, scaler=None, vectorizer=None):
    """Evaluate and print metrics for a single model."""
    if vectorizer:
        X_test_transformed = vectorizer.transform(X_test)
    elif scaler:
        X_test_transformed = scaler.transform(X_test)
    else:
        X_test_transformed = X_test

    y_pred = model.predict(X_test_transformed)
    y_proba = model.predict_proba(X_test_transformed) if hasattr(model, 'predict_proba') else None

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    rec = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print(f"\n{'='*65}")
    print(f"  {name} MODEL EVALUATION")
    print(f"{'='*65}")
    print(f"\n  {'Metric':<30} {'Value':>10}")
    print(f"  {'-'*42}")
    print(f"  {'Accuracy':<30} {acc:>10.2%}")
    print(f"  {'Precision':<30} {prec:>10.2%}")
    print(f"  {'Recall':<30} {rec:>10.2%}")
    print(f"  {'F1-Score':<30} {f1:>10.2%}")
    print(f"\n  Confusion Matrix:")
    for i, label in enumerate(class_names):
        print(f"    {label}: {cm[i]}")
    print(f"\n{classification_report(y_test, y_pred, target_names=class_names, digits=3)}")

    return {"name": name, "acc": acc, "prec": prec, "rec": rec, "f1": f1, "cm": cm, "y_test": y_test, "y_pred": y_pred}


def plot_all_confusion_matrices(results, class_names_map):
    """Plot confusion matrices for all 5 models in a single figure."""
    fig, axes = plt.subplots(1, 5, figsize=(28, 5))
    fig.patch.set_facecolor("#0d1117")

    colors = ["Blues", "Greens", "Oranges", "Purples", "Reds"]

    for i, (result, cmap) in enumerate(zip(results, colors)):
        cm = result["cm"]
        names = class_names_map.get(result["name"], ["Benign", "Malicious"])

        disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=names)
        disp.plot(ax=axes[i], cmap=cmap, values_format="d", colorbar=False)

        axes[i].set_title(f"{result['name']}\nAcc: {result['acc']:.1%}", fontsize=11,
                          fontweight="bold", color="white", pad=10)
        axes[i].set_xlabel("Predicted", fontsize=9, color="white")
        axes[i].set_ylabel("True", fontsize=9, color="white")
        axes[i].tick_params(colors="white", labelsize=8)
        axes[i].set_facecolor("#161b22")
        for text_obj in disp.text_.ravel():
            text_obj.set_fontsize(14)
            text_obj.set_fontweight("bold")

    fig.suptitle("Threat Classification Models - Confusion Matrices (All IOC Types)",
                 fontsize=16, fontweight="bold", color="white", y=1.05)
    plt.tight_layout()

    save_path = os.path.join(BASE_DIR, "all_models_confusion_matrix.png")
    fig.savefig(save_path, dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close(fig)
    print(f"\n  Combined confusion matrix saved to: {save_path}")
    return save_path


def main():
    print("\n" + "=" * 65)
    print("  EVALUATING ALL TRAINED MODELS")
    print("=" * 65)

    results = []

    # 1. KEYWORD MODEL
    print("\n[1/5] Loading Keyword Model...")
    kw_model = joblib.load(os.path.join(MODELS_DIR, "keyword_model.pkl"))
    kw_vec = joblib.load(os.path.join(MODELS_DIR, "keyword_vectorizer.pkl"))
    X_text, y = generate_keyword_data()
    _, X_test, _, y_test = train_test_split(X_text, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y)
    results.append(evaluate_model("Keyword", kw_model, X_test, np.array(y_test),
                                  ["Benign", "Malicious"], vectorizer=kw_vec))

    # 2. URL MODEL
    print("\n[2/5] Loading URL Model...")
    url_model = joblib.load(os.path.join(MODELS_DIR, "url_model.pkl"))
    url_scaler = joblib.load(os.path.join(MODELS_DIR, "url_scaler.pkl"))
    urls, labels = [], []
    for _ in range(1000):
        urls.append(generate_benign_url()); labels.append(0)
    for _ in range(100):
        urls.append(generate_edge_case_benign_url()); labels.append(0)
    for _ in range(1000):
        urls.append(generate_malicious_url()); labels.append(1)
    for _ in range(100):
        urls.append(generate_edge_case_malicious_url()); labels.append(1)
    X_url = np.array([extract_url_features(u) for u in urls])
    results.append(evaluate_model("URL", url_model, X_url, np.array(labels),
                                  ["Benign", "Malicious"], scaler=url_scaler))

    # 3. IP MODEL
    print("\n[3/5] Loading IP Model...")
    ip_model = joblib.load(os.path.join(MODELS_DIR, "ip_model.pkl"))
    ip_scaler = joblib.load(os.path.join(MODELS_DIR, "ip_scaler.pkl"))
    X_ip, y_ip = [], []
    for _ in range(800):
        X_ip.append(generate_ip_features(0, False)); y_ip.append(0)
    for _ in range(200):
        X_ip.append(generate_ip_features(0, True)); y_ip.append(0)
    for _ in range(800):
        X_ip.append(generate_ip_features(1, False)); y_ip.append(1)
    for _ in range(200):
        X_ip.append(generate_ip_features(1, True)); y_ip.append(1)
    X_ip = np.array(X_ip, dtype=np.float32)
    results.append(evaluate_model("IP", ip_model, X_ip, np.array(y_ip),
                                  ["Benign", "Malicious"], scaler=ip_scaler))

    # 4. DOMAIN MODEL
    print("\n[4/5] Loading Domain Model...")
    dom_model = joblib.load(os.path.join(MODELS_DIR, "domain_model.pkl"))
    dom_scaler = joblib.load(os.path.join(MODELS_DIR, "domain_scaler.pkl"))
    domains, d_labels = [], []
    for _ in range(1000):
        domains.append(random.choice(LEGIT_PATTERNS)()); d_labels.append(0)
    for _ in range(1000):
        domains.append(random.choice(MALICIOUS_DOMAIN_PATTERNS)()); d_labels.append(1)
    X_dom = np.array([extract_domain_features(d) for d in domains])
    results.append(evaluate_model("Domain", dom_model, X_dom, np.array(d_labels),
                                  ["Benign", "Malicious"], scaler=dom_scaler))

    # 5. HASH MODEL
    print("\n[5/5] Loading Hash Model...")
    hash_model = joblib.load(os.path.join(MODELS_DIR, "hash_model.pkl"))
    hash_scaler = joblib.load(os.path.join(MODELS_DIR, "hash_scaler.pkl"))
    X_hash, y_hash = [], []
    for _ in range(800):
        X_hash.append(generate_hash_features(0, False)); y_hash.append(0)
    for _ in range(200):
        X_hash.append(generate_hash_features(0, True)); y_hash.append(0)
    for _ in range(800):
        X_hash.append(generate_hash_features(1, False)); y_hash.append(1)
    for _ in range(200):
        X_hash.append(generate_hash_features(1, True)); y_hash.append(1)
    X_hash = np.array(X_hash, dtype=np.float32)
    results.append(evaluate_model("Hash", hash_model, X_hash, np.array(y_hash),
                                  ["Benign", "Malicious"], scaler=hash_scaler))

    # COMBINED CONFUSION MATRIX
    class_names_map = {r["name"]: ["Benign", "Malicious"] for r in results}
    plot_all_confusion_matrices(results, class_names_map)

    # SUMMARY TABLE
    print(f"\n{'='*65}")
    print(f"  FINAL SUMMARY - ALL MODELS")
    print(f"{'='*65}")
    print(f"\n  {'Model':<15} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>8}")
    print(f"  {'-'*55}")
    for r in results:
        print(f"  {r['name']:<15} {r['acc']:>10.2%} {r['prec']:>10.2%} {r['rec']:>10.2%} {r['f1']:>8.4f}")
    print(f"\n{'='*65}\n")


if __name__ == "__main__":
    main()
