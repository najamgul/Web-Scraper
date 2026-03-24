"""
evaluate_model.py
Generates confusion matrix visualization and evaluation metrics report
for the trained threat classification model.
"""

import numpy as np
import joblib
import os
import sys

if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr.encoding != 'utf-8':
    sys.stderr.reconfigure(encoding='utf-8')

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.metrics import (
    confusion_matrix, classification_report, accuracy_score,
    precision_score, recall_score, f1_score, ConfusionMatrixDisplay
)
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from train_improved_model import create_training_data


def evaluate():
    print("\n" + "=" * 65)
    print("LOADING MODEL & DATA")
    print("=" * 65)

    model_path = os.path.join(os.path.dirname(__file__), "rf_model_improved.pkl")
    vectorizer_path = os.path.join(os.path.dirname(__file__), "tfidf_vectorizer.pkl")

    model = joblib.load(model_path)
    vectorizer = joblib.load(vectorizer_path)
    print(f"  Model loaded from: {model_path}")
    print(f"  Vectorizer loaded from: {vectorizer_path}")

    X_text, y = create_training_data()
    X_train, X_test, y_train, y_test = train_test_split(
        X_text, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"  Test samples: {len(X_test)}  (Train: {len(X_train)})")

    X_test_tfidf = vectorizer.transform(X_test)
    y_pred = model.predict(X_test_tfidf)
    y_proba = model.predict_proba(X_test_tfidf)

    # Build confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    cm_norm = cm.astype("float") / cm.sum(axis=1)[:, np.newaxis]

    fig, axes = plt.subplots(1, 2, figsize=(14, 5.5))
    fig.patch.set_facecolor("#0d1117")

    # Raw counts plot
    disp1 = ConfusionMatrixDisplay(
        confusion_matrix=cm, display_labels=["Benign", "Malicious"]
    )
    disp1.plot(ax=axes[0], cmap="Blues", values_format="d", colorbar=False)
    axes[0].set_title("Confusion Matrix  (Counts)", fontsize=13,
                        fontweight="bold", color="white", pad=12)
    axes[0].set_xlabel("Predicted Label", fontsize=11, color="white")
    axes[0].set_ylabel("True Label", fontsize=11, color="white")
    axes[0].tick_params(colors="white")
    axes[0].set_facecolor("#161b22")
    for text_obj in disp1.text_.ravel():
        text_obj.set_fontsize(18)
        text_obj.set_fontweight("bold")

    # Normalized plot
    disp2 = ConfusionMatrixDisplay(
        confusion_matrix=cm_norm, display_labels=["Benign", "Malicious"]
    )
    disp2.plot(ax=axes[1], cmap="Oranges", values_format=".1%", colorbar=False)
    axes[1].set_title("Confusion Matrix  (Normalized)", fontsize=13,
                        fontweight="bold", color="white", pad=12)
    axes[1].set_xlabel("Predicted Label", fontsize=11, color="white")
    axes[1].set_ylabel("True Label", fontsize=11, color="white")
    axes[1].tick_params(colors="white")
    axes[1].set_facecolor("#161b22")
    for text_obj in disp2.text_.ravel():
        text_obj.set_fontsize(18)
        text_obj.set_fontweight("bold")

    fig.suptitle(
        "Threat Classification Model - Confusion Matrix",
        fontsize=16, fontweight="bold", color="white", y=1.02
    )
    plt.tight_layout()

    save_path = os.path.join(os.path.dirname(__file__), "confusion_matrix.png")
    fig.savefig(save_path, dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close(fig)

    # Print metrics
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    print("\n" + "=" * 65)
    print("MODEL EVALUATION REPORT")
    print("=" * 65)

    print(f"\n  {'Metric':<30} {'Value':>10}")
    print("  " + "-" * 42)
    print(f"  {'Accuracy':<30} {acc:>10.2%}")
    print(f"  {'Precision  (Malicious)':<30} {prec:>10.2%}")
    print(f"  {'Recall     (Malicious)':<30} {rec:>10.2%}")
    print(f"  {'F1-Score   (Malicious)':<30} {f1:>10.2%}")

    print(f"\n  Confusion Matrix Breakdown:")
    print(f"     True Negatives  (TN): {cm[0, 0]:>4}  - Benign correctly identified")
    print(f"     False Positives (FP): {cm[0, 1]:>4}  - Benign wrongly flagged as threat")
    print(f"     False Negatives (FN): {cm[1, 0]:>4}  - Actual threats missed")
    print(f"     True Positives  (TP): {cm[1, 1]:>4}  - Threats correctly caught")

    print(f"\n  Full Classification Report:\n")
    print(classification_report(
        y_test, y_pred,
        target_names=["Benign", "Malicious"],
        digits=3
    ))

    # Per-sample predictions
    print("  Individual Test Predictions:")
    print(f"  {'#':<4} {'Text':<45} {'True':<12} {'Pred':<12} {'Conf':>8}  {'':>3}")
    print("  " + "-" * 90)
    for i, (text, true, pred, proba) in enumerate(
        zip(X_test, y_test, y_pred, y_proba), 1
    ):
        label_true = "Malicious" if true == 1 else "Benign"
        label_pred = "Malicious" if pred == 1 else "Benign"
        conf = max(proba) * 100
        status = "OK" if true == pred else "MISS"
        short_text = (text[:42] + "...") if len(text) > 45 else text
        print(f"  {i:<4} {short_text:<45} {label_true:<12} {label_pred:<12} {conf:>6.1f}%  {status:>4}")

    print(f"\n  Confusion matrix heatmap saved to: {save_path}")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    evaluate()
