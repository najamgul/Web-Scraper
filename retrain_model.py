#!/usr/bin/env python
"""Retrain the threat classification model."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    print("\n" + "="*80)
    print("RETRAINING THREAT CLASSIFICATION MODEL")
    print("="*80 + "\n")

    from train_improved_model import train_tfidf_model

    try:
        model, vectorizer = train_tfidf_model()
        print("\nModel training completed successfully!")
        print("\nFiles created/updated:")
        print("  - rf_model_improved.pkl (Random Forest model)")
        print("  - tfidf_vectorizer.pkl (TF-IDF vectorizer)")
        print("\nNext steps:")
        print("  1. Restart your Flask application")
        print("  2. Test the improved classification")
        print("  3. Monitor the detailed logs for confidence scores\n")

    except Exception as e:
        print(f"\nError during training: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
