#!/usr/bin/env python
"""
Quick script to retrain the improved ML model
Run this to update the model with the new TF-IDF + SMOTE approach
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    print("\n" + "="*80)
    print("🚀 RETRAINING IMPROVED ML MODEL")
    print("="*80 + "\n")
    
    # Import and run training
    from train_improved_model import train_tfidf_model
    
    try:
        model, vectorizer = train_tfidf_model()
        print("\n✅ Model training completed successfully!")
        print("\nThe following files have been created/updated:")
        print("  - rf_model_improved.pkl (Random Forest model)")
        print("  - tfidf_vectorizer.pkl (TF-IDF vectorizer)")
        print("\n🎯 Next steps:")
        print("  1. Restart your Flask application")
        print("  2. Test the improved classification")
        print("  3. Monitor the detailed logs for confidence scores\n")
        
    except Exception as e:
        print(f"\n❌ Error during training: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
