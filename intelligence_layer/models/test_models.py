# test_models.py
"""
Test all supervised models together
"""

from supervised import train_supervised_model

if __name__ == "__main__":
    print("="*60)
    print("🚀 Testing Supervised Models (Random Forest + XGBoost) on CIC-IDS2017 Dataset")
    print("="*60)
    
    # Train and test models
    clf_rf, clf_xgb, encoder = train_supervised_model(sample_frac=0.1)  # Use 10% dataset for memory safety
    
    print("="*60)
    print("✅ Supervised Models Test Completed")
    print("="*60)


from unsupervised import (
    load_unsupervised_data,
    train_isolation_forest,
    train_autoencoder,
    train_clustering
)

print("\n============================================================")
print("🚀 Testing Unsupervised Models on CIC-IDS2017 Dataset")
print("============================================================")

try:
    X_unsup = load_unsupervised_data(sample_frac=0.03)
    iso = train_isolation_forest(X_unsup)
    ae = train_autoencoder(X_unsup)
    km = train_clustering(X_unsup)
    print("\n✅ All Unsupervised Models trained successfully!")
except Exception as e:
    print(f"❌ Error during unsupervised model training: {e}")

print("============================================================")
print("✅ Full Intelligence Layer Model Test Completed")
print("============================================================")

