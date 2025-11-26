"""
PALADIN - Model Evaluation
File: log_pipeline/consumer/training/evaluate_models.py

Detailed evaluation of trained models
"""

import pandas as pd
import numpy as np
import joblib
import json
from pathlib import Path
from sklearn.metrics import (
    classification_report, confusion_matrix, 
    accuracy_score, precision_recall_fscore_support
)
import warnings
warnings.filterwarnings('ignore')

print("="*70)
print("📊 PALADIN MODEL EVALUATION")
print("="*70)

# Configuration
BASE_DIR = Path('/app')
DATA_DIR = BASE_DIR / 'data/cic_ids_2017/processed'
MODEL_DIR = BASE_DIR / 'models/supervised'

# Load test data
print("\n📥 Loading test data...")
test_df = pd.read_csv(DATA_DIR / 'test_balanced.csv')
X_test = test_df.drop('label', axis=1).values
y_test = test_df['label'].values

with open(DATA_DIR / 'label_mapping.json', 'r') as f:
    label_mapping = json.load(f)
    label_mapping = {int(k): v for k, v in label_mapping.items()}

print(f"✅ Test set: {len(X_test):,} samples")

# Load models
print("\n📦 Loading models...")
rf_model = joblib.load(MODEL_DIR / 'random_forest.pkl')
xgb_model = joblib.load(MODEL_DIR / 'xgboost.pkl')
scaler = joblib.load(MODEL_DIR / 'scaler_supervised.pkl')

X_test_scaled = scaler.transform(X_test)

# ============================================================================
# RANDOM FOREST EVALUATION
# ============================================================================

print("\n" + "="*70)
print("🌲 RANDOM FOREST EVALUATION")
print("="*70)

rf_pred = rf_model.predict(X_test_scaled)
rf_acc = accuracy_score(y_test, rf_pred)

print(f"\n✅ Accuracy: {rf_acc*100:.2f}%")
print("\n📊 Classification Report:")
print(classification_report(
    y_test, 
    rf_pred, 
    target_names=[label_mapping[i] for i in sorted(label_mapping.keys())],
    digits=4
))

# Confusion Matrix
print("\n📈 Confusion Matrix:")
cm = confusion_matrix(y_test, rf_pred)
print("     ", end="")
for i in sorted(label_mapping.keys()):
    print(f"{label_mapping[i][:8]:>8s}", end=" ")
print()
for i, row in enumerate(cm):
    print(f"{label_mapping[i][:8]:8s}", end=" ")
    for val in row:
        print(f"{val:>8d}", end=" ")
    print()

# Per-class metrics
print("\n📊 Per-Class Performance:")
precision, recall, f1, support = precision_recall_fscore_support(y_test, rf_pred)
for i in sorted(label_mapping.keys()):
    print(f"   {label_mapping[i]:20s}: P={precision[i]:.4f} | R={recall[i]:.4f} | F1={f1[i]:.4f} | N={support[i]:>6,}")

# ============================================================================
# XGBOOST EVALUATION
# ============================================================================

print("\n" + "="*70)
print("🚀 XGBOOST EVALUATION")
print("="*70)

xgb_pred = xgb_model.predict(X_test_scaled)
xgb_acc = accuracy_score(y_test, xgb_pred)

print(f"\n✅ Accuracy: {xgb_acc*100:.2f}%")
print("\n📊 Classification Report:")
print(classification_report(
    y_test, 
    xgb_pred, 
    target_names=[label_mapping[i] for i in sorted(label_mapping.keys())],
    digits=4
))

# Per-class metrics
print("\n📊 Per-Class Performance:")
precision, recall, f1, support = precision_recall_fscore_support(y_test, xgb_pred)
for i in sorted(label_mapping.keys()):
    print(f"   {label_mapping[i]:20s}: P={precision[i]:.4f} | R={recall[i]:.4f} | F1={f1[i]:.4f} | N={support[i]:>6,}")

# ============================================================================
# ENSEMBLE EVALUATION
# ============================================================================

print("\n" + "="*70)
print("🎯 ENSEMBLE EVALUATION (RF 40% + XGB 60%)")
print("="*70)

rf_proba = rf_model.predict_proba(X_test_scaled)
xgb_proba = xgb_model.predict_proba(X_test_scaled)

# Weighted ensemble
ensemble_proba = 0.4 * rf_proba + 0.6 * xgb_proba
ensemble_pred = np.argmax(ensemble_proba, axis=1)
ensemble_acc = accuracy_score(y_test, ensemble_pred)

print(f"\n✅ Ensemble Accuracy: {ensemble_acc*100:.2f}%")
print("\n📊 Classification Report:")
print(classification_report(
    y_test, 
    ensemble_pred, 
    target_names=[label_mapping[i] for i in sorted(label_mapping.keys())],
    digits=4
))

# ============================================================================
# COMPARISON
# ============================================================================

print("\n" + "="*70)
print("📊 MODEL COMPARISON")
print("="*70)

print(f"\n{'Model':<20s} {'Accuracy':<12s} {'Improvement':<15s}")
print("-" * 50)
print(f"{'Random Forest':<20s} {rf_acc*100:>10.2f}%")
print(f"{'XGBoost':<20s} {xgb_acc*100:>10.2f}%  {(xgb_acc-rf_acc)*100:>+6.2f}%")
print(f"{'Ensemble':<20s} {ensemble_acc*100:>10.2f}%  {(ensemble_acc-xgb_acc)*100:>+6.2f}%")

# ============================================================================
# ERROR ANALYSIS
# ============================================================================

print("\n" + "="*70)
print("❌ ERROR ANALYSIS")
print("="*70)

errors = ensemble_pred != y_test
error_count = errors.sum()

print(f"\n🔍 Total Errors: {error_count:,} / {len(y_test):,} ({error_count/len(y_test)*100:.2f}%)")

if error_count > 0:
    print("\n📊 Most Common Misclassifications:")
    error_pairs = []
    for i in range(len(y_test)):
        if errors[i]:
            error_pairs.append((label_mapping[y_test[i]], label_mapping[ensemble_pred[i]]))
    
    from collections import Counter
    common_errors = Counter(error_pairs).most_common(10)
    for (true, pred), count in common_errors:
        print(f"   {true:15s} → {pred:15s}: {count:>4,} times")

# ============================================================================
# SUMMARY
# ============================================================================

print("\n" + "="*70)
print("✅ EVALUATION COMPLETE!")
print("="*70)

print(f"\n🎯 Final Ensemble Performance:")
print(f"   Accuracy:  {ensemble_acc*100:.2f}%")
print(f"   Errors:    {error_count:,} / {len(y_test):,}")

best_model = "Ensemble" if ensemble_acc >= max(rf_acc, xgb_acc) else ("XGBoost" if xgb_acc > rf_acc else "Random Forest")
print(f"\n🏆 Best Model: {best_model}")

print(f"\n📊 Attack Detection Performance:")
for i in sorted(label_mapping.keys()):
    if label_mapping[i] != 'NORMAL':
        mask = y_test == i
        if mask.sum() > 0:
            acc = (ensemble_pred[mask] == y_test[mask]).mean()
            print(f"   {label_mapping[i]:20s}: {acc*100:.2f}% ({mask.sum():>6,} samples)")

print("\n🚀 Models ready for deployment!")