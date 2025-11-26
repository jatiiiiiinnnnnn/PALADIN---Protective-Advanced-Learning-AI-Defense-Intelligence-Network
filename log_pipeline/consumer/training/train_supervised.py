"""
PALADIN - Supervised Model Training on CIC-IDS2017
File: log_pipeline/consumer/training/train_supervised.py

Trains Random Forest and XGBoost models on preprocessed CIC-IDS2017 data
"""

import pandas as pd
import numpy as np
import joblib
import json
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import xgboost as xgb
import warnings
warnings.filterwarnings('ignore')

print("="*70)
print("🤖 PALADIN SUPERVISED MODEL TRAINING (CIC-IDS2017)")
print("="*70)

# Configuration
BASE_DIR = Path('/app')
DATA_DIR = BASE_DIR / 'data/cic_ids_2017/processed'
MODEL_DIR = BASE_DIR / 'models/supervised'
MODEL_DIR.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42

# ============================================================================
# STEP 1: LOAD PREPROCESSED DATA
# ============================================================================

print("\n📥 Step 1: Loading preprocessed data...")

train_df = pd.read_csv(DATA_DIR / 'train_balanced.csv')
val_df = pd.read_csv(DATA_DIR / 'val_balanced.csv')
test_df = pd.read_csv(DATA_DIR / 'test_balanced.csv')

with open(DATA_DIR / 'label_mapping.json', 'r') as f:
    label_mapping = json.load(f)
    # Convert string keys to int
    label_mapping = {int(k): v for k, v in label_mapping.items()}

print(f"✅ Loaded datasets:")
print(f"   Train: {len(train_df):>7,} samples")
print(f"   Val:   {len(val_df):>7,} samples")
print(f"   Test:  {len(test_df):>7,} samples")

# Separate features and labels
X_train = train_df.drop('label', axis=1).values
y_train = train_df['label'].values

X_val = val_df.drop('label', axis=1).values
y_val = val_df['label'].values

X_test = test_df.drop('label', axis=1).values
y_test = test_df['label'].values

print(f"\n📊 Features: {X_train.shape[1]}")
print(f"📊 Classes: {len(label_mapping)}")
for idx, name in label_mapping.items():
    count = (y_train == idx).sum()
    print(f"   {name:20s}: {count:>7,} samples")

# ============================================================================
# STEP 2: SCALE FEATURES
# ============================================================================

print("\n📏 Step 2: Scaling features...")

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)
X_test_scaled = scaler.transform(X_test)

print("✅ Features scaled")

# ============================================================================
# STEP 3: TRAIN RANDOM FOREST
# ============================================================================

print("\n" + "="*70)
print("🌲 Step 3: Training Random Forest...")
print("="*70)

rf_model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    class_weight='balanced',
    random_state=RANDOM_STATE,
    n_jobs=-1,
    verbose=1
)

print("\n🔄 Training Random Forest (this may take 10-30 minutes)...")
rf_model.fit(X_train_scaled, y_train)

# Evaluate on validation set
rf_val_pred = rf_model.predict(X_val_scaled)
rf_val_acc = accuracy_score(y_val, rf_val_pred)

print(f"\n✅ Random Forest Validation Accuracy: {rf_val_acc*100:.2f}%")

# Test set evaluation
rf_test_pred = rf_model.predict(X_test_scaled)
rf_test_acc = accuracy_score(y_test, rf_test_pred)

print(f"✅ Random Forest Test Accuracy: {rf_test_acc*100:.2f}%")

print("\n📊 Classification Report (Test Set):")
print(classification_report(
    y_test, 
    rf_test_pred, 
    target_names=[label_mapping[i] for i in sorted(label_mapping.keys())],
    digits=4
))

# Feature importance
feature_names = train_df.drop('label', axis=1).columns
importance = rf_model.feature_importances_
top_features = sorted(zip(feature_names, importance), key=lambda x: x[1], reverse=True)[:10]

print("\n🔍 Top 10 Most Important Features:")
for name, imp in top_features:
    print(f"   {name:30s}: {imp:.4f}")

# ============================================================================
# STEP 4: TRAIN XGBOOST
# ============================================================================

print("\n" + "="*70)
print("🚀 Step 4: Training XGBoost...")
print("="*70)

xgb_model = xgb.XGBClassifier(
    n_estimators=100,
    max_depth=10,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    gamma=0.1,
    random_state=RANDOM_STATE,
    eval_metric='mlogloss',
    use_label_encoder=False,
    n_jobs=-1,
    verbosity=1
)

print("\n🔄 Training XGBoost (this may take 10-30 minutes)...")
xgb_model.fit(X_train_scaled, y_train)

# Evaluate
xgb_val_pred = xgb_model.predict(X_val_scaled)
xgb_val_acc = accuracy_score(y_val, xgb_val_pred)

print(f"\n✅ XGBoost Validation Accuracy: {xgb_val_acc*100:.2f}%")

xgb_test_pred = xgb_model.predict(X_test_scaled)
xgb_test_acc = accuracy_score(y_test, xgb_test_pred)

print(f"✅ XGBoost Test Accuracy: {xgb_test_acc*100:.2f}%")

print("\n📊 Classification Report (Test Set):")
print(classification_report(
    y_test, 
    xgb_test_pred, 
    target_names=[label_mapping[i] for i in sorted(label_mapping.keys())],
    digits=4
))

# ============================================================================
# STEP 5: SAVE MODELS
# ============================================================================

print("\n" + "="*70)
print("💾 Step 5: Saving models...")
print("="*70)

joblib.dump(rf_model, MODEL_DIR / 'random_forest.pkl')
joblib.dump(xgb_model, MODEL_DIR / 'xgboost.pkl')
joblib.dump(scaler, MODEL_DIR / 'scaler_supervised.pkl')

# Save label mapping with proper format
label_names_dict = label_mapping
joblib.dump(label_names_dict, MODEL_DIR / 'label_names.pkl')

# Also save as JSON for reference
with open(MODEL_DIR / 'label_names.json', 'w') as f:
    json.dump(label_names_dict, f, indent=2)

print(f"✅ Models saved to: {MODEL_DIR}")
print(f"   - random_forest.pkl")
print(f"   - xgboost.pkl")
print(f"   - scaler_supervised.pkl")
print(f"   - label_names.pkl")

# ============================================================================
# STEP 6: TEST PREDICTIONS
# ============================================================================

print("\n" + "="*70)
print("🧪 Step 6: Testing predictions on sample data...")
print("="*70)

# Get some test samples
for i in range(min(5, len(X_test))):
    sample = X_test_scaled[i:i+1]
    true_label = label_mapping[y_test[i]]
    
    rf_pred = rf_model.predict(sample)[0]
    rf_proba = rf_model.predict_proba(sample)[0]
    rf_label = label_mapping[rf_pred]
    rf_conf = rf_proba[rf_pred]
    
    xgb_pred = xgb_model.predict(sample)[0]
    xgb_proba = xgb_model.predict_proba(sample)[0]
    xgb_label = label_mapping[xgb_pred]
    xgb_conf = xgb_proba[xgb_pred]
    
    print(f"\n📝 Sample {i+1}:")
    print(f"   True Label:  {true_label}")
    print(f"   RF Pred:     {rf_label:15s} (confidence: {rf_conf*100:.1f}%)")
    print(f"   XGB Pred:    {xgb_label:15s} (confidence: {xgb_conf*100:.1f}%)")

# ============================================================================
# SUMMARY
# ============================================================================

print("\n" + "="*70)
print("✅ TRAINING COMPLETE!")
print("="*70)

print(f"\n📊 Final Results:")
print(f"   Random Forest:")
print(f"      Validation: {rf_val_acc*100:.2f}%")
print(f"      Test:       {rf_test_acc*100:.2f}%")
print(f"\n   XGBoost:")
print(f"      Validation: {xgb_val_acc*100:.2f}%")
print(f"      Test:       {xgb_test_acc*100:.2f}%")

print(f"\n📁 Models saved to: {MODEL_DIR}")
print(f"\n🚀 Next steps:")
print(f"   1. Run evaluate_models.py for detailed analysis")
print(f"   2. Update consumer.py to use trained models")
print(f"   3. Test with live honeypot data")