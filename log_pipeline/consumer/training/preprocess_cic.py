"""
PALADIN - CIC-IDS2017 Dataset Preprocessing
File: log_pipeline/consumer/training/preprocess_cic.py

Prepares CIC-IDS2017 for training:
1. Loads all CSV files
2. Cleans data (NaN, infinity)
3. Balances classes
4. Creates train/val/test splits
"""

import pandas as pd
import numpy as np
import os
from pathlib import Path
import json
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.utils import resample
import warnings
warnings.filterwarnings('ignore')

print("="*70)
print("🔧 PALADIN CIC-IDS2017 PREPROCESSING")
print("="*70)

# Configuration
BASE_DIR = Path('/app')
RAW_DATA_DIR = BASE_DIR / 'data/cic_ids_2017/raw'
PROCESSED_DATA_DIR = BASE_DIR / 'data/cic_ids_2017/processed'
PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_BENIGN = 50000  # Limit benign samples
RANDOM_STATE = 42

# Attack category mapping
ATTACK_MAPPING = {
    'BENIGN': 'NORMAL',
    'FTP-Patator': 'BRUTE_FORCE',
    'SSH-Patator': 'BRUTE_FORCE',
    'DoS Hulk': 'DOS',
    'DoS GoldenEye': 'DOS',
    'DoS slowloris': 'DOS',
    'DoS Slowhttptest': 'DOS',
    'DDoS': 'DDOS',
    'Heartbleed': 'HEARTBLEED',
    'Web Attack � Brute Force': 'WEB_ATTACK',
    'Web Attack � XSS': 'WEB_ATTACK',
    'Web Attack � Sql Injection': 'WEB_ATTACK',
    'Infiltration': 'INFILTRATION',
    'Bot': 'BOTNET',
    'PortScan': 'PORT_SCAN'
}

print("\n📥 Loading CSV files...")
csv_files = sorted(list(RAW_DATA_DIR.glob('*.csv')))

if not csv_files:
    print("❌ No CSV files found!")
    print(f"   Place CIC-IDS2017 files in: {RAW_DATA_DIR}")
    exit(1)

print(f"✅ Found {len(csv_files)} files")

# Load all CSVs
dfs = []
for csv_file in csv_files:
    print(f"   Loading {csv_file.name}...", end='')
    df = pd.read_csv(csv_file, encoding='utf-8', low_memory=False)
    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
    dfs.append(df)
    print(f" {len(df):,} rows")

df_combined = pd.concat(dfs, ignore_index=True)
print(f"✅ Total: {len(df_combined):,} rows")

# Find label column
label_cols = [col for col in df_combined.columns if 'label' in col.lower()]
LABEL_COL = label_cols[0] if label_cols else None
if not LABEL_COL:
    print("❌ No label column found!")
    exit(1)

print(f"\n📊 Attack Distribution:")
for label, count in df_combined[LABEL_COL].value_counts().items():
    print(f"   {label:30s}: {count:>8,}")

# Clean data
print(f"\n🧹 Cleaning data...")
df_combined.fillna(0, inplace=True)
df_combined.replace([np.inf, -np.inf], 0, inplace=True)
print("   ✅ Cleaned NaN and infinity values")

# Map attack labels
df_combined['attack_category'] = df_combined[LABEL_COL].map(ATTACK_MAPPING)
df_combined['attack_category'].fillna('OTHER', inplace=True)

print(f"\n🏷️  Categories:")
for cat, count in df_combined['attack_category'].value_counts().items():
    print(f"   {cat:20s}: {count:>8,}")



# Step 1: Limit benign
df_benign = df_combined[df_combined['attack_category'] == 'NORMAL']
if len(df_benign) > SAMPLE_BENIGN:
    df_benign = df_benign.sample(n=SAMPLE_BENIGN, random_state=RANDOM_STATE)

# Step 2: Balance attack types
df_attacks = df_combined[df_combined['attack_category'] != 'NORMAL']

# Set target samples per attack type
TARGET_SAMPLES_PER_CLASS = 10000  # Adjust based on smallest class

balanced_dfs = [df_benign]  # Start with benign

for attack_type in df_attacks['attack_category'].unique():
    df_attack = df_attacks[df_attacks['attack_category'] == attack_type]
    
    # Oversample small classes, undersample large ones
    if len(df_attack) < TARGET_SAMPLES_PER_CLASS:
        # Oversample (duplicate with replacement)
        df_resampled = resample(df_attack, 
                                n_samples=TARGET_SAMPLES_PER_CLASS, 
                                replace=True,  # Allow duplicates
                                random_state=RANDOM_STATE)
        print(f"   ⬆️  {attack_type:20s}: {len(df_attack):>7,} → {TARGET_SAMPLES_PER_CLASS:>7,} (oversampled)")
    else:
        # Undersample (random sample)
        df_resampled = resample(df_attack, 
                                n_samples=TARGET_SAMPLES_PER_CLASS, 
                                replace=False,
                                random_state=RANDOM_STATE)
        print(f"   ⬇️  {attack_type:20s}: {len(df_attack):>7,} → {TARGET_SAMPLES_PER_CLASS:>7,} (undersampled)")
    
    balanced_dfs.append(df_resampled)

df_balanced = pd.concat(balanced_dfs, ignore_index=True)
print(f"\n⚖️  Final balanced dataset: {len(df_balanced):,} samples")


# Select features
SELECTED_FEATURES = [
    'destination_port', 'protocol', 'flow_duration',
    'total_fwd_packets', 'total_backward_packets',
    'flow_bytes/s', 'flow_packets/s', 'flow_iat_mean',
    'fwd_iat_mean', 'syn_flag_count', 'ack_flag_count',
    'average_packet_size', 'avg_fwd_segment_size',
    'attack_category'
]

available = [f for f in SELECTED_FEATURES if f in df_balanced.columns]
df_final = df_balanced[available].copy()

print(f"\n🎯 Features: {len(available)-1} selected")

# Split data
X = df_final.drop('attack_category', axis=1)
y = df_final['attack_category']

label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)
label_mapping = {i: label for i, label in enumerate(label_encoder.classes_)}

X_train, X_temp, y_train, y_temp = train_test_split(
    X, y_encoded, test_size=0.3, random_state=RANDOM_STATE, stratify=y_encoded
)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.5, random_state=RANDOM_STATE, stratify=y_temp
)

print(f"\n✂️  Splits:")
print(f"   Train: {len(X_train):,} | Val: {len(X_val):,} | Test: {len(X_test):,}")

# Save
train_df = X_train.copy()
train_df['label'] = y_train
train_df.to_csv(PROCESSED_DATA_DIR / 'train_balanced.csv', index=False)

val_df = X_val.copy()
val_df['label'] = y_val
val_df.to_csv(PROCESSED_DATA_DIR / 'val_balanced.csv', index=False)

test_df = X_test.copy()
test_df['label'] = y_test
test_df.to_csv(PROCESSED_DATA_DIR / 'test_balanced.csv', index=False)

with open(PROCESSED_DATA_DIR / 'label_mapping.json', 'w') as f:
    json.dump(label_mapping, f, indent=2)

with open(PROCESSED_DATA_DIR / 'feature_names.json', 'w') as f:
    json.dump(list(X.columns), f, indent=2)

print(f"\n💾 Saved to: {PROCESSED_DATA_DIR}")
print("\n✅ PREPROCESSING COMPLETE!")
print("🚀 Next: Run train_supervised.py")