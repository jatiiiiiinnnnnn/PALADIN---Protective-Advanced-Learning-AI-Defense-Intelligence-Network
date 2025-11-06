import pandas as pd
import numpy as np
import os
from sklearn.preprocessing import StandardScaler, LabelEncoder

DATA_DIR = "/app/data/MachineLearningCVE/"

def load_cicids_csv(sample_frac=0.1, max_rows_per_file=200000):
    """
    Load CIC-IDS2017 CSV files safely with memory control.
    Streams each file in chunks, samples early to avoid full memory load.
    Returns scaled features, encoded labels, and the encoder.
    """
    csv_files = [f for f in os.listdir(DATA_DIR) if f.endswith(".csv")]
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {DATA_DIR}")

    df_list = []
    for file in csv_files:
        path = os.path.join(DATA_DIR, file)
        print(f"Reading {file} ...")
        try:
            # Read only up to max_rows_per_file rows per file
            chunk = pd.read_csv(path, nrows=max_rows_per_file, low_memory=False)
            if sample_frac < 1.0:
                chunk = chunk.sample(frac=sample_frac, random_state=42)
            df_list.append(chunk)
            print(f"Loaded {chunk.shape[0]} rows from {file}")
        except Exception as e:
            print(f"⚠️ Error reading {file}: {e}")
            continue

    df = pd.concat(df_list, ignore_index=True)
    print("✅ Combined dataset shape:", df.shape)

    # Identify label column
    label_col = next((col for col in df.columns if "Label" in col or "label" in col), None)
    if label_col is None:
        raise KeyError("No suitable label column found")

    # Separate features and labels
    y = df[label_col].copy()
    X = df.drop(columns=[label_col])

    # Handle missing or infinite values
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    # Encode labels
    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print("✅ Preprocessing complete. X shape:", X_scaled.shape)
    return X_scaled, y_encoded, encoder
