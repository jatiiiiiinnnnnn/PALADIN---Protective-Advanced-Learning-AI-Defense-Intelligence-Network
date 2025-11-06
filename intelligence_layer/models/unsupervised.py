import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.optimizers import Adam

DATA_DIR = "/app/data/MachineLearningCVE"

def load_unsupervised_data(sample_frac=0.05):
    """Load and sample unlabeled CICIDS2017 data for unsupervised learning"""
    csv_files = [f for f in os.listdir(DATA_DIR) if f.endswith(".csv")]
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {DATA_DIR}")
    
    data_list = []
    for file in csv_files:
        df = pd.read_csv(os.path.join(DATA_DIR, file))
        if ' Label' in df.columns:
            df = df.drop(columns=[' Label'])
        elif 'Label' in df.columns:
            df = df.drop(columns=['Label'])
        df = df.select_dtypes(include=[np.number])  # use numeric features only
        data_list.append(df.sample(frac=sample_frac, random_state=42))
    combined = pd.concat(data_list, ignore_index=True)
    
    X = combined.fillna(0)
    X_scaled = StandardScaler().fit_transform(X)
    print(f"✅ Loaded unsupervised dataset with shape: {X_scaled.shape}")
    return X_scaled

def train_isolation_forest(X):
    print("\n[🔍] Training Isolation Forest for anomaly detection...")
    iso = IsolationForest(contamination=0.02, random_state=42)
    preds = iso.fit_predict(X)
    anomalies = np.sum(preds == -1)
    print(f"✅ Isolation Forest trained | Detected anomalies: {anomalies}/{len(X)}")
    return iso

def train_autoencoder(X):
    print("\n[🧠] Training Autoencoder for anomaly detection...")
    input_dim = X.shape[1]
    model = Sequential([
        Dense(64, activation='relu', input_shape=(input_dim,)),
        Dense(32, activation='relu'),
        Dense(64, activation='relu'),
        Dense(input_dim, activation='sigmoid')
    ])
    model.compile(optimizer=Adam(learning_rate=0.001), loss='mse')
    model.fit(X, X, epochs=10, batch_size=128, shuffle=True, validation_split=0.1, verbose=0)
    print("✅ Autoencoder trained successfully")
    return model

def train_clustering(X):
    print("\n[🧩] Performing clustering analysis (K-Means)...")
    kmeans = KMeans(n_clusters=5, random_state=42)
    kmeans.fit(X)
    print(f"✅ Clustering completed | Found {len(set(kmeans.labels_))} clusters")
    return kmeans
