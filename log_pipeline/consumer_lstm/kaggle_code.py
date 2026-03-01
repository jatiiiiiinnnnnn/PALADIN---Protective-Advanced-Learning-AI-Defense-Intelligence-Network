import tensorflow as tf
import os
import glob

# 1. Check if the GPU engine is "on"
gpus = tf.config.list_physical_devices('GPU')
if len(gpus) > 0:
    print(f"✅ Status: Found {len(gpus)} GPU(s). Ready for Deep Learning!")
else:
    print("❌ Status: No GPU found. Please check 'Session Options' in the sidebar.")

# 2. Check if the 'fuel' (dataset) is attached
# This looks into the folder where Kaggle puts your Distrinet files
files = glob.glob('/kaggle/input/datasets/dhoogla/distrinetcicids2017/*.parquet')
if len(files) > 0:
    print(f"✅ Data: Found {len(files)} Distrinet files. Ready to merge.")
else:
    print("❌ Data: Found 0 files. Did you click the '+' Add Data button and search for 'distrinetcicids2017'?")

import os
print(os.listdir('/kaggle/input/datasets/dhoogla'))

import pandas as pd
import glob

# The exact path you just verified
file_path = '/kaggle/input/datasets/dhoogla/distrinetcicids2017/*.parquet'
all_files = glob.glob(file_path)

print("⏳ Loading 5 data files into memory (this takes a few seconds)...")
# Read all parquet files and stack them into one giant table
df_list = [pd.read_parquet(f) for f in all_files]
full_df = pd.concat(df_list, ignore_index=True)

print(f"✅ Total Raw Rows Loaded: {len(full_df):,}")

# --- THE SMART SAMPLING ---
# Cap at 20,000 rows per attack so Kaggle doesn't crash and the AI stays balanced
print("⚖️ Balancing the dataset (Max 20,000 rows per class)...")
balanced_df = full_df.groupby('Label').apply(lambda x: x.sample(n=min(len(x), 40000), random_state=42)).reset_index(drop=True)

print(f"🚀 Final 'Master Brain' Size: {len(balanced_df):,} rows")
print("\n📊 Attack Types Ready for Training:")
print(balanced_df['Label'].value_counts())

import numpy as np
import joblib
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from tensorflow.keras.utils import to_categorical

print("⚙️ Step 3: Preprocessing Data (Matching Local Pipeline)...")

# 1. Separate Features (X) and Labels (y)
X = balanced_df.drop(columns=['Label'])
y = balanced_df['Label']

# 2. Encode Labels (Text -> Numbers -> One-Hot Array)
encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)
y_final = to_categorical(y_encoded) # Creates the [0, 1, 0] format

# 3. Scale Features (0 to 1 range)
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# 4. Reshape for LSTM (Samples, TimeSteps, Features)
X_final = np.reshape(X_scaled, (X_scaled.shape[0], 1, X_scaled.shape[1]))

# 5. Split Data (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(X_final, y_final, test_size=0.2, random_state=42)

# 6. Save the artifacts so you can download them for your local app later
joblib.dump(scaler, "scaler.pkl")
joblib.dump(encoder, "encoder.pkl")

print(f"✅ Preprocessing Complete!")
print(f"🧠 LSTM Input Shape (X_train): {X_train.shape}")
print(f"🏷️ Labels Shape (y_train): {y_train.shape}")
print("💾 Saved 'scaler.pkl' and 'encoder.pkl' to Kaggle working directory.")

from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping

print("🏗️ Step 4: Building the Deep Learning Model (Exact Local Replica)...")
model = Sequential()

# First LSTM Layer (The "Brain" trying to find complex patterns)
model.add(LSTM(128, input_shape=(X_train.shape[1], X_train.shape[2]), activation='relu', return_sequences=True))
model.add(Dropout(0.2)) # Forgets 20% of data to prevent "memorizing"

# Second LSTM Layer (Deepens the understanding)
model.add(LSTM(64, activation='relu'))
model.add(Dropout(0.2))

# Output Layer (Dynamically sizing to your exact attack types)
model.add(Dense(y_train.shape[1], activation='softmax'))

# Compile the Model
model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
model.summary()

print("\n🚀 Step 5: Starting GPU Training (This is it!)...")
# Early stopping: Stops training if the AI stops getting smarter, saving you time.
early_stop = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)

# THE TRAINING RUN
history = model.fit(
    X_train, y_train, 
    epochs=50, 
    batch_size=256, 
    validation_data=(X_test, y_test), 
    callbacks=[early_stop]
)

# Save the completely trained Master Brain
model.save("paladin_lstm_master.h5")
print("✅ Model saved as paladin_lstm_master.h5! All steps complete.")