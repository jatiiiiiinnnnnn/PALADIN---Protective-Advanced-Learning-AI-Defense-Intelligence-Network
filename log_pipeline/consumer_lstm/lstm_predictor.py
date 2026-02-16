import pandas as pd
import joblib
import numpy as np
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from tensorflow.keras.utils import to_categorical
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping

# 1. Load the Dataset
print("Loading data... (This might take a minute)")
# Replace with your actual file name
df = pd.read_parquet("C:/Users/reach/Documents/PALADIN---Protective-Advanced-Learning-AI-Defense-Intelligence-Network/training_data/CIC_IDS_MASTER_BALANCED.parquet")
# 2. Cleanup (Remove infinity and nulls)
print("Cleaning data...")
df.columns = df.columns.str.strip() # Remove spaces in column names
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()

# 3. Separate Features (X) and Labels (y)
# 'Label' is usually the last column in CIC-IDS2017
y = df['Label']
X = df.drop(columns=['Label'])

# 4. Encode Labels (Text -> Numbers)
# Example: "BENIGN" -> 0, "DoS Hulk" -> 1
encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)
y_final = to_categorical(y_encoded) # Convert to [0, 1, 0] format for AI

# 5. Scale Features (0 to 1 range)
# LSTM needs normalized data to converge
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# 6. Reshape for LSTM (Crucial Step!)
# LSTM expects 3D input: (Samples, TimeSteps, Features)
# We treat each row as 1 timestep
X_final = np.reshape(X_scaled, (X_scaled.shape[0], 1, X_scaled.shape[1]))

print(f"Data Ready! Shape: {X_final.shape}")
print(f"Attack Types Found: {encoder.classes_}")

# 7. Save the processed data (Optional, saves time later)
# np.save("X_data.npy", X_final)
# np.save("y_data.npy", y_final)
# 8. Split the Data (80% for studying, 20% for testing)
print("Splitting data into training and testing sets...")
X_train, X_test, y_train, y_test = train_test_split(X_final, y_final, test_size=0.2, random_state=42)

# 9. Build the Neural Network
print("Building the Deep Learning Model...")
model = Sequential()

# First LSTM Layer (The "Brain" trying to find complex patterns)
model.add(LSTM(64, input_shape=(X_train.shape[1], X_train.shape[2]), activation='relu', return_sequences=True))
model.add(Dropout(0.2)) # Forgets 20% of data to prevent "memorizing" (overfitting)

# Second LSTM Layer (Deepens the understanding)
model.add(LSTM(32, activation='relu'))
model.add(Dropout(0.2))

# Output Layer (6 neurons for our 6 attack types)
model.add(Dense(y_train.shape[1], activation='softmax'))

# 10. Compile the Model
model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
model.summary()

# 11. Train the Model!
print("Starting Training (This might take 10-20 minutes!)...")
# Early stopping: Stops training if the AI stops getting smarter, saving you time.
early_stop = EarlyStopping(monitor='val_loss', patience=3, restore_best_weights=True)

history = model.fit(
    X_train, y_train, 
    epochs=10, 
    batch_size=256, 
    validation_data=(X_test, y_test), 
    callbacks=[early_stop]
)

# 12. Save the New Brain
model.save("paladin_lstm.h5")
print("Model saved as paladin_lstm.h5! Training Complete.")
# 13. Save the Translators (Crucial for Live Predictions)
joblib.dump(scaler, "scaler.pkl")
joblib.dump(encoder, "encoder.pkl")
print("Scaler and Encoder saved!")