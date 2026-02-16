import json
import time
import numpy as np
import redis
from elasticsearch import Elasticsearch
from tensorflow.keras.models import load_model
import joblib

print("Starting Neuro-PALADIN Live Consumer...")

# 1. Load the Brain and Translators
print("Loading LSTM Model, Scaler, and Encoder...")
model = load_model("paladin_lstm.h5")
scaler = joblib.load("scaler.pkl")
encoder = joblib.load("encoder.pkl")
print("AI Core Online.")

# 2. Connect to the Nervous System (Redis & Elasticsearch)
# We use 'redis' and 'elasticsearch' hostnames because they will run inside Docker
r = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)
es = Elasticsearch([{'host': 'elasticsearch', 'port': 9200, 'scheme': 'http'}])

# The channel your honeypots/trigger script publishes to
REDIS_CHANNEL = "honeypot_logs"
pubsub = r.pubsub()
pubsub.subscribe(REDIS_CHANNEL)

print(f"Listening for live attacks on Redis channel: '{REDIS_CHANNEL}'...")

# 3. The Infinite Loop (Real-Time Inference)
for message in pubsub.listen():
    if message['type'] == 'message':
        try:
            # Parse the incoming honeypot log
            log_data = json.loads(message['data'])
            
            # --- FEATURE EXTRACTION ---
            # The LSTM expects exactly 77 numerical features.
            # (Note: You will map your actual honeypot JSON fields to this array later. 
            # For now, we simulate the 77 features to keep the pipeline from crashing).
            raw_features = np.zeros(77) 
            
            # Example: If your log has 'packet_size', you'd map it like: raw_features[0] = log_data.get('packet_size', 0)
            
            # 1. Reshape for the Scaler (2D)
            features_2d = raw_features.reshape(1, -1)
            
            # 2. Scale the numbers (0 to 1)
            features_scaled = scaler.transform(features_2d)
            
            # 3. Reshape for the LSTM (3D: 1 sample, 1 timestep, 77 features)
            features_3d = np.reshape(features_scaled, (1, 1, 77))
            
            # 4. Make the Prediction!
            prediction_probs = model.predict(features_3d, verbose=0)
            predicted_class_index = np.argmax(prediction_probs, axis=1)
            predicted_label = encoder.inverse_transform(predicted_class_index)[0]
            
            # Add the AI's verdict to the log
            log_data['ai_prediction'] = predicted_label
            log_data['ai_confidence'] = float(np.max(prediction_probs))
            log_data['model_used'] = "LSTM_Deep_Learning"
            
            # 5. Send to Elasticsearch (Dashboard)
            es.index(index="paladin-alerts", document=log_data)
            
            print(f"🚨 ATTACK DETECTED: {predicted_label} (Confidence: {log_data['ai_confidence']*100:.2f}%)")
            
        except Exception as e:
            print(f"Error processing log: {e}")