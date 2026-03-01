import json
import time
import numpy as np
import redis
from elasticsearch import Elasticsearch
import os
import joblib

# Suppress Legacy Keras warnings
os.environ['TF_USE_LEGACY_KERAS'] = '0'
from tensorflow.keras.models import load_model

print("🏗️ Starting Neuro-PALADIN Live Consumer...")

# 1. Load the Brain and Translators
print("🧠 Loading LSTM Model, Scaler, and Encoder...")
model = load_model("paladin_lstm.h5", compile=False)
scaler = joblib.load("scaler.pkl")
encoder = joblib.load("encoder.pkl")
print("✅ AI Core Online.")

# 2. Connect to Redis & Elasticsearch
r = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)
es = Elasticsearch([{'host': 'elasticsearch', 'port': 9200, 'scheme': 'http'}])

REDIS_CHANNEL = "honeypot_logs"
pubsub = r.pubsub()
pubsub.subscribe(REDIS_CHANNEL)

print(f"📡 Listening for live attacks on Redis channel: '{REDIS_CHANNEL}'...")

# 3. Real-Time Inference Loop
for message in pubsub.listen():
    if message['type'] == 'message':
        try:
            log_data = json.loads(message['data'])
            
            # --- FEATURE ALIGNMENT (The 82-Dimension Fix) ---
            # Create the 82-column array the model expects
            full_features = np.zeros((1, 82)) 
            
            # Get features from trigger, default to empty list if not found
            incoming = log_data.get('network_features', [])
            
            if incoming:
                num_to_map = min(len(incoming), 82)
                full_features[0, :num_to_map] = incoming[:num_to_map]
            
            # Scale and Reshape to (1, 1, 82)
            features_scaled = scaler.transform(full_features)
            features_3d = np.reshape(features_scaled, (1, 1, 82))
            
            # 4. Make Prediction
            prediction_probs = model.predict(features_3d, verbose=0)
            predicted_class_index = np.argmax(prediction_probs, axis=1)
            predicted_label = encoder.inverse_transform(predicted_class_index)[0]
            confidence = float(np.max(prediction_probs))
            
            # --- MAP AI VERDICT TO MITRE DASHBOARD ---
            
            # Define base severity for different attacks (out of 5.0)
            SEVERITY_MAP = {
                "Benign": 0.0,
                "Portscan": 3.0,
                "Infiltration - Portscan": 3.5,
                "FTP-Patator": 3.5,
                "SSH-Patator": 3.8,
                "DoS Slowloris": 4.0,
                "DoS Hulk": 4.0,
                "Web Attack - Brute Force": 4.2,
                "Infiltration": 4.5,
                "Web Attack - SQL Injection": 4.8,
                "DDoS": 5.0,
                "Botnet": 5.0,
                "Heartbleed": 5.0
            }
            
            # Get base severity (default to 4.0 if attack isn't explicitly in list)
            base_severity = SEVERITY_MAP.get(predicted_label, 4.0)
            
            # Calculate Final Risk Score (Severity * AI Confidence)
            final_risk = round(base_severity * confidence, 2) if predicted_label != "Benign" else 0.0

            # Assign Dynamic MITRE Tactics
            if predicted_label == "Benign":
                tactics = []
            elif final_risk < 4.0:
                tactics = ["Reconnaissance", "Discovery"]
            else:
                tactics = ["Initial Access", "Execution"]

            # Create the 'mitre' object the dashboard expects
            mitre_data = {
                "risk_score": final_risk,
                "tactics": tactics
            }

            # Determine Action Status based on Risk Score
            if final_risk >= 4.0:
                action_status = "BLOCKED"
            elif final_risk > 0:
                action_status = "ELEVATED_MONITORING"
            else:
                action_status = "ALLOWED"

            # 5. Enrich Log and Send to Elasticsearch
            log_data['ai_prediction'] = predicted_label
            log_data['ai_confidence'] = confidence
            log_data['mitre'] = mitre_data
            log_data['ai_final_status'] = action_status
            log_data['service'] = log_data.get('honeypot_name', 'Unknown')
            
            # Send to database
            es.index(index="honeypot-logs", document=log_data)
            
            # Terminal Output
            print(f"🚨 VERDICT: {predicted_label} | Risk Score: {final_risk}/5.0 | Action: {action_status}")
            
        except Exception as e:
            print(f"⚠️ Error processing log: {e}")