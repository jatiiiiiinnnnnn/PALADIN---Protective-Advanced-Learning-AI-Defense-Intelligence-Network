import redis
import json
import sys
import time
import joblib
from datetime import datetime
import numpy as np
from elasticsearch import Elasticsearch

# --- CONFIGURATION ---
REDIS_HOST = 'redis'
REDIS_PORT = 6379
QUEUE_NAME = 'honeypot-logs'
ES_HOST = 'elasticsearch'
ES_PORT = 9200

try:
    ml_model = joblib.load('/app/anomaly_detector.pkl')
    scaler = joblib.load('/app/scaler.pkl')
    print("✅ [AI] Anomaly Detection Model and Scaler loaded successfully!")
except Exception as e:
    ml_model = None
    scaler = None
    print(f"❌ [AI] Failed to load model: {e}")

def connect_redis():
    r = None
    while not r:
        try:
            print(f"[*] Connecting to Redis at {REDIS_HOST}...")
            r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
            r.ping()
            print("✅ [*] Redis connected!")
            return r
        except redis.ConnectionError:
            print("[!] Redis not ready. Retrying in 5s...")
            time.sleep(5)

def connect_es():
    es = None
    while not es:
        try:
            print(f"[*] Connecting to Elasticsearch at {ES_HOST}...")
            es = Elasticsearch(hosts=[f'http://{ES_HOST}:{ES_PORT}'])
            if es.ping():
                print("✅ [*] Elasticsearch connected!")
                return es
            else:
                raise Exception("Ping failed")
        except Exception as e:
            print(f"[!] Elasticsearch not ready. Retrying in 5s...")
            time.sleep(5)

def process_log(log_data):
    """Runs the AI model on the log data with improved feature detection."""
    if ml_model and scaler:
        try:
            # 1. Extract Features (4 features total, NO hour_of_day)
            
            # Feature 1: Port
            port_val = log_data.get('destination_port', 0)
            port = int(port_val) if str(port_val).isdigit() else 0
            
            # Feature 2: Is SSH? (1 = yes, 0 = no)
            service = log_data.get('service', '').upper()
            is_ssh = 1 if service == 'SSH' else 0
            
            # Feature 3: Failed login attempt? (1 = yes, 0 = no)
            message = str(log_data.get('message', '')).lower()
            eventid = str(log_data.get('eventid', '')).lower()
            failed_login = 1 if (
                ('login' in message and 'failed' in message) or
                'login.failed' in eventid
            ) else 0
            
            # Feature 4: Number of attempts
            num_attempts = 1
            if failed_login:
                num_attempts = 3  # Assume brute force for failed logins
            
            # 2. Create feature vector [port, is_ssh, failed_login, num_attempts]
            features = np.array([[port, is_ssh, failed_login, num_attempts]])
            
            # 3. Scale features (CRITICAL for consistency!)
            features_scaled = scaler.transform(features)
            
            # 4. Predict
            score = ml_model.decision_function(features_scaled)[0]
            prediction = ml_model.predict(features_scaled)[0]
            
            # 5. Enrich the log
            log_data['ai_anomaly_score'] = round(float(score), 4)
            log_data['ai_is_anomaly'] = bool(prediction == -1)  # -1 = anomaly
            
        except Exception as e:
            log_data['ai_error'] = str(e)
            print(f"[AI ERROR] {e}")
    
    return log_data

def main():
    r = connect_redis()
    es = connect_es()

    print("-" * 50)
    print(f"🚀 PALADIN Intelligence Consumer ONLINE.")
    print(f"[*] Waiting for logs in queue: '{QUEUE_NAME}'...")
    print("-" * 50)

    # Main event loop
    while True:
        try:
            # Blocking pop: waits for log to arrive
            message = r.blpop(QUEUE_NAME, timeout=1)
            if not message:
                continue

            # message[1] is the data from Redis
            raw_data = message[1]
            
            # Parse the JSON
            log_data = json.loads(raw_data)
            
            # The codec.json in filebeat already sent clean JSON
            # No need to unwrap a "message" field anymore!
            
            # Normalize Cowrie fields to match our standard format
            if 'protocol' in log_data and 'service' not in log_data:
                log_data['service'] = log_data['protocol'].upper()
            
            if 'dst_port' in log_data and 'destination_port' not in log_data:
                log_data['destination_port'] = log_data['dst_port']
            
            # If it's SSH and no port specified, default to 2222
            if log_data.get('service') == 'SSH' and 'destination_port' not in log_data:
                log_data['destination_port'] = 2222
            
            # Process with AI
            enriched_log = process_log(log_data)

            # Display results
            score = enriched_log.get('ai_anomaly_score', 'N/A')
            status = "🚨 ANOMALY" if enriched_log.get('ai_is_anomaly') else "✅ Normal"
            
            print(f"\n[Received] {enriched_log.get('timestamp', 'No timestamp')}")
            print(f"   Service: {enriched_log.get('service', 'Unknown')} | Port: {enriched_log.get('destination_port', 'Unknown')}")
            print(f"   AI Analysis: {status} (Score: {score})")

            # Save to Elasticsearch
            if es:
                try:
                    resp = es.index(index='honeypot-logs', document=enriched_log)
                except Exception as es_e:
                    print(f"   [!] Database Write Failed: {es_e}")

        except json.JSONDecodeError as jde:
            print(f"[!] JSON Decode Error: {jde}")
            print(f"[!] Problematic data: {message[1][:500]}")
        except KeyboardInterrupt:
            print("\n[!] Shutting down consumer.")
            sys.exit(0)
        except Exception as e:
            print(f"[!] Unexpected error in main loop: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(1)

if __name__ == '__main__':
    main()