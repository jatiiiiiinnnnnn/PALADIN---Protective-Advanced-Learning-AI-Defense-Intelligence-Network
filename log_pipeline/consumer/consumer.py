import redis
import json
import sys
import time
import joblib
import numpy as np
from elasticsearch import Elasticsearch

# --- CONFIGURATION ---
REDIS_HOST = 'redis'
REDIS_PORT = 6379
QUEUE_NAME = 'honeypot-logs'
ES_HOST = 'elasticsearch'
ES_PORT = 9200

# --- 1. LOAD ML MODEL ---
print("[AI] Initializing Intelligence Layer...")
try:
    ml_model = joblib.load('anomaly_detector.pkl')
    print("✅ [AI] Anomaly Detection Model loaded successfully!")
except Exception as e:
    print(f"⚠️ [AI] Warning: Could not load model. Running in data-only mode. Error: {e}")
    ml_model = None

def connect_redis():
    # ... (same as before)
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
    # ... (same as before)
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
    # ... (same as before)
    if ml_model:
        try:
            # Use 0 if port is missing or N/A
            port_val = log_data.get('destination_port', 0)
            # Handle cases where it might be a string "2222" or int 2222
            port = int(port_val) if str(port_val).isdigit() else 0
            
            score = ml_model.decision_function([[port]])[0]
            log_data['ai_anomaly_score'] = round(float(score), 4)
            log_data['ai_is_anomaly'] = bool(score < 0)
        except Exception as e:
            log_data['ai_error'] = str(e)
    return log_data

def main():
    r = connect_redis()
    es = connect_es()

    print("-" * 50)
    print(f"🚀 PALADIN Intelligence Consumer ONLINE.")
    print("-" * 50)

    while True:
        try:
            message = r.blpop(QUEUE_NAME, timeout=1)
            if not message: continue

            # 1. First Parse: Decode the entry from Redis (Filebeat's wrapper)
            raw_data = message[1]
            log_data = json.loads(raw_data)

            # --- CRITICAL FIX: UNWRAP THE INNER MESSAGE ---
            # If Filebeat wrapped our JSON in a 'message' string, parse it again.
            if 'message' in log_data and isinstance(log_data['message'], str):
                try:
                    # This extracts destination_port, service, etc. to the top level
                    inner_data = json.loads(log_data['message'])
                    if isinstance(inner_data, dict):
                        log_data.update(inner_data)
                except json.JSONDecodeError:
                    # It wasn't JSON, just a normal text log. Ignore.
                    pass
            # ---------------------------------------------

            # 2. Intelligence Step
            enriched_log = process_log(log_data)

            # 3. Output
            score = enriched_log.get('ai_anomaly_score', 'N/A')
            status = "🚨 ANOMALY" if enriched_log.get('ai_is_anomaly') else "✅ Normal"
            
            print(f"\n[Received] {log_data.get('@timestamp', 'No timestamp')}")
            print(f"   Service: {log_data.get('service', 'Unknown')} | Port: {log_data.get('destination_port', 'Unknown')}")
            print(f"   AI Analysis: {status} (Score: {score})")

            if es:
                try:
                    es.index(index='honeypot-logs', document=enriched_log)
                except Exception: pass

        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(1)

if __name__ == '__main__':
    main()