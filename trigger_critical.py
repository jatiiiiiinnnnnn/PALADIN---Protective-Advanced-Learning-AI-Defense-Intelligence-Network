import redis
import json
from datetime import datetime

print("Initializing PALADIN Test Attack...")

try:
    # Connect to the Redis container exposed on your local machine
    r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    
    # Create a simulated malicious honeypot log
    fake_log = {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": "192.168.1.105",
        "destination_port": 80,
        "protocol": "TCP",
        "honeypot_name": "http-apache-test",
        "raw_data": "GET /etc/passwd HTTP/1.1",
        "event_type": "Directory Traversal Attempt"
    }
    
    # Publish to the exact channel your consumer_lstm.py is listening to
    channel = "honeypot_logs"
    r.publish(channel, json.dumps(fake_log))
    
    print(f"🎯 Simulated attack fired successfully into Redis channel: '{channel}'")
    print(f"Payload sent: {fake_log['raw_data']}")
    print("\n⏳ Now, go check your Streamlit dashboard!")

except Exception as e:
    print(f"❌ Error connecting to Redis: {e}\nIs Docker running?")