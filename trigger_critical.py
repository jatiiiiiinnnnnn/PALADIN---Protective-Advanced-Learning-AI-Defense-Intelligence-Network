"""import redis
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
    print(f"❌ Error connecting to Redis: {e}\nIs Docker running?")"""

"""import redis
import json
import numpy as np
from datetime import datetime

print("Initializing PALADIN Smart Test Attack...")

try:
    # 1. Connect to the Redis container (localhost works if ports are mapped)
    r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    
    # 2. CREATE THE BRAIN DATA (The 77 Numerical Features)
    # We create a base of zeros and then "inject" DDoS patterns
    network_data = np.zeros(77)
    
    # Mimicking a DDoS Attack profile:
    network_data[0] = 80          # Destination Port
    network_data[1] = 1550000     # Flow Duration (High)
    network_data[2] = 200         # Total Fwd Packets (High)
    network_data[4] = 1200        # Total Length of Fwd Packets
    network_data[7] = 600         # Fwd Packet Length Max
    network_data[12] = 15.5       # Flow Packets/s
    
    # 3. Create the Full Honeypot Log
    fake_log = {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": "192.168.1.105",
        "destination_port": 80,
        "protocol": "TCP",
        "honeypot_name": "http-apache-test",
        "raw_data": "GET /etc/passwd HTTP/1.1",
        "event_type": "DDoS Simulation",
        # This is what our updated consumer_lstm.py will look for:
        "network_features": network_data.tolist() 
    }
    
    # 4. Publish to the 'honeypot_logs' channel
    channel = "honeypot_logs"
    r.publish(channel, json.dumps(fake_log))
    
    print(f"🎯 Smart attack fired successfully into Redis channel: '{channel}'")
    print(f"Payload sent: {fake_log['event_type']}")
    print("📈 AI Features injected: 77 features (Simulated DDoS pattern)")
    print("\n⏳ Go check your terminal logs and Streamlit dashboard!")

except Exception as e:
    print(f"❌ Error: {e}")
    print("Is Docker running? Ensure Redis port 6379 is mapped to localhost.")"""

"""import redis
import json
import numpy as np
from datetime import datetime

r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# We create 82 zeros (to match your new consumer logic)
attack_data = np.zeros(82)

# This is a 'Strong' DDoS signature based on the Kaggle dataset structure:
attack_data[0] = 80           # Destination Port
attack_data[1] = 5000000      # Flow Duration (Very Long)
attack_data[2] = 500          # Total Fwd Packets (Heavy Traffic)
attack_data[3] = 500          # Total Bwd Packets
attack_data[4] = 20000        # Total Length of Fwd Packets
attack_data[7] = 1460         # Fwd Packet Length Max (Full MTU)
attack_data[14] = 1000        # Flow Bytes/s (High)
attack_data[15] = 100         # Flow Packets/s

fake_log = {
    "timestamp": datetime.utcnow().isoformat(),
    "source_ip": "1.2.3.4",
    "honeypot_name": "Kaggle-Master-Test",
    "network_features": attack_data.tolist(),
    "event_type": "DDoS Simulation"
}

r.publish("honeypot_logs", json.dumps(fake_log))
print("🔥 High-Intensity Attack Sent! Check your consumer logs.")"""

import redis
import json
import numpy as np
from datetime import datetime

r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# 1. Create a "Hot" Feature Vector
# We fill the first 40 slots with high values (0.8 to 1.0 after scaling)
# This ensures we hit the 'Active' features learned on Kaggle
attack_data = np.zeros(82)
for i in range(40):
    attack_data[i] = 999999  # Large numbers to trigger 'High' scaling

fake_log = {
    "timestamp": datetime.utcnow().isoformat(),
    "source_ip": "10.0.0.66",
    "honeypot_name": "Kaggle-Master-Invasion",
    "network_features": attack_data.tolist(),
    "event_type": "Critical Saturation Attack"
}

r.publish("honeypot_logs", json.dumps(fake_log))
print("💥 CRITICAL ATTACK FIRED: Features Saturated. Check Consumer Logs!")