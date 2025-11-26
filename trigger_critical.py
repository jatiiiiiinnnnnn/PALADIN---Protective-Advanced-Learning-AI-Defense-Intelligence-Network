import redis
import json
import datetime
import time
import random

# Configuration
REDIS_HOST = 'localhost' # Use 'localhost' if running from host, 'redis' if inside docker
REDIS_PORT = 6379
QUEUE_NAME = 'honeypot-logs'

def send_log(r, attack_type, service, port, ip):
    """Constructs a log designed to trigger specific ML classifications"""
    
    # DoS Signature: Massive packets, tiny duration, repetitive message
    if attack_type == "DOS":
        log = {
            "timestamp": datetime.datetime.now().isoformat() + "Z",
            "service": service,
            "destination_port": port,
            "src_ip": ip,
            "message": f"GET /flood_attack?id={random.randint(1000,9999)} HTTP/1.1",
            "eventid": "cowrie.session.connect",
            "duration": 0.01,           # Impossible speed
            "packets": 50000 + random.randint(1,1000), # Massive packet count
            "protocol": "http"
        }
    # Recon Signature: Standard probing
    else:
        log = {
            "timestamp": datetime.datetime.now().isoformat() + "Z",
            "service": service,
            "destination_port": port,
            "src_ip": ip,
            "message": "Connection attempt",
            "eventid": "cowrie.session.connect",
            "duration": 0.5,
            "packets": 5,
            "protocol": "tcp"
        }

    r.rpush(QUEUE_NAME, json.dumps(log))
    print(f"💣 Sent {attack_type} payload from {ip}")

def main():
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        r.ping()
        print(f"[*] Connected to Redis. Preparing Critical Simulation...")
    except Exception as e:
        print(f"Error: {e}")
        return

    attacker_ip = "192.168.66.6" # The "Evil" IP

    # PHASE 1: Rapid Reconnaissance (Sets the stage)
    print("\n--- PHASE 1: Warming up LSTM (Reconnaissance) ---")
    for port in [80, 443, 8080]:
        send_log(r, "PORT_SCAN", "HTTP", port, attacker_ip)
        time.sleep(0.2)

    # PHASE 2: The Critical DoS Flood
    print("\n--- PHASE 2: LAUNCHING CRITICAL DoS FLOOD ---")
    # Sending multiple to ensure LSTM sees the "Sequence" and volume
    for _ in range(4):
        send_log(r, "DOS", "HTTP", 80, attacker_ip)
        time.sleep(0.5)

    print("\n✅ Simulation Complete. Check Consumer logs for RED ALERTS.")

if __name__ == "__main__":
    main()