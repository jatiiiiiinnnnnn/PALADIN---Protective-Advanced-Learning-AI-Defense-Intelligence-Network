import json
from datetime import datetime
from jsonschema import validate, ValidationError

# Define a simple schema for normalized logs
log_schema = {
    "type": "object",
    "properties": {
        "timestamp": {"type": "string"},
        "source_ip": {"type": "string"},
        "destination_ip": {"type": "string"},
        "protocol": {"type": "string"},
        "command": {"type": "string"}
    },
    "required": ["timestamp", "source_ip", "destination_ip", "protocol"]
}

def normalize_log(raw_log):
    """
    Convert raw honeypot log lines into normalized JSON format
    """
    try:
        data = json.loads(raw_log)
    except json.JSONDecodeError:
        # Handle simple space-separated logs
        parts = raw_log.strip().split(" ")
        if len(parts) < 4:
            return None
        data = {
            "timestamp": parts[0],
            "source_ip": parts[1],
            "destination_ip": parts[2],
            "protocol": parts[3],
            "command": " ".join(parts[4:]) if len(parts) > 4 else ""
        }

    # Normalize timestamp
    try:
        datetime.strptime(data["timestamp"], "%Y-%m-%dT%H:%M:%S")
    except Exception:
        data["timestamp"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")

    return data

def validate_log(normalized_log):
    """
    Validate normalized logs against schema
    """
    try:
        validate(instance=normalized_log, schema=log_schema)
        return True
    except ValidationError:
        return False

if __name__ == "__main__":
    sample_logs = [
        '{"timestamp": "2025-10-04T12:00:00", "source_ip": "192.168.1.5", "destination_ip": "10.0.0.2", "protocol": "SSH", "command": "ls -la"}',
        "2025-10-04T12:05:00 192.168.1.9 10.0.0.3 HTTP GET /index.html",
        "invalid log line example"
    ]

    for log in sample_logs:
        print("Raw:", log)
        normalized = normalize_log(log)
        print("Normalized:", normalized)
        if normalized:
            print("Valid schema:", validate_log(normalized))
        print("-" * 60)
