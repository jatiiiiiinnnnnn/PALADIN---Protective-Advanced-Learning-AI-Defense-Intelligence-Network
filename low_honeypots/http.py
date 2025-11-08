import socket
import json
from datetime import datetime

# --- CONFIGURATION ---
HOST = '0.0.0.0'
PORT = 8080 
LOG_FILE = '/shared_logs/http_honeypot.json'

# Standard response to appear as a regular web server
STANDARD_RESPONSE = b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.29\r\nContent-Type: text/html\r\n\r\n<h1>Welcome to the Honeypot!</h1>'

def log_event(event_data):
    """Writes a standardized JSON event to the shared log file."""
    print(f"[DEBUG] Attempting to log event to {LOG_FILE}")
    try:
        with open(LOG_FILE, 'a+') as f:
            json.dump(event_data, f)
            f.write('\n')
            f.flush()
        print(f"[DEBUG] Log successful.")

    except Exception as log_e:
        # If the file write fails, this prints the error directly to the Docker logs.
        import traceback
        print(f"[!!] FAILED TO WRITE LOG: {log_e}")
        traceback.print_exc()

def create_log_entry(addr, request):
    """Constructs the log entry following the team's agreed-upon format."""
    now_utc = datetime.utcnow().isoformat() + 'Z'
    request_lines = request.split('\r\n')
    
    # Extract method and path from the first line
    first_line_parts = request_lines[0].split()
    method = first_line_parts[0] if len(first_line_parts) > 0 else "UNKNOWN"
    path = first_line_parts[1] if len(first_line_parts) > 1 else "/"

    return {
        "timestamp": now_utc,
        "source_ip": addr[0],
        "source_port": addr[1],
        "destination_port": PORT,
        "honeypot_name": "http-honeypot",
        "service": "HTTP",
        "event_type": "REQUEST",
        "details": {
            "method": method,
            "path": path,
            "raw_request": request,
            "user_agent": next((line.split(': ')[1] for line in request_lines if line.startswith('User-Agent:')), 'N/A')
        }
    }

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Allow the port to be immediately reused
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[*] HTTP Honeypot listening on {HOST}:{PORT}. Logs to {LOG_FILE}")
        
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"[*] Connection from {addr[0]}")
                try:
                    # Receive data (up to 1KB)
                    request_data = conn.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    if request_data:
                        # Log the event
                        log_entry = create_log_entry(addr, request_data)
                        log_event(log_entry)
                        
                        # Send the fake response
                        conn.sendall(STANDARD_RESPONSE)
                    
                except Exception as e:
                    print(f"Error handling connection: {e}")

if __name__ == '__main__':
    start_server()