import socket
import json
from datetime import datetime

# --- CONFIGURATION ---
HOST = '0.0.0.0'
PORT = 2121 
LOG_FILE = '../shared_logs/ftp_honeypot.json'

# FTP response codes
RESP_WELCOME = b'220 (ftpd-fake 1.0) Service ready.\r\n'
RESP_LOGIN_OK = b'230 User logged in, proceed.\r\n'
RESP_CMD_OK = b'200 Command okay.\r\n'
RESP_LOGIN_FAIL = b'530 Not logged in.\r\n'

def log_event(event_data):
    """Writes a standardized JSON event to the shared log file."""
    with open(LOG_FILE, 'a') as f:
        json.dump(event_data, f)
        f.write('\n')

def create_log_entry(addr, command, detail_data):
    """Constructs the log entry following the team's agreed-upon format."""
    now_utc = datetime.utcnow().isoformat() + 'Z'

    log_entry = {
        "timestamp": now_utc,
        "source_ip": addr[0],
        "source_port": addr[1],
        "destination_port": PORT,
        "honeypot_name": "ftp-honeypot",
        "service": "FTP",
        "event_type": command,
        "details": detail_data
    }
    return log_entry

def handle_connection(conn, addr):
    conn.sendall(RESP_WELCOME)
    username = None

    while True:
        try:
            data = conn.recv(1024).decode('utf-8', errors='ignore').strip()
            if not data:
                break

            command_line = data.upper().split()
            if not command_line:
                continue

            command = command_line[0]
            arg = " ".join(command_line[1:]) if len(command_line) > 1 else ""

            if command == 'USER':
                username = arg
                conn.sendall(b'331 User name okay, need password.\r\n')
            elif command == 'PASS':
                password = arg
                if username:
                    # Log the login attempt
                    log_entry = create_log_entry(addr, "LOGIN_ATTEMPT", {"username": username, "password": password})
                    log_event(log_entry)

                    # Fake a successful login for simple attacks
                    conn.sendall(RESP_LOGIN_OK)
                    username = f"{username}/{password}" # Mark as logged in
                else:
                    conn.sendall(RESP_LOGIN_FAIL)
            elif command in ['STOR', 'RETR', 'GET', 'PUT']:
                # Log file transfer commands
                log_entry = create_log_entry(addr, "FILE_TRANSFER_ATTEMPT", {"command": command, "file": arg, "authenticated_as": username})
                log_event(log_entry)
                conn.sendall(RESP_CMD_OK)
            elif command == 'QUIT':
                conn.sendall(b'221 Goodbye.\r\n')
                break
            else:
                conn.sendall(RESP_CMD_OK)

        except Exception as e:
            print(f"Error handling connection: {e}")
            break

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[*] FTP Honeypot listening on {HOST}:{PORT}. Logs to {LOG_FILE}")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"[*] Connection from {addr[0]} on FTP")
                handle_connection(conn, addr)

if __name__ == '__main__':
    start_server()