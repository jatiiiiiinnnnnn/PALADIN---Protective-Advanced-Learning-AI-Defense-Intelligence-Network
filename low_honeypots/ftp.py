import socket
import json
from datetime import datetime

# --- CONFIGURATION ---
HOST = '0.0.0.0'
PORT = 2121 
LOG_FILE = '/shared_logs/ftp_honeypot.json'

# FTP response codes
RESP_WELCOME = b'220 (ftpd-fake 1.0) Service ready.\r\n'
RESP_LOGIN_OK = b'230 User logged in, proceed.\r\n'
RESP_CMD_OK = b'200 Command okay.\r\n'
RESP_LOGIN_FAIL = b'530 Not logged in.\r\n'

def log_event(event_data):
    """Writes a standardized JSON event to the shared log file."""
    with open(LOG_FILE, 'a+') as f:
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
    # Create a file-like object for easier line-by-line reading
    makefile = conn.makefile('rw', encoding='utf-8', errors='ignore', newline='\r\n')
    
    makefile.write('220 (ftpd-fake 1.0) Service ready.\r\n')
    makefile.flush()
    username = None

    while True:
        try:
            line = makefile.readline().strip()
            if not line:
                break

            command_line = line.upper().split()
            if not command_line:
                continue
            
            command = command_line[0]
            arg = " ".join(command_line[1:]) if len(command_line) > 1 else ""

            if command == 'USER':
                username = arg
                makefile.write('331 User name okay, need password.\r\n')
            elif command == 'PASS':
                password = arg
                if username:
                    log_entry = create_log_entry(addr, "LOGIN_ATTEMPT", {"username": username, "password": password})
                    log_event(log_entry)
                    makefile.write('230 User logged in, proceed.\r\n')
                    username = f"{username}/{password}"
                else:
                    makefile.write('530 Not logged in.\r\n')
            elif command in ['STOR', 'RETR', 'GET', 'PUT']:
                log_entry = create_log_entry(addr, "FILE_TRANSFER_ATTEMPT", {"command": command, "file": arg, "authenticated_as": username})
                log_event(log_entry)
                makefile.write('200 Command okay.\r\n')
            elif command == 'QUIT':
                makefile.write('221 Goodbye.\r\n')
                break
            else:
                makefile.write('200 Command okay.\r\n')
            
            makefile.flush()

        except Exception as e:
            print(f"Error handling FTP connection: {e}")
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