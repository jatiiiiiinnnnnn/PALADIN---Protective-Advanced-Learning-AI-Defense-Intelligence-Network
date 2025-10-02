import socket
import json
from datetime import datetime

# --- CONFIGURATION ---
HOST = '0.0.0.0'
PORT = 2525 
LOG_FILE = '/shared_logs/smtp_honeypot.json'

# SMTP response codes
RESP_WELCOME = b'220 mail.honeypot.net ESMTP Service ready\r\n'
RESP_OK = b'250 OK\r\n'
RESP_DATA_START = b'354 Start mail input; end with <CRLF>.<CRLF>\r\n'
RESP_GOODBYE = b'221 Bye\r\n'
RESP_SYNTAX_ERROR = b'500 Syntax error, command unrecognised\r\n'

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
        "honeypot_name": "smtp-honeypot",
        "service": "SMTP",
        "event_type": command,
        "details": detail_data
    }
    return log_entry

def handle_connection(conn, addr):
    # Create a file-like object for easier line-by-line reading
    makefile = conn.makefile('rw', encoding='utf-8', errors='ignore', newline='\r\n')

    makefile.write('220 mail.honeypot.net ESMTP Service ready\r\n')
    makefile.flush()
    mail_from = None
    mail_to = []

    while True:
        try:
            line = makefile.readline().strip()
            if not line:
                break

            command_line = line.upper().split(':', 1)
            command = command_line[0].split()[0]

            if command == 'QUIT':
                makefile.write('221 Bye\r\n')
                break
            elif command == 'MAIL':
                mail_from = command_line[1].strip() if len(command_line) > 1 else "UNKNOWN"
                makefile.write('250 OK\r\n')
            elif command == 'RCPT':
                mail_to.append(command_line[1].strip() if len(command_line) > 1 else "UNKNOWN")
                makefile.write('250 OK\r\n')
            elif command == 'DATA':
                makefile.write('354 Start mail input; end with <CRLF>.<CRLF>\r\n')
                makefile.flush()
                
                email_body = ""
                while True:
                    body_line = makefile.readline()
                    email_body += body_line
                    if body_line.strip() == '.':
                        break
                
                log_entry = create_log_entry(addr, "EMAIL_RECEIVED", {
                    "from": mail_from, 
                    "to": mail_to,
                    "body_snippet": email_body[:100].replace('\n', ' ').strip() + "..."
                })
                log_event(log_entry)
                makefile.write('250 OK\r\n')
            elif command in ['HELO', 'EHLO', 'VRFY']:
                makefile.write('250 OK\r\n')
            else:
                makefile.write('500 Syntax error, command unrecognised\r\n')
            
            makefile.flush()

        except Exception as e:
            print(f"Error handling SMTP connection: {e}")
            break

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[*] SMTP Honeypot listening on {HOST}:{PORT}. Logs to {LOG_FILE}")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"[*] Connection from {addr[0]} on SMTP")
                handle_connection(conn, addr)

if __name__ == '__main__':
    start_server()