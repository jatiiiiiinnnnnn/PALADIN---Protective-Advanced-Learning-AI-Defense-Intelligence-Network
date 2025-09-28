# high_cowrie/session_parser.py
import json
from collections import defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
LOG_DIR = REPO_ROOT / "shared_logs" / "cowrie"
OUT_DIR = REPO_ROOT / "shared_logs" / "transcripts"
OUT_DIR.mkdir(parents=True, exist_ok=True)

def parse_logs_file(path):
    sessions = defaultdict(list)
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            sid = obj.get("session") or obj.get("src_ip") or obj.get("id") or "unknown"
            ts = obj.get("timestamp", "")
            eventid = obj.get("eventid", obj.get("event"))
            user = obj.get("username", "")
            pwd = obj.get("password", "")
            cmd = obj.get("input", obj.get("output", ""))
            line_txt = f"{ts} | evt={eventid} | user={user} | pass={pwd} | cmd={cmd}"
            sessions[sid].append(line_txt)
    return sessions

def main():
    json_files = sorted(LOG_DIR.glob("*.json"))
    combined = defaultdict(list)
    for jf in json_files:
        s = parse_logs_file(jf)
        for k, v in s.items():
            combined[k].extend(v)
    for sid, events in combined.items():
        out = OUT_DIR / f"session_{sid}.log"
        out.write_text("\n".join(events), encoding="utf-8")
    print(f"Parsed {len(combined)} sessions -> {OUT_DIR}")

if __name__ == "__main__":
    main()
