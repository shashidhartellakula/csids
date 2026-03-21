import time
import os
import sys
import argparse
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "ids.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_risk_score(command):
    """Simple risk scoring for live commands."""
    risky = [
        'rm', 'sudo', 'chmod', 'chown', 'wget', 'curl', 'nc', 'nmap',
        'passwd', 'su', 'kill', 'pkill', 'dd', 'mkfs', 'fdisk',
        'iptables', 'ufw', 'ssh', 'scp', 'ftp', 'python', 'perl',
        'bash', 'sh', 'eval', 'exec', 'base64', 'crontab', 'at',
        'systemctl', 'service', 'mount', 'umount', 'useradd', 'userdel'
    ]
    cmd = command.strip().split()[0] if command.strip() else ''
    score = 0.0
    for r in risky:
        if r in command.lower():
            score += 2.0
    if cmd in risky:
        score += 1.0
    return min(score, 10.0)

def log_command(user, command, risk_score, flagged=0):
    conn = get_db()
    conn.execute(
        "INSERT INTO live_log (user, command, risk_score, flagged) VALUES (?,?,?,?)",
        (user, command.strip(), risk_score, flagged)
    )
    conn.commit()
    conn.close()

def monitor(user, history_path):
    print(f"[CSIDS] Monitoring user: {user}")
    print(f"[CSIDS] Watching file:   {history_path}")
    print(f"[CSIDS] Press Ctrl+C to stop.\n")

    if not os.path.exists(history_path):
        print(f"[ERROR] File not found: {history_path}")
        sys.exit(1)

    # start from current end of file
    with open(history_path, 'r', errors='replace') as f:
        f.seek(0, 2)  # seek to end
        last_pos = f.tell()

    while True:
        try:
            with open(history_path, 'r', errors='replace') as f:
                f.seek(last_pos)
                new_lines = f.readlines()
                last_pos  = f.tell()

            for line in new_lines:
                line = line.strip()
                if not line:
                    continue
                # strip bash history timestamps (#1234567890)
                if line.startswith('#'):
                    continue

                risk    = get_risk_score(line)
                flagged = 1 if risk >= 6 else 0
                log_command(user, line, risk, flagged)

                icon = '🚨' if flagged else ('🟡' if risk >= 3 else '🟢')
                print(f"{icon} [{user}] {line}  (risk: {risk:.1f})")

            time.sleep(1)

        except KeyboardInterrupt:
            print("\n[CSIDS] Monitor stopped.")
            break
        except Exception as e:
            print(f"[ERROR] {e}")
            time.sleep(2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='CSIDS Live Monitor')
    parser.add_argument('--user',    required=True, help='Username to monitor')
    parser.add_argument('--history', default=os.path.expanduser('~/.bash_history'),
                        help='Path to bash history file')
    args = parser.parse_args()
    monitor(args.user, args.history)