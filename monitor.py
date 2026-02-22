"""
CSIDS Real-Time Monitor
Watches ~/.bash_history for new commands and runs detection live.

Usage:
    python monitor.py --user shashi
    python monitor.py --user shashi --history /custom/path/.bash_history
    python monitor.py --user shashi --quiet
"""
import time
import os
import sys
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detector.preprocess import clean_commands, get_risk_score, get_risky_commands_in
from detector.sequence_builder import build_sequences
from detector.detector import detect
from database import get_db, init_db

POLL_INTERVAL = 1.5   # seconds between checks
WINDOW_SIZE   = 3     # sequence window size
COLORS = {
    "reset":  "\033[0m",
    "red":    "\033[91m",
    "yellow": "\033[93m",
    "green":  "\033[92m",
    "cyan":   "\033[96m",
    "dim":    "\033[2m",
    "bold":   "\033[1m",
}


def c(text, color):
    """Wrap text in terminal color."""
    return COLORS.get(color, "") + str(text) + COLORS["reset"]


def tail_new_lines(filepath, last_pos):
    """Read only new lines added since last_pos."""
    try:
        with open(filepath, "r", errors="replace") as f:
            f.seek(last_pos)
            new_lines = f.readlines()
            new_pos   = f.tell()
        return new_lines, new_pos
    except FileNotFoundError:
        return [], last_pos


def log_to_db(user, command, risk_score, flagged):
    """Save live command to DB for the browser dashboard."""
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("""
            INSERT INTO live_log (user, command, risk_score, flagged)
            VALUES (?, ?, ?, ?)
        """, (user, command, risk_score, int(flagged)))
        conn.commit()
        conn.close()
    except Exception:
        pass


def save_alert_to_db(user, alert):
    """Persist a real-time alert to the alerts table."""
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("""
            INSERT INTO alerts (user, sequence, reason, risk_score, risky_cmds)
            VALUES (?, ?, ?, ?, ?)
        """, (user, alert["sequence"], alert["reason"],
              alert["risk_score"], ",".join(alert["risky"])))
        conn.commit()
        conn.close()
    except Exception:
        pass


def print_banner(user, history_path):
    print(c("=" * 58, "cyan"))
    print(c("  CSIDS — Real-Time Monitor", "bold"))
    print(c("=" * 58, "cyan"))
    print(f"  User     : {c(user, 'cyan')}")
    print(f"  Watching : {c(history_path, 'dim')}")
    print(f"  Interval : {POLL_INTERVAL}s")
    print(c("=" * 58, "cyan"))
    print()


def monitor_loop(user, history_path, verbose=True):
    init_db()

    # make sure live_log table exists
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS live_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user       TEXT NOT NULL,
            command    TEXT NOT NULL,
            risk_score REAL DEFAULT 0,
            flagged    INTEGER DEFAULT 0,
            timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

    if not os.path.exists(history_path):
        print(c(f"[ERROR] History file not found: {history_path}", "red"))
        sys.exit(1)

    print_banner(user, history_path)

    # start from end of file — only watch NEW commands
    with open(history_path, "r", errors="replace") as f:
        f.seek(0, 2)
        last_pos = f.tell()

    # rolling buffer keeps last 20 commands for sequence context
    cmd_buffer = []

    ts = datetime.now().strftime("%H:%M:%S")
    print(c(f"[{ts}] Monitoring started. Run commands in another terminal...", "dim"))
    print()

    try:
        while True:
            new_lines, last_pos = tail_new_lines(history_path, last_pos)

            if new_lines:
                cleaned = clean_commands(new_lines)
                if not cleaned:
                    time.sleep(POLL_INTERVAL)
                    continue

                cmd_buffer.extend(cleaned)
                # keep buffer to last 20 commands
                if len(cmd_buffer) > 20:
                    cmd_buffer = cmd_buffer[-20:]

                for cmd in cleaned:
                    ts        = datetime.now().strftime("%H:%M:%S")
                    risk      = get_risk_score(f"{cmd} | {cmd} | {cmd}")
                    risky     = get_risky_commands_in(cmd)
                    is_flagged = bool(risky and risk >= 3)

                    if verbose:
                        if risk >= 6:
                            icon = c("🔴 HIGH  ", "red")
                        elif risk >= 3:
                            icon = c("🟡 WARN  ", "yellow")
                        else:
                            icon = c("🟢 OK    ", "green")

                        print(f"[{c(ts, 'dim')}] {icon} {c(cmd, 'cyan')}")

                        if risky:
                            print(f"           {c('⚠ Risky: ' + ', '.join(risky), 'yellow')}")

                    log_to_db(user, cmd, risk, is_flagged)

                # run detection on latest sequences
                sequences = build_sequences(cmd_buffer, WINDOW_SIZE)
                if sequences:
                    # only check last 5 sequences for performance
                    alerts, err = detect(user, sequences[-5:], source="realtime")
                    if alerts:
                        for alert in alerts:
                            save_alert_to_db(user, alert)
                            ts = datetime.now().strftime("%H:%M:%S")
                            print()
                            print(c("!" * 58, "red"))
                            print(c(f"  🚨 INTRUSION ALERT [{ts}]", "red"))
                            print(f"  Sequence  : {c(alert['sequence'], 'yellow')}")
                            print(f"  Reason    : {alert['reason']}")
                            print(f"  Risk Score: {c(str(alert['risk_score']) + '/10', 'red')}")
                            print(f"  Risky Cmds: {c(', '.join(alert['risky']), 'red')}")
                            print(c("!" * 58, "red"))
                            print()

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        ts = datetime.now().strftime("%H:%M:%S")
        print()
        print(c(f"[{ts}] Monitor stopped.", "dim"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CSIDS Real-Time Monitor")
    parser.add_argument("--user",    required=True,
                        help="Username to monitor (must have a trained profile)")
    parser.add_argument("--history", default=os.path.expanduser("~/.bash_history"),
                        help="Path to bash history file (default: ~/.bash_history)")
    parser.add_argument("--quiet",   action="store_true",
                        help="Only show alerts, suppress normal command output")
    args = parser.parse_args()

    monitor_loop(args.user, args.history, verbose=not args.quiet)