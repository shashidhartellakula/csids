import time
import os
import sys
import argparse
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "ids.db")
sys.path.insert(0, os.path.dirname(__file__))

from detector.preprocess       import clean_commands
from detector.sequence_builder import build_sequences
from detector.profiler         import train_user
from detector.detector         import detect

BASELINE_THRESHOLD = 100


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_total_commands(user):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM live_log WHERE user=?", (user,))
    count = cur.fetchone()[0]
    conn.close()
    return count


def log_command(user, cmd, risk_score=0.0, flagged=0):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO live_log "
            "(user,command,risk_score,flagged) VALUES (?,?,?,?)",
            (user, cmd, risk_score, flagged)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB ERROR log] {e}")


def save_alert(user, sequence, reason, risk_score, risky_cmds):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO alerts "
            "(user,sequence,reason,risk_score,risky_cmds) "
            "VALUES (?,?,?,?,?)",
            (user, sequence, reason, risk_score, ','.join(risky_cmds))
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[DB ERROR alert] {e}")
        return False


def get_user_email(user):
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            "SELECT email FROM auth_users WHERE username=?", (user,)
        )
        row = cur.fetchone()
        conn.close()
        return row['email'] if row and row['email'] else None
    except Exception as e:
        print(f"[DB ERROR email] {e}")
        return None


def send_auto_alert(user, alerts):
    try:
        env_path = '/home/vboxuser/csids/.env'
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        k, v = line.split('=', 1)
                        os.environ[k] = v

        smtp_user = os.environ.get("CSIDS_SMTP_USER", "")
        smtp_pass = os.environ.get("CSIDS_SMTP_PASS", "")

        if not smtp_user or not smtp_pass:
            print(f"   [EMAIL] SMTP not configured")
            return

        email = get_user_email(user)
        if not email:
            print(f"   [EMAIL] No email for {user}")
            return

        print(f"   [EMAIL] Sending to {email}...")
        from notifier import send_alert_email
        send_alert_email(email, user, alerts)
        print(f"   [EMAIL] ✅ Alert sent to {email}")

    except Exception as e:
        import traceback
        print(f"   [EMAIL ERROR] {e}")
        traceback.print_exc()


def build_seqs(commands):
    try:
        cleaned   = clean_commands([c + '\n' for c in commands])
        sequences = build_sequences(cleaned)
        return sequences
    except Exception as e:
        print(f"[SEQ ERROR] {e}")
        return []


def update_profile(user, sequences):
    try:
        if sequences:
            train_user(user, sequences)
    except Exception as e:
        print(f"[PROFILE ERROR] {e}")


def run_detection(user, sequences):
    try:
        alerts, error = detect(user, sequences)
        if error:
            return []
        return alerts if alerts else []
    except Exception as e:
        print(f"[DETECT ERROR] {e}")
        return []


def monitor(user, history_path):
    history_path = os.path.expanduser(history_path)
    history_path = os.path.abspath(history_path)

    print(f"[CSIDS] Monitoring user     : {user}")
    print(f"[CSIDS] Watching file       : {history_path}")
    print(f"[CSIDS] Baseline threshold  : {BASELINE_THRESHOLD} commands")
    print(f"[CSIDS] Technique           : N-gram + TF-IDF + Cosine Similarity")
    print(f"[CSIDS] Profile update      : Continuous learning")
    print(f"[CSIDS] Alert basis         : Sequence of 3 commands")
    print(f"[CSIDS] Press Ctrl+C to stop.\n")

    # wait for file
    waited = 0
    while not os.path.exists(history_path):
        if waited == 0:
            print(f"[WAIT] File not found: {history_path}")
            print(f"[WAIT] Login as {user} and type any command.")
        waited += 1
        time.sleep(2)
        if waited > 30:
            print("[ERROR] File not found after 60s.")
            sys.exit(1)

    # show status
    total = get_total_commands(user)
    if total < BASELINE_THRESHOLD:
        remaining = BASELINE_THRESHOLD - total
        print(f"[CSIDS] 🔵 BASELINE TRAINING MODE")
        print(f"[CSIDS]    {total} commands learned")
        print(f"[CSIDS]    Need {remaining} more to activate detection\n")
    else:
        print(f"[CSIDS] ✅ DETECTION + CONTINUOUS LEARNING MODE")
        print(f"[CSIDS]    {total} commands in profile\n")

    # seek to end
    with open(history_path, 'r', errors='replace') as f:
        f.seek(0, 2)
        last_pos = f.tell()

    # sliding window of last 3 commands
    command_buffer = []

    while True:
        try:
            with open(history_path, 'r', errors='replace') as f:
                f.seek(last_pos)
                lines    = f.readlines()
                last_pos = f.tell()

            for raw_line in lines:
                cmd = raw_line.strip()
                if not cmd or cmd.startswith('#'):
                    continue

                total = get_total_commands(user)
                log_command(user, cmd, 0.0, 0)

                command_buffer.append(cmd)
                if len(command_buffer) > 3:
                    command_buffer.pop(0)

                # ── BASELINE TRAINING ─────────────────────────────────
                if total < BASELINE_THRESHOLD:
                    print(f"🔵 [TRAIN {total+1}/{BASELINE_THRESHOLD}]"
                          f" [{user}] {cmd}")

                    if len(command_buffer) == 3:
                        seqs = build_seqs(command_buffer)
                        if seqs:
                            update_profile(user, seqs)

                    if total + 1 >= BASELINE_THRESHOLD:
                        print(f"\n{'='*60}")
                        print(f"[CSIDS] ✅ BASELINE TRAINING COMPLETE!")
                        print(f"[CSIDS]    Detection mode activated.")
                        print(f"[CSIDS]    Profile keeps learning continuously.")
                        print(f"[CSIDS]    Alerts based on sequence of 3 commands.")
                        print(f"{'='*60}\n")

                # ── DETECTION + CONTINUOUS LEARNING ───────────────────
                else:
                    print(f"⌨  [DETECT] [{user}] {cmd}")

                    if len(command_buffer) == 3:
                        seqs    = build_seqs(command_buffer)
                        seq_str = ' | '.join(command_buffer)
                        print(f"   🔍 Analyzing: {seq_str}")

                        if seqs:
                            alerts = run_detection(user, seqs)

                            if alerts:
                                for a in alerts:
                                    saved = save_alert(
                                        user,
                                        a['sequence'],
                                        a['reason'],
                                        a['risk_score'],
                                        a['risky']
                                    )
                                    if saved:
                                        print(f"\n{'='*60}")
                                        print(f"   ⚠  INTRUSION ALERT!")
                                        print(f"   Sequence  : {a['sequence']}")
                                        print(f"   Reason    : {a['reason']}")
                                        print(f"   Risk Score: {a['risk_score']:.1f}")
                                        print(f"{'='*60}\n")

                                high_risk = [
                                    a for a in alerts
                                    if a['risk_score'] >= 6.0
                                ]
                                if high_risk:
                                    send_auto_alert(user, high_risk)
                            else:
                                # safe — update profile continuously
                                update_profile(user, seqs)
                                print(f"   ✅ Safe sequence — profile updated")

            time.sleep(1)

        except PermissionError:
            print(f"[ERROR] Permission denied.")
            print(f"[FIX]   sudo /home/vboxuser/csids/venv/bin/python "
                  f"/home/vboxuser/csids/monitor.py "
                  f"--user {user} --history {history_path}")
            sys.exit(1)

        except KeyboardInterrupt:
            print("\n[CSIDS] Monitor stopped.")
            break

        except Exception as e:
            print(f"[ERROR] {e}")
            time.sleep(2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='CSIDS Live Monitor')
    parser.add_argument('--user',    required=True)
    parser.add_argument('--history',
                        default=os.path.expanduser('~/.bash_history'))
    args = parser.parse_args()
    monitor(args.user, args.history)