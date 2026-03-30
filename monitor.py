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

TRAINING_THRESHOLD = 100  # commands before switching to detection

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


def has_trained_profile(user):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM user_sequences WHERE user=?", (user,))
    count = cur.fetchone()[0]
    conn.close()
    return count > 0


def log_command(user, cmd, risk_score=0.0, flagged=0):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO live_log (user,command,risk_score,flagged) VALUES (?,?,?,?)",
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
            "INSERT INTO alerts (user,sequence,reason,risk_score,risky_cmds) VALUES (?,?,?,?,?)",
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
        cur.execute("SELECT email FROM auth_users WHERE username=?", (user,))
        row = cur.fetchone()
        conn.close()
        return row['email'] if row and row['email'] else None
    except Exception as e:
        print(f"[DB ERROR email] {e}")
        return None


def load_smtp_config():
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, v = line.split('=', 1)
                    os.environ[k] = v


def send_auto_alert(user, alerts):
    try:
        # load smtp from .env file directly
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

        print(f"   [EMAIL] SMTP user: {smtp_user}")

        if not smtp_user or not smtp_pass:
            print(f"   [EMAIL] SMTP not configured — go to admin Settings and save SMTP")
            return

        email = get_user_email(user)
        if not email:
            print(f"   [EMAIL] No email found for {user} in database")
            return

        print(f"   [EMAIL] Sending to {email}...")

        sys.path.insert(0, '/home/vboxuser/csids')
        from notifier import send_alert_email
        send_alert_email(email, user, alerts)
        print(f"   [EMAIL] ✅ Alert sent to {email}")

    except Exception as e:
        import traceback
        print(f"   [EMAIL ERROR] {e}")
        traceback.print_exc()


def auto_train(user, commands):
    """
    Automatically train user profile from commands.
    Uses existing profiler and sequence_builder.
    """
    try:
        cleaned   = clean_commands([c + '\n' for c in commands])
        sequences = build_sequences(cleaned)
        if sequences:
            count = train_user(user, sequences)
            return count
        return 0
    except Exception as e:
        print(f"[TRAIN ERROR] {e}")
        return 0


def auto_detect(user, commands):
    """
    Automatically detect intrusion from commands.
    Uses existing detector with TF-IDF + Cosine Similarity.
    """
    try:
        cleaned   = clean_commands([c + '\n' for c in commands])
        sequences = build_sequences(cleaned)
        if not sequences:
            return []
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

    print(f"[CSIDS] Monitoring user      : {user}")
    print(f"[CSIDS] Watching file        : {history_path}")
    print(f"[CSIDS] Training threshold   : {TRAINING_THRESHOLD} commands")
    print(f"[CSIDS] Detection technique  : N-gram + TF-IDF + Cosine Similarity")
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

    # show current status
    total = get_total_commands(user)
    if total < TRAINING_THRESHOLD:
        remaining = TRAINING_THRESHOLD - total
        print(f"[CSIDS] 🔵 TRAINING MODE")
        print(f"[CSIDS]    {total} commands learned so far")
        print(f"[CSIDS]    Need {remaining} more commands to switch to detection\n")
    else:
        print(f"[CSIDS] ✅ DETECTION MODE")
        print(f"[CSIDS]    {total} commands learned in profile\n")

    # seek to end — only watch new commands
    with open(history_path, 'r', errors='replace') as f:
        f.seek(0, 2)
        last_pos = f.tell()

    # buffer to hold recent commands for sequence building
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

                # ── TRAINING MODE ─────────────────────────────────────────
                if total < TRAINING_THRESHOLD:
                    remaining = TRAINING_THRESHOLD - total
                    log_command(user, cmd, 0.0, 0)
                    command_buffer.append(cmd)

                    print(f"🔵 [TRAIN {total+1}/{TRAINING_THRESHOLD}] [{user}] {cmd}")

                    # train every 3 commands using sequences
                    if len(command_buffer) >= 3:
                        auto_train(user, command_buffer)

                    # announce switch to detection
                    if total + 1 >= TRAINING_THRESHOLD:
                        print(f"\n{'='*55}")
                        print(f"[CSIDS] ✅ TRAINING COMPLETE for {user}!")
                        print(f"[CSIDS]    Switching to DETECTION mode now.")
                        print(f"[CSIDS]    Profile has learned normal behavior.")
                        print(f"{'='*55}\n")
                        command_buffer = []

                # ── DETECTION MODE ────────────────────────────────────────
                else:
                    log_command(user, cmd, 0.0, 0)
                    command_buffer.append(cmd)

                    print(f"⌨  [DETECT] [{user}] {cmd}")

                    # run detection every 3 commands
                    if len(command_buffer) >= 3:
                        alerts = auto_detect(user, command_buffer)

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
                                    print(f"\n{'='*55}")
                                    print(f"   ⚠  INTRUSION ALERT!")
                                    print(f"   Sequence  : {a['sequence']}")
                                    print(f"   Reason    : {a['reason']}")
                                    print(f"   Risk Score: {a['risk_score']:.1f}")
                                    print(f"{'='*55}\n")

                            # send email for high risk alerts
                            high_risk = [
                                a for a in alerts
                                if a['risk_score'] >= 6.0
                            ]
                            if high_risk:
                                send_auto_alert(user, high_risk)

                        # keep last 3 commands for next window
                        command_buffer = command_buffer[-3:]

            time.sleep(1)

        except PermissionError:
            print(f"[ERROR] Permission denied.")
            print(f"[FIX]   sudo venv/bin/python monitor.py --user {user} --history {history_path}")
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
    parser.add_argument('--history', default=os.path.expanduser('~/.bash_history'))
    args = parser.parse_args()
    monitor(args.user, args.history)