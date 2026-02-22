from database import get_db

RISKY_CMDS = ["sudo", "chmod", "chown", "wget", "curl", "scp", "passwd", "su"]

def detect(user, sequences, freq_threshold=1):
    conn = get_db()
    cur = conn.cursor()

    alerts = []

    for seq in sequences:
        cur.execute(
            "SELECT frequency FROM user_sequences WHERE user=? AND sequence=?",
            (user, seq)
        )
        row = cur.fetchone()

        deviation = row is None or row[0] <= freq_threshold
        risky = [cmd for cmd in RISKY_CMDS if cmd in seq]

        if deviation and risky:
            alerts.append({
                "sequence": seq,
                "reason": "Abnormal for user + risky commands",
                "risky": risky
            })

    conn.close()
    return alerts
