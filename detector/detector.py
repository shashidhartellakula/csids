from database import get_db

RISKY_CMDS = ["sudo", "chmod", "chown", "wget", "curl", "scp", "passwd", "su"]

def detect(user, sequences, freq_threshold=2):  # ✅ FIXED threshold: was 1, now 2
    conn = get_db()
    cur = conn.cursor()

    # ✅ NEW — check user has a trained profile
    cur.execute("SELECT 1 FROM user_sequences WHERE user = ? LIMIT 1", (user,))
    if not cur.fetchone():
        conn.close()
        return None, f"No training profile found for '{user}'. Please train first."

    alerts = []

    for seq in sequences:
        cur.execute(
            "SELECT frequency FROM user_sequences WHERE user=? AND sequence=?",
            (user, seq)
        )
        row = cur.fetchone()
        freq = row[0] if row else 0

        # ✅ FIXED — was: row is None or row[0] <= 1 (too loose)
        deviation = freq <= freq_threshold
        risky = [cmd for cmd in RISKY_CMDS if cmd in seq]

        if deviation and risky:
            alerts.append({
                "sequence": seq,
                "reason": f"Abnormal for user (seen {freq}x) + risky commands",
                "risky": risky,
                "frequency": freq
            })

    conn.close()
    return alerts, None  # ✅ now returns (alerts, error) tuple