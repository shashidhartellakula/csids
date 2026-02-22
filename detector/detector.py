import re
from database import get_db
from detector.preprocess import get_risk_score, get_risky_commands_in

FREQ_THRESHOLD    = 2
HIGH_RISK_SCORE   = 6.0
MEDIUM_RISK_SCORE = 3.0


def detect(user, sequences, freq_threshold=FREQ_THRESHOLD, source="upload"):
    conn = get_db()
    cur = conn.cursor()

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

        risk_score = get_risk_score(seq)
        risky      = get_risky_commands_in(seq)
        reason     = None

        # Rule 1 — never seen + any risky command
        if freq == 0 and risky:
            reason = f"Unseen sequence with risky commands"

        # Rule 2 — never seen + medium risk score
        elif freq == 0 and risk_score >= MEDIUM_RISK_SCORE:
            reason = f"Unseen sequence with risk score {risk_score}"

        # Rule 3 — very high risk even if seen before
        elif risk_score >= HIGH_RISK_SCORE:
            reason = f"High-risk sequence (score {risk_score}/10)"

        # Rule 4 — rarely seen + moderately risky
        elif freq <= freq_threshold and risk_score >= MEDIUM_RISK_SCORE:
            reason = f"Rarely seen ({freq}x) with risk score {risk_score}"

        if reason:
            alerts.append({
                "sequence":   seq,
                "reason":     reason,
                "risk_score": risk_score,
                "risky":      risky,
                "frequency":  freq,
            })

    conn.close()
    return alerts, None