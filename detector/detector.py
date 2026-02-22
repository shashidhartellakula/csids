import re
from database import get_db
from detector.preprocess import RISKY_COMMANDS, get_risky_commands_in

# Thresholds
FREQ_THRESHOLD   = 2    # sequences seen <= this many times = rare
HIGH_RISK_SCORE  = 6.0  # always alert even if seen before
MEDIUM_RISK_SCORE = 3.0 # alert if also rare


def get_risk_score(sequence):
    """
    Calculate a numeric risk score 0.0 - 10.0 for a sequence.
    Based on command weights, sensitive paths, piping, etc.
    """
    score = 0
    parts = sequence.split(" | ")

    for part in parts:
        # base command weight
        base_cmd = part.split()[0] if part.split() else ""
        score += RISKY_COMMANDS.get(base_cmd, 0)

        # sensitive path access is extra risky
        if "SENSITIVE_" in part:
            score += 3

        # chained pipes are suspicious
        if "|" in part:
            score += 1

        # output redirected to sensitive location
        if re.search(r">\s*SENSITIVE_", part):
            score += 2

        # encoded payloads
        if "base64" in part or "xxd" in part:
            score += 2

        # background execution
        if part.strip().endswith("&"):
            score += 1

    # normalize to 0-10
    max_possible = len(parts) * 8
    if max_possible == 0:
        return 0.0
    return round(min((score / max_possible) * 10, 10.0), 2)


def detect(user, sequences, freq_threshold=FREQ_THRESHOLD):
    conn = get_db()
    cur = conn.cursor()

    # validate user has a trained profile
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

        # ✅ Rule 1 — never seen before + any risky command
        if freq == 0 and risky:
            reason = f"Unseen sequence containing risky commands"

        # ✅ Rule 2 — never seen before + medium risk score
        elif freq == 0 and risk_score >= MEDIUM_RISK_SCORE:
            reason = f"Unseen sequence with medium risk score ({risk_score})"

        # ✅ Rule 3 — very high risk even if seen before
        elif risk_score >= HIGH_RISK_SCORE:
            reason = f"High-risk sequence (score {risk_score}/10)"

        # ✅ Rule 4 — rarely seen + moderately risky
        elif freq <= FREQ_THRESHOLD and risk_score >= MEDIUM_RISK_SCORE:
            reason = f"Rarely seen sequence (only {freq}x) with risk score {risk_score}"

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