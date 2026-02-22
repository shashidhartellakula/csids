from database import get_db

def train_user(user, sequences):
    conn = get_db()
    cur = conn.cursor()

    for seq in sequences:
        cur.execute(
            "SELECT frequency FROM user_sequences WHERE user=? AND sequence=?",
            (user, seq)
        )
        row = cur.fetchone()

        if row:
            cur.execute(
                "UPDATE user_sequences SET frequency = frequency + 1 WHERE user=? AND sequence=?",
                (user, seq)
            )
        else:
            cur.execute(
                "INSERT INTO user_sequences VALUES (?, ?, 1)",
                (user, seq)
            )

    conn.commit()
    conn.close()
