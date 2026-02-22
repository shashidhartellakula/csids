from database import get_db
from datetime import datetime


def train_user(user, sequences):
    """
    Train a user's normal behavior profile from sequences.
    Uses INSERT OR REPLACE to properly upsert — no duplicate rows.
    Returns count of sequences stored.
    """
    conn = get_db()
    cur = conn.cursor()

    for seq in sequences:
        # ✅ FIXED — single query instead of SELECT then INSERT/UPDATE
        cur.execute("""
            INSERT INTO user_sequences (user, sequence, frequency)
            VALUES (?, ?, 1)
            ON CONFLICT(user, sequence)
            DO UPDATE SET frequency = frequency + 1
        """, (user, seq))

    conn.commit()
    conn.close()
    return len(sequences)


def user_exists(user):
    """Check if a user has a trained profile."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM user_sequences WHERE user = ? LIMIT 1", (user,))
    exists = cur.fetchone() is not None
    conn.close()
    return exists


def get_profile_stats(user):
    """Return stats about a user's trained profile."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT
            COUNT(*)        as total_sequences,
            SUM(frequency)  as total_observations,
            MAX(frequency)  as max_frequency,
            MIN(frequency)  as min_frequency,
            AVG(frequency)  as avg_frequency
        FROM user_sequences
        WHERE user = ?
    """, (user,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else {}