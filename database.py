import sqlite3

DB_NAME = "ids.db"

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # ✅ lets us access columns by name
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_sequences (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        user      TEXT NOT NULL,
        sequence  TEXT NOT NULL,
        frequency INTEGER DEFAULT 1,
        UNIQUE(user, sequence)
    )
    """)

    conn.commit()
    conn.close()