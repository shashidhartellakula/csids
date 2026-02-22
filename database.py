import sqlite3

DB_NAME = "ids.db"

def get_db():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_sequences (
        user TEXT,
        sequence TEXT,
        frequency INTEGER
    )
    """)

    conn.commit()
    conn.close()
