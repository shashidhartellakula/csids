import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "ids.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur  = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS user_sequences (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user      TEXT NOT NULL,
            sequence  TEXT NOT NULL,
            frequency INTEGER DEFAULT 1,
            UNIQUE(user, sequence)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user       TEXT NOT NULL,
            sequence   TEXT NOT NULL,
            reason     TEXT,
            risk_score REAL,
            risky_cmds TEXT,
            timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS live_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user       TEXT NOT NULL,
            command    TEXT NOT NULL,
            risk_score REAL    DEFAULT 0,
            flagged    INTEGER DEFAULT 0,
            timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS auth_users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'user',
            email         TEXT DEFAULT '',
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS false_positives (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user      TEXT NOT NULL,
            sequence  TEXT NOT NULL,
            marked_by TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user, sequence)
        )
    """)

    conn.commit()
    conn.close()