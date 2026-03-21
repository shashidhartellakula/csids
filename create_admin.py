from werkzeug.security import generate_password_hash
from database import init_db, get_db

def create_admin(username="admin", password="admin123", email="admin@csids.local"):
    init_db()
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT id FROM auth_users WHERE username = ?", (username,))
    if cur.fetchone():
        print(f"[!] Admin '{username}' already exists.")
        conn.close()
        return
    hashed = generate_password_hash(password)
    cur.execute(
        "INSERT INTO auth_users (username, password_hash, role, email) VALUES (?,?,?,?)",
        (username, hashed, "admin", email)
    )
    conn.commit()
    conn.close()
    print(f"[✓] Admin created → username: {username}  password: {password}")

if __name__ == "__main__":
    create_admin()