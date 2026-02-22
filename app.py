from flask import Flask, render_template, request, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename

from database import init_db, get_db
from detector.preprocess import clean_commands
from detector.sequence_builder import build_sequences
from detector.profiler import train_user, get_profile_stats
from detector.detector import detect

app = Flask(__name__)
app.secret_key = "csids-secret-key"
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt", "log", "history"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

init_db()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def is_text_file(filepath):
    try:
        with open(filepath, "r", errors="strict") as f:
            f.read(1024)
        return True
    except UnicodeDecodeError:
        return False


@app.route("/")
def dashboard():
    conn = get_db()
    cur  = conn.cursor()

    cur.execute("SELECT COUNT(DISTINCT user) FROM user_sequences")
    total_users = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM alerts WHERE timestamp > datetime('now', '-1 day')")
    alerts_24h = cur.fetchone()[0]

    cur.execute("SELECT user, COUNT(*) as cnt FROM alerts GROUP BY user ORDER BY cnt DESC LIMIT 5")
    top_users = cur.fetchall()

    cur.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 8")
    recent = cur.fetchall()

    # chart data — alerts grouped by hour
    cur.execute("""
        SELECT strftime('%H', timestamp) as hour, COUNT(*) as cnt
        FROM alerts GROUP BY hour ORDER BY hour
    """)
    hourly_raw = cur.fetchall()

    # chart data — risk score distribution
    cur.execute("""
        SELECT
            CASE
                WHEN risk_score >= 6 THEN 'High'
                WHEN risk_score >= 3 THEN 'Medium'
                ELSE 'Low'
            END as level,
            COUNT(*) as cnt
        FROM alerts GROUP BY level
    """)
    risk_raw = cur.fetchall()

    conn.close()

    # build full 24-hour array (fill missing hours with 0)
    hourly = [0] * 24
    for row in hourly_raw:
        hourly[int(row["hour"])] = row["cnt"]

    risk_dist = {r["level"]: r["cnt"] for r in risk_raw}

    return render_template("dashboard.html",
        total_users=total_users,
        total_alerts=total_alerts,
        alerts_24h=alerts_24h,
        top_users=top_users,
        recent_alerts=recent,
        hourly=hourly,
        risk_dist=risk_dist
    )

@app.route("/analyze", methods=["GET", "POST"])
def analyze():
    if request.method == "POST":
        user  = request.form.get("user", "").strip()
        mode  = request.form.get("mode")
        file  = request.files.get("history")

        if not user:
            flash("Username is required.", "error")
            return redirect(url_for("analyze"))

        if not file or file.filename == "":
            flash("Please upload a file.", "error")
            return redirect(url_for("analyze"))

        if not allowed_file(file.filename):
            flash("Only .txt, .log, or .history files allowed.", "error")
            return redirect(url_for("analyze"))

        filename = secure_filename(file.filename)
        path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(path)

        if not is_text_file(path):
            os.remove(path)
            flash("File must be plain text.", "error")
            return redirect(url_for("analyze"))

        with open(path, errors="replace") as f:
            commands = f.readlines()

        cleaned   = clean_commands(commands)
        sequences = build_sequences(cleaned)

        if mode == "train":
            count = train_user(user, sequences)
            flash(f"Profile trained for '{user}' — {count} sequences stored.", "success")
            return redirect(url_for("analyze"))

        alerts, error = detect(user, sequences)
        if error:
            flash(error, "error")
            return redirect(url_for("analyze"))

        # save alerts to DB
        if alerts:
            conn = get_db()
            cur  = conn.cursor()
            for a in alerts:
                cur.execute("""
                    INSERT INTO alerts (user, sequence, reason, risk_score, risky_cmds)
                    VALUES (?, ?, ?, ?, ?)
                """, (user, a["sequence"], a["reason"],
                      a["risk_score"], ",".join(a["risky"])))
            conn.commit()
            conn.close()

        return render_template("results.html",
            alerts=alerts, user=user, total=len(sequences))

    return render_template("analyze.html")


@app.route("/alerts")
def alerts_page():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 200")
    alerts = cur.fetchall()
    conn.close()
    return render_template("alerts.html", alerts=alerts)


@app.route("/live")
def live_monitor():
    return render_template("live.html")


@app.route("/settings")
def settings():
    return render_template("settings.html")


if __name__ == "__main__":
    app.run(debug=True)