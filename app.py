from flask import (send_file, Flask, render_template, request,
                   redirect, url_for, flash, jsonify, abort)
import io, os
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_required, current_user
from functools import wraps

from database import init_db, get_db
from models import User
from auth import auth as auth_blueprint
from detector.preprocess import clean_commands
from detector.sequence_builder import build_sequences
from detector.profiler import train_user, get_profile_stats
from detector.detector import detect

# load .env
_env_path = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if "=" in _line and not _line.startswith("#"):
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k, _v)

app = Flask(__name__)
app.secret_key = "csids-secret-key"
UPLOAD_FOLDER      = "uploads"
ALLOWED_EXTENSIONS = {"txt", "log", "history"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
init_db()

# Flask-Login
login_manager = LoginManager(app)
login_manager.login_view             = "auth.login"
login_manager.login_message          = "Please log in to access this page."
login_manager.login_message_category = "error"
app.register_blueprint(auth_blueprint)


@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM auth_users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        return User(row["id"], row["username"], row["role"], row["email"])
    return None


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


def allowed_file(filename):
    return ("." in filename and
            filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS)


def is_text_file(filepath):
    try:
        with open(filepath, "r", errors="strict") as f:
            f.read(1024)
        return True
    except UnicodeDecodeError:
        return False


# ═══════════════════════════════════════════
#  ADMIN ROUTES
# ═══════════════════════════════════════════

@app.route("/")
@admin_required
def dashboard():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT COUNT(DISTINCT user) FROM user_sequences")
    total_users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cur.fetchone()[0]
    cur.execute(
        "SELECT COUNT(*) FROM alerts "
        "WHERE timestamp > datetime('now', '-1 day')"
    )
    alerts_24h = cur.fetchone()[0]
    cur.execute(
        "SELECT user, COUNT(*) as cnt FROM alerts "
        "GROUP BY user ORDER BY cnt DESC LIMIT 5"
    )
    top_users = cur.fetchall()
    cur.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 8")
    recent = cur.fetchall()
    cur.execute(
        "SELECT strftime('%H', timestamp) as hour, COUNT(*) as cnt "
        "FROM alerts GROUP BY hour ORDER BY hour"
    )
    hourly_raw = cur.fetchall()
    cur.execute("""
        SELECT
            CASE WHEN risk_score>=6 THEN 'High'
                 WHEN risk_score>=3 THEN 'Medium'
                 ELSE 'Low' END as level,
            COUNT(*) as cnt
        FROM alerts GROUP BY level
    """)
    risk_raw = cur.fetchall()
    cur.execute(
        "SELECT id, username, role, email, created_at "
        "FROM auth_users ORDER BY created_at DESC"
    )
    all_auth_users = cur.fetchall()
    conn.close()

    hourly = [0] * 24
    for row in hourly_raw:
        hourly[int(row["hour"])] = row["cnt"]
    risk_dist = {r["level"]: r["cnt"] for r in risk_raw}

    return render_template("dashboard.html",
        total_users=total_users, total_alerts=total_alerts,
        alerts_24h=alerts_24h, top_users=top_users,
        recent_alerts=recent, hourly=hourly,
        risk_dist=risk_dist, all_auth_users=all_auth_users)


@app.route("/admin/send-alert", methods=["POST"])
@admin_required
def admin_send_alert():
    target_user = request.form.get("target_user", "").strip()
    email       = request.form.get("email", "").strip()
    if not target_user or not email:
        flash("Target user and email are required.", "error")
        return redirect(url_for("dashboard"))
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT * FROM alerts WHERE user=? ORDER BY timestamp DESC LIMIT 10",
        (target_user,)
    )
    alerts = [dict(r) for r in cur.fetchall()]
    conn.close()
    if not alerts:
        flash(f"No alerts found for '{target_user}'.", "error")
        return redirect(url_for("dashboard"))
    from notifier import send_alert_email
    send_alert_email(email, target_user, alerts)
    flash(f"✅ Alert email sent to {email} for user '{target_user}'.", "success")
    return redirect(url_for("dashboard"))


@app.route("/admin/user/<username>")
@admin_required
def admin_user_detail(username):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT * FROM alerts WHERE user=? ORDER BY timestamp DESC LIMIT 200",
        (username,)
    )
    alerts = cur.fetchall()
    cur.execute(
        "SELECT * FROM live_log WHERE user=? ORDER BY timestamp DESC LIMIT 200",
        (username,)
    )
    commands = cur.fetchall()
    cur.execute(
        "SELECT sequence, frequency FROM user_sequences "
        "WHERE user=? ORDER BY frequency DESC LIMIT 50",
        (username,)
    )
    sequences = cur.fetchall()
    conn.close()
    stats = get_profile_stats(username)
    return render_template("admin_user_detail.html",
        username=username, alerts=alerts,
        commands=commands, sequences=sequences, stats=stats)


@app.route("/admin/mark-safe/<int:alert_id>", methods=["POST"])
@admin_required
def mark_safe(alert_id):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM alerts WHERE id=?", (alert_id,))
    alert = cur.fetchone()
    if not alert:
        flash("Alert not found.", "error")
        conn.close()
        return redirect(url_for("alerts_page"))

    # save to false_positives
    cur.execute("""
        INSERT OR IGNORE INTO false_positives (user, sequence, marked_by)
        VALUES (?, ?, ?)
    """, (alert['user'], alert['sequence'], current_user.username))

    # add to user profile with high frequency so it learns it
    cur.execute("""
        INSERT INTO user_sequences (user, sequence, frequency)
        VALUES (?, ?, 5)
        ON CONFLICT(user, sequence)
        DO UPDATE SET frequency = frequency + 5
    """, (alert['user'], alert['sequence']))

    # delete the alert
    cur.execute("DELETE FROM alerts WHERE id=?", (alert_id,))

    conn.commit()
    conn.close()
    flash("✅ Marked as safe. System will not alert on this again.", "success")
    return redirect(url_for("alerts_page"))


@app.route("/analyze", methods=["GET", "POST"])
@admin_required
def analyze():
    if request.method == "POST":
        user   = request.form.get("user", "").strip()
        mode   = request.form.get("mode")
        email  = request.form.get("email", "").strip()
        notify = request.form.get("notify_email") == "on"
        file   = request.files.get("history")
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
        path     = os.path.join(UPLOAD_FOLDER, filename)
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
            flash(f"Profile trained for '{user}' — {count} sequences stored.",
                  "success")
            return redirect(url_for("analyze"))
        alerts, error = detect(user, sequences)
        if error:
            flash(error, "error")
            return redirect(url_for("analyze"))
        if alerts:
            conn = get_db()
            cur  = conn.cursor()
            for a in alerts:
                cur.execute(
                    "INSERT INTO alerts "
                    "(user,sequence,reason,risk_score,risky_cmds) "
                    "VALUES (?,?,?,?,?)",
                    (user, a["sequence"], a["reason"],
                     a["risk_score"], ",".join(a["risky"]))
                )
            conn.commit()
            conn.close()
            if notify and email:
                from notifier import send_alert_email
                send_alert_email(email, user, alerts)
        return render_template("results.html",
                               alerts=alerts, user=user,
                               total=len(sequences))
    return render_template("analyze.html")


@app.route("/alerts")
@admin_required
def alerts_page():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 200")
    alerts = cur.fetchall()
    conn.close()
    return render_template("alerts.html", alerts=alerts, user_view=False)


@app.route("/live")
@admin_required
def live_monitor():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT username FROM auth_users "
        "WHERE role='user' ORDER BY username"
    )
    user_list = [r["username"] for r in cur.fetchall()]
    conn.close()
    return render_template("live.html",
                           locked_user=None, user_list=user_list)


@app.route("/settings")
@admin_required
def settings():
    smtp_host = os.environ.get("CSIDS_SMTP_HOST", "")
    smtp_port = os.environ.get("CSIDS_SMTP_PORT", "587")
    smtp_user = os.environ.get("CSIDS_SMTP_USER", "")
    return render_template("settings.html",
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_user=smtp_user)


@app.route("/settings/save", methods=["POST"])
@admin_required
def settings_save():
    env_path = os.path.join(os.path.dirname(__file__), ".env")

    if request.form.get("clear_smtp"):
        with open(env_path, "w") as f:
            f.write("")
        for key in ["CSIDS_SMTP_HOST", "CSIDS_SMTP_PORT",
                    "CSIDS_SMTP_USER", "CSIDS_SMTP_PASS"]:
            os.environ.pop(key, None)
        flash("🗑 Email settings removed.", "success")
        return redirect(url_for("settings"))

    smtp_host = request.form.get("smtp_host", "smtp.gmail.com")
    smtp_port = request.form.get("smtp_port", "587")
    smtp_user = request.form.get("smtp_user", "")
    smtp_pass = request.form.get("smtp_pass", "")

    existing = {}
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    existing[k] = v

    existing["CSIDS_SMTP_HOST"] = smtp_host
    existing["CSIDS_SMTP_PORT"] = smtp_port
    existing["CSIDS_SMTP_USER"] = smtp_user
    if smtp_pass:
        existing["CSIDS_SMTP_PASS"] = smtp_pass

    with open(env_path, "w") as f:
        for k, v in existing.items():
            f.write(f"{k}={v}\n")

    os.environ["CSIDS_SMTP_HOST"] = smtp_host
    os.environ["CSIDS_SMTP_PORT"] = smtp_port
    os.environ["CSIDS_SMTP_USER"] = smtp_user
    if smtp_pass:
        os.environ["CSIDS_SMTP_PASS"] = smtp_pass

    flash("✅ Settings saved successfully.", "success")
    return redirect(url_for("settings"))


@app.route("/report/<username>")
@admin_required
def download_report(username):
    from pdf_report import generate_pdf_report
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT * FROM alerts WHERE user=? "
        "ORDER BY timestamp DESC LIMIT 500",
        (username,)
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    alerts = []
    for r in rows:
        r["risky"] = r["risky_cmds"].split(",") if r["risky_cmds"] else []
        alerts.append(r)
    stats     = get_profile_stats(username)
    pdf_bytes = generate_pdf_report(username, alerts, stats)
    return send_file(io.BytesIO(pdf_bytes),
                     mimetype="application/pdf",
                     as_attachment=True,
                     download_name=f"csids_report_{username}.pdf")


# ═══════════════════════════════════════════
#  USER ROUTES
# ═══════════════════════════════════════════

@app.route("/user/dashboard")
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for("dashboard"))
    username = current_user.username
    conn     = get_db()
    cur      = conn.cursor()
    cur.execute(
        "SELECT COUNT(*) FROM alerts WHERE user=?", (username,)
    )
    total_alerts = cur.fetchone()[0]
    cur.execute(
        "SELECT COUNT(*) FROM alerts "
        "WHERE user=? AND timestamp > datetime('now','-1 day')",
        (username,)
    )
    alerts_24h = cur.fetchone()[0]
    cur.execute(
        "SELECT * FROM alerts WHERE user=? "
        "ORDER BY timestamp DESC LIMIT 8",
        (username,)
    )
    recent = cur.fetchall()
    cur.execute("""
        SELECT
            CASE WHEN risk_score>=6 THEN 'High'
                 WHEN risk_score>=3 THEN 'Medium'
                 ELSE 'Low' END as level,
            COUNT(*) as cnt
        FROM alerts WHERE user=? GROUP BY level
    """, (username,))
    risk_dist = {r["level"]: r["cnt"] for r in cur.fetchall()}
    conn.close()
    return render_template("user_dashboard.html",
        total_alerts=total_alerts, alerts_24h=alerts_24h,
        recent_alerts=recent, risk_dist=risk_dist)


@app.route("/user/upload", methods=["GET", "POST"])
@login_required
def user_upload():
    if current_user.is_admin:
        return redirect(url_for("analyze"))
    username = current_user.username
    if request.method == "POST":
        mode   = request.form.get("mode")
        file   = request.files.get("history")
        notify = request.form.get("notify_email") == "on"
        if not file or file.filename == "":
            flash("Please upload a file.", "error")
            return redirect(url_for("user_upload"))
        if not allowed_file(file.filename):
            flash("Only .txt, .log, or .history files allowed.", "error")
            return redirect(url_for("user_upload"))
        filename = secure_filename(file.filename)
        path     = os.path.join(UPLOAD_FOLDER, filename)
        file.save(path)
        if not is_text_file(path):
            os.remove(path)
            flash("File must be plain text.", "error")
            return redirect(url_for("user_upload"))
        with open(path, errors="replace") as f:
            commands = f.readlines()
        cleaned   = clean_commands(commands)
        sequences = build_sequences(cleaned)
        if mode == "train":
            count = train_user(username, sequences)
            flash(f"Profile trained — {count} sequences stored.", "success")
            return redirect(url_for("user_upload"))
        alerts, error = detect(username, sequences)
        if error:
            flash(error, "error")
            return redirect(url_for("user_upload"))
        if alerts:
            conn = get_db()
            cur  = conn.cursor()
            for a in alerts:
                cur.execute(
                    "INSERT INTO alerts "
                    "(user,sequence,reason,risk_score,risky_cmds) "
                    "VALUES (?,?,?,?,?)",
                    (username, a["sequence"], a["reason"],
                     a["risk_score"], ",".join(a["risky"]))
                )
            conn.commit()
            conn.close()
            if notify and current_user.email:
                from notifier import send_alert_email
                send_alert_email(current_user.email, username, alerts)
        return render_template("results.html",
                               alerts=alerts, user=username,
                               total=len(sequences))
    return render_template("user_upload.html")


@app.route("/user/alerts")
@login_required
def user_alerts():
    if current_user.is_admin:
        return redirect(url_for("alerts_page"))
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT * FROM alerts WHERE user=? "
        "ORDER BY timestamp DESC LIMIT 200",
        (current_user.username,)
    )
    alerts = cur.fetchall()
    conn.close()
    return render_template("alerts.html", alerts=alerts, user_view=True)


@app.route("/user/live")
@login_required
def user_live():
    if current_user.is_admin:
        return redirect(url_for("live_monitor"))
    return render_template("live.html",
                           locked_user=current_user.username,
                           user_list=[])


@app.route("/user/report")
@login_required
def user_download_report():
    if current_user.is_admin:
        return redirect(url_for("dashboard"))
    username = current_user.username
    from pdf_report import generate_pdf_report
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT * FROM alerts WHERE user=? "
        "ORDER BY timestamp DESC LIMIT 500",
        (username,)
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    if not rows:
        flash("No alerts found to generate report.", "error")
        return redirect(url_for("user_dashboard"))
    alerts = []
    for r in rows:
        r['risky'] = r['risky_cmds'].split(',') if r['risky_cmds'] else []
        alerts.append(r)
    stats     = get_profile_stats(username)
    pdf_bytes = generate_pdf_report(username, alerts, stats)
    return send_file(io.BytesIO(pdf_bytes),
                     mimetype="application/pdf",
                     as_attachment=True,
                     download_name=f"csids_report_{username}.pdf")


@app.route("/user/mark-safe/<int:alert_id>", methods=["POST"])
@login_required
def user_mark_safe(alert_id):
    if current_user.is_admin:
        return redirect(url_for("alerts_page"))
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT * FROM alerts WHERE id=? AND user=?",
        (alert_id, current_user.username)
    )
    alert = cur.fetchone()
    if not alert:
        flash("Alert not found.", "error")
        conn.close()
        return redirect(url_for("user_alerts"))

    # save to false_positives
    cur.execute("""
        INSERT OR IGNORE INTO false_positives (user, sequence, marked_by)
        VALUES (?, ?, ?)
    """, (current_user.username, alert['sequence'], current_user.username))

    # add to profile with high frequency
    cur.execute("""
        INSERT INTO user_sequences (user, sequence, frequency)
        VALUES (?, ?, 5)
        ON CONFLICT(user, sequence)
        DO UPDATE SET frequency = frequency + 5
    """, (current_user.username, alert['sequence']))

    # delete the alert
    cur.execute("DELETE FROM alerts WHERE id=?", (alert_id,))

    conn.commit()
    conn.close()
    flash("✅ Marked as safe. System will not alert on this again.", "success")
    return redirect(url_for("user_alerts"))


# ═══════════════════════════════════════════
#  API ROUTES
# ═══════════════════════════════════════════

@app.route("/api/live-log")
@login_required
def api_live_log():
    since_id = request.args.get("since", 0, type=int)
    user     = request.args.get("user", "")
    if not current_user.is_admin:
        user = current_user.username
    conn = get_db()
    cur  = conn.cursor()
    if user:
        cur.execute(
            "SELECT id,user,command,risk_score,flagged,timestamp "
            "FROM live_log WHERE id>? AND user=? "
            "ORDER BY id ASC LIMIT 100",
            (since_id, user)
        )
    else:
        cur.execute(
            "SELECT id,user,command,risk_score,flagged,timestamp "
            "FROM live_log WHERE id>? ORDER BY id ASC LIMIT 100",
            (since_id,)
        )
    rows = []
    for r in cur.fetchall():
        rows.append({
            "id":         r[0],
            "user":       r[1],
            "command":    r[2],
            "risk_score": r[3],
            "flagged":    r[4],
            "timestamp":  r[5]
        })
    conn.close()
    return jsonify(rows)


@app.route("/api/recent-alerts")
@login_required
def api_recent_alerts():
    since_id = request.args.get("since", 0, type=int)
    user     = request.args.get("user", "")
    if not current_user.is_admin:
        user = current_user.username
    conn = get_db()
    cur  = conn.cursor()
    if user:
        cur.execute(
            "SELECT id,user,sequence,reason,risk_score,risky_cmds,timestamp "
            "FROM alerts WHERE id>? AND user=? "
            "ORDER BY id ASC LIMIT 20",
            (since_id, user)
        )
    else:
        cur.execute(
            "SELECT id,user,sequence,reason,risk_score,risky_cmds,timestamp "
            "FROM alerts WHERE id>? ORDER BY id ASC LIMIT 20",
            (since_id,)
        )
    rows = []
    for r in cur.fetchall():
        rows.append({
            "id":         r[0],
            "user":       r[1],
            "sequence":   r[2],
            "reason":     r[3],
            "risk_score": r[4],
            "risky_cmds": r[5],
            "timestamp":  r[6]
        })
    conn.close()
    return jsonify(rows)


@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403


if __name__ == "__main__":
    app.run(debug=True)