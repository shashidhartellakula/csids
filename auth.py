from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db
from models import User

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("SELECT * FROM auth_users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()
        if row and check_password_hash(row['password_hash'], password):
            user = User(row['id'], row['username'], row['role'], row['email'])
            login_user(user)
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for('dashboard') if row['role'] == 'admin' else url_for('user_dashboard'))
        flash("Invalid username or password.", "error")
    return render_template('login.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for('auth.login'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email    = request.form.get('email', '').strip()
        if not username or not password:
            flash("Username and password are required.", "error")
            return redirect(url_for('auth.register'))
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("SELECT id FROM auth_users WHERE username = ?", (username,))
        if cur.fetchone():
            flash("Username already exists.", "error")
            conn.close()
            return redirect(url_for('auth.register'))
        hashed = generate_password_hash(password)
        cur.execute(
            "INSERT INTO auth_users (username, password_hash, role, email) VALUES (?,?,?,?)",
            (username, hashed, 'user', email)
        )
        conn.commit()
        conn.close()
        flash("Account created! Please log in.", "success")
        return redirect(url_for('auth.login'))
    return render_template('register.html')