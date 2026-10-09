import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (Flask, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "change-this-secret-key"
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "complaints.db")

CATEGORIES = ["Academic", "Hostel", "Canteen", "Library", "Transport",
              "Infrastructure", "Faculty", "Other"]
STATUSES = ["Pending", "In Progress", "Resolved", "Rejected"]


# ---------- Database ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        roll_no TEXT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'student'
    );
    CREATE TABLE IF NOT EXISTS complaints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        subject TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Pending',
        admin_reply TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    """)
    exists = db.execute("SELECT 1 FROM users WHERE role='admin'").fetchone()
    if not exists:
        db.execute(
            "INSERT INTO users (name, roll_no, email, password, role) VALUES (?,?,?,?,?)",
            ("Administrator", "-", "admin@college.edu",
             generate_password_hash("admin123"), "admin"))
    db.commit()
    db.close()


# ---------- Auth helpers ----------
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                flash("Please login first.", "warning")
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                flash("You are not allowed to view that page.", "danger")
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return wrapper
    return decorator


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


# ---------- Public routes ----------
@app.route("/")
def index():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    if session.get("role") == "student":
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        roll_no = request.form["roll_no"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        if not (name and roll_no and email and password):
            flash("All fields are required.", "danger")
        elif len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (name, roll_no, email, password) VALUES (?,?,?,?)",
                    (name, roll_no, email, generate_password_hash(password)))
                db.commit()
                flash("Registration successful. Please login.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That email is already registered.", "danger")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        user = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["role"] = user["role"]
            return redirect(url_for("index"))
        flash("Invalid email or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("index"))


# ---------- Student routes ----------
@app.route("/dashboard")
@login_required("student")
def dashboard():
    rows = get_db().execute(
        "SELECT * FROM complaints WHERE user_id=? ORDER BY id DESC",
        (session["user_id"],)).fetchall()
    return render_template("student_dashboard.html", complaints=rows)


@app.route("/complaint/new", methods=["GET", "POST"])
@login_required("student")
def new_complaint():
    if request.method == "POST":
        category = request.form["category"]
        subject = request.form["subject"].strip()
        description = request.form["description"].strip()
        if category not in CATEGORIES or not subject or not description:
            flash("Please fill all fields correctly.", "danger")
        else:
            db = get_db()
            db.execute(
                """INSERT INTO complaints
                   (user_id, category, subject, description, created_at, updated_at)
                   VALUES (?,?,?,?,?,?)""",
                (session["user_id"], category, subject, description, now(), now()))
            db.commit()
            flash("Complaint submitted successfully.", "success")
            return redirect(url_for("dashboard"))
    return render_template("new_complaint.html", categories=CATEGORIES)


# ---------- Admin routes ----------
@app.route("/admin")
@login_required("admin")
def admin_dashboard():
    status = request.args.get("status", "")
    category = request.args.get("category", "")
    query = """SELECT c.*, u.name, u.roll_no FROM complaints c
               JOIN users u ON u.id = c.user_id WHERE 1=1"""
    params = []
    if status in STATUSES:
        query += " AND c.status=?"
        params.append(status)
    if category in CATEGORIES:
        query += " AND c.category=?"
        params.append(category)
    query += " ORDER BY c.id DESC"
    db = get_db()
    rows = db.execute(query, params).fetchall()
    counts = {s: db.execute("SELECT COUNT(*) FROM complaints WHERE status=?", (s,)).fetchone()[0]
              for s in STATUSES}
    return render_template("admin_dashboard.html", complaints=rows, counts=counts,
                           statuses=STATUSES, categories=CATEGORIES,
                           sel_status=status, sel_category=category)


@app.route("/admin/complaint/<int:cid>", methods=["GET", "POST"])
@login_required("admin")
def admin_complaint(cid):
    db = get_db()
    if request.method == "POST":
        status = request.form["status"]
        reply = request.form["admin_reply"].strip()
        if status in STATUSES:
            db.execute(
                "UPDATE complaints SET status=?, admin_reply=?, updated_at=? WHERE id=?",
                (status, reply, now(), cid))
            db.commit()
            flash("Complaint updated.", "success")
            return redirect(url_for("admin_dashboard"))
    row = db.execute(
        """SELECT c.*, u.name, u.roll_no, u.email FROM complaints c
           JOIN users u ON u.id = c.user_id WHERE c.id=?""", (cid,)).fetchone()
    if row is None:
        flash("Complaint not found.", "danger")
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_complaint.html", c=row, statuses=STATUSES)


init_db()

if __name__ == "__main__":
    app.run(debug=True)
