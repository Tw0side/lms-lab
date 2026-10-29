import os
import sqlite3
from functools import wraps

from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "lms.db")
MATERIALS_DIR = os.path.join(BASE_DIR, "materials")

app = Flask(__name__)
app.secret_key = "lms-lab-not-a-real-secret-2026"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role     TEXT NOT NULL,
    email    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS courses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT UNIQUE NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS enrollments (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (course_id) REFERENCES courses (id)
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    db.commit()
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        from seed import seed

        seed()
        db.commit()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.context_processor
def inject_session():
    return {"session": session}


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULN 2: SQL Injection - Login Bypass
        # Source: request.form["username"] and request.form["password"]
        # Sink: cursor.execute() below (raw sqlite3 cursor)
        # Missing control: parameterized query / bound parameters
        query = (
            "SELECT * FROM users WHERE username='"
            + username
            + "' AND password='"
            + password
            + "'"
        )
        user = get_db().execute(query).fetchone()  # noqa: S608  # VULN: string concatenation in SQL; username/password flow directly into execute()

        if user is not None:
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()

    if session.get("role") == "instructor":
        courses = db.execute("SELECT * FROM courses ORDER BY id").fetchall()
        enrollments = db.execute(
            """
            SELECT e.id AS enrollment_id, u.username, u.email, c.name AS course
            FROM enrollments e
            JOIN users u   ON u.id = e.user_id
            JOIN courses c ON c.id = e.course_id
            ORDER BY e.id
            """
        ).fetchall()
    else:
        courses = db.execute(
            """
            SELECT c.*
            FROM courses c
            JOIN enrollments e ON e.course_id = c.id
            WHERE e.user_id = ?
            ORDER BY c.id
            """,
            (session["user_id"],),
        ).fetchall()
        enrollments = db.execute(
            """
            SELECT e.id AS enrollment_id, u.username, u.email, c.name AS course
            FROM enrollments e
            JOIN users u   ON u.id = e.user_id
            JOIN courses c ON c.id = e.course_id
            WHERE e.user_id = ?
            ORDER BY e.id
            """,
            (session["user_id"],),
        ).fetchall()

    return render_template("dashboard.html", courses=courses, enrollments=enrollments)


@app.route("/course/<int:course_id>")
@login_required
def course(course_id):
    db = get_db()
    course_row = db.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
    if course_row is None:
        abort(404)

    course_dir = os.path.join(MATERIALS_DIR, course_row["name"])
    files = []
    if os.path.isdir(course_dir):
        files = sorted(
            name
            for name in os.listdir(course_dir)
            if os.path.isfile(os.path.join(course_dir, name))
        )

    enrolled = db.execute(
        """
        SELECT e.id AS enrollment_id, u.username, u.email
        FROM enrollments e
        JOIN users u ON u.id = e.user_id
        WHERE e.course_id = ?
        ORDER BY e.id
        """,
        (course_id,),
    ).fetchall()

    return render_template("course.html", course=course_row, files=files, enrolled=enrolled)


@app.route("/course/<int:course_id>/description", methods=["POST"])
@login_required
def update_description(course_id):
    if session.get("role") != "instructor":
        abort(403)

    description = request.form.get("description", "")
    db = get_db()
    db.execute(
        "UPDATE courses SET description = ? WHERE id = ?",
        (description, course_id),
    )
    db.commit()
    return redirect(url_for("course", course_id=course_id))


# VULN 1: Path Traversal - Unauthorized Course Material Read
# Source: request.args.get("file") (and attacker-controlled "course")
# Sink: open() on the path built by os.path.join() below
# Missing control: realpath containment check (resolved path must start with materials/<course>/)
@app.route("/material")
@login_required
def material():
    course_name = request.args.get("course", "")
    filename = request.args.get("file", "")

    path = os.path.join(MATERIALS_DIR, course_name, filename)  # VULN: no realpath containment check; filename can contain ../

    if not os.path.isfile(path):
        abort(404)

    with open(path, "rb") as handle:
        data = handle.read()

    return Response(data, mimetype="text/plain")


# VULN 4: IDOR - Another Student's Enrollment Data
# Source: URL path segment <int:enrollment_id> in /enrollment/<id>
# Sink: database read below followed by rendering enrollment.html
# Missing control: ownership check (enrollment.user_id must equal session["user_id"])
@app.route("/enrollment/<int:enrollment_id>")
@login_required
def enrollment(enrollment_id):
    db = get_db()

    record = db.execute(
        "SELECT * FROM enrollments WHERE id = ?", (enrollment_id,)
    ).fetchone()  # VULN: no ownership check; any logged-in user can read any enrollment by id
    if record is None:
        abort(404)

    student = db.execute(
        "SELECT username, email FROM users WHERE id = ?", (record["user_id"],)
    ).fetchone()
    course_row = db.execute(
        "SELECT name FROM courses WHERE id = ?", (record["course_id"],)
    ).fetchone()

    return render_template(
        "enrollment.html",
        enrollment=record,
        student=student,
        course=course_row,
    )


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
