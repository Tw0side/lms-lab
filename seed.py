import os
import sqlite3

FLAG = "FLAG{path_traversal_works}"

INTRO_MATERIAL = """Welcome to Introduction to Application Security.

This course covers the OWASP Top 10, source/sink analysis, and safe coding
practices. Your instructor will release additional handouts here.
"""

ADVANCED_MATERIAL = """Advanced Application Security - Week 1

Topics: authorization bugs, insecure direct object references, and
server-side trust boundaries. Quiz 1 will be announced in class.
"""


def ensure_materials(materials_dir):
    directories = {
        os.path.join(materials_dir, "intro"): {
            "intro.txt": INTRO_MATERIAL,
        },
        os.path.join(materials_dir, "advanced"): {
            "secret.txt": FLAG + "\n",
            "notes.txt": ADVANCED_MATERIAL,
        },
        materials_dir: {
            "secret.txt": FLAG + "\n",
        },
    }

    for directory, files in directories.items():
        os.makedirs(directory, exist_ok=True)
        for name, content in files.items():
            with open(os.path.join(directory, name), "w", encoding="utf-8") as handle:
                handle.write(content)


def seed():
    from app import DB_PATH, MATERIALS_DIR, SCHEMA

    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)

    conn.execute("DELETE FROM enrollments")
    conn.execute("DELETE FROM courses")
    conn.execute("DELETE FROM users")
    conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('users', 'courses', 'enrollments')")

    conn.executemany(
        "INSERT INTO users (id, username, password, role, email) VALUES (?, ?, ?, ?, ?)",
        [
            (1, "alice", "alice123", "student", "alice@example.com"),
            (2, "bob", "bob123", "student", "bob@example.com"),
            (3, "inst", "inst123", "instructor", "inst@example.com"),
        ],
    )

    conn.executemany(
        "INSERT INTO courses (id, name, description) VALUES (?, ?, ?)",
        [
            (
                1,
                "intro",
                "<p>Introduction to Application Security. Learn how to read code "
                "like an attacker and trace data from sources to sinks.</p>",
            ),
            (
                2,
                "advanced",
                "<p>Advanced Application Security. Authorization, access control, "
                "and trust boundaries.</p>",
            ),
        ],
    )

    conn.executemany(
        "INSERT INTO enrollments (id, user_id, course_id) VALUES (?, ?, ?)",
        [
            (1, 1, 1),
            (2, 2, 2),
        ],
    )

    conn.commit()
    conn.close()

    ensure_materials(MATERIALS_DIR)


if __name__ == "__main__":
    seed()
    print("Seeded database and materials")
