"""SQLite persistence and schema migration for the IDPS user store.

Kept free of Flask imports so the schema migration -- the riskiest part of this
upgrade, since it rewrites existing password rows -- can be tested directly
against a temporary database file.
"""

from __future__ import annotations

import sqlite3

import security

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT UNIQUE NOT NULL,
    password   TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

ROLE_ADMIN = "admin"
ROLE_USER = "user"


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def init_db(path: str, *, admin_username: str, admin_password: str | None = None) -> dict:
    """Create or upgrade the schema and make sure an admin account exists.

    Every step is idempotent, so this is safe to run on each start:

    * add the ``role`` column -- the previous build decided who was an
      administrator by comparing the session username to a hardcoded string;
    * add ``created_at``;
    * replace any plaintext password with a PBKDF2 hash **in place**, so accounts
      that already exist keep working after the upgrade;
    * seed the admin account if it is missing, using ``admin_password`` when
      given and otherwise a generated one that is returned to the caller.

    Returns ``{"migrated": int, "created_admin": bool, "generated_password": str|None}``.
    """
    report = {"migrated": 0, "created_admin": False, "generated_password": None}
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        columns = _columns(conn, "users")
        if "role" not in columns:
            conn.execute(
                f"ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT '{ROLE_USER}'"
            )
        if "created_at" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN created_at TEXT")

        # Whoever holds the configured admin name keeps the admin role.
        conn.execute(
            "UPDATE users SET role = ? WHERE username = ?", (ROLE_ADMIN, admin_username)
        )
        conn.execute(
            "UPDATE users SET role = ? WHERE role IS NULL OR role = ''", (ROLE_USER,)
        )

        for row in conn.execute("SELECT id, password FROM users").fetchall():
            stored = row["password"] or ""
            if security.looks_hashed(stored):
                continue
            # An empty password column cannot be logged into: replace it with a
            # hash of a random value rather than leaving it blank.
            plaintext = stored or security.new_csrf_token()
            conn.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (security.hash_password(plaintext), row["id"]),
            )
            report["migrated"] += 1

        exists = conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (admin_username,)
        ).fetchone()
        if not exists:
            password = (admin_password or "").strip()
            if not password:
                password = security.new_csrf_token()
                report["generated_password"] = password
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (admin_username, security.hash_password(password), ROLE_ADMIN),
            )
            report["created_admin"] = True

        conn.commit()
    finally:
        conn.close()
    return report


def find_user(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, username, password, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def create_user(conn: sqlite3.Connection, username: str, password: str,
                role: str = ROLE_USER) -> None:
    """Insert a user. Raises sqlite3.IntegrityError when the name is taken."""
    conn.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        (username, security.hash_password(password), role),
    )
    conn.commit()


def set_password(conn: sqlite3.Connection, user_id: int, password: str) -> None:
    conn.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (security.hash_password(password), user_id),
    )
    conn.commit()


def list_users(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT username, role, created_at FROM users ORDER BY username"
    ).fetchall()


def delete_non_admins(conn: sqlite3.Connection) -> int:
    cursor = conn.execute("DELETE FROM users WHERE role != ?", (ROLE_ADMIN,))
    conn.commit()
    return cursor.rowcount
