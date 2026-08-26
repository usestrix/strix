"""SQLite database persistence for Strix Hub (users, tasks, sessions)."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

DB_PATH = Path(os.environ.get("STRIX_HUB_DB", "/opt/strix/strix_hub.db"))
if not DB_PATH.parent.exists():
    try:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        DB_PATH = Path.home() / ".strix" / "strix_hub.db"
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize database tables and create default admin account if not exists."""
    with get_connection() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL,
            owner_username TEXT NOT NULL,
            target TEXT NOT NULL,
            scan_mode TEXT NOT NULL DEFAULT 'deep',
            instruction TEXT DEFAULT '',
            root_model TEXT NOT NULL DEFAULT 'openai/gemini-3.1-pro-preview',
            root_api_base TEXT DEFAULT '',
            root_api_key_masked TEXT DEFAULT '',
            root_api_key_raw TEXT DEFAULT '',
            subagent_model TEXT NOT NULL DEFAULT 'openai/gemini-3.5-flash',
            subagent_api_base TEXT DEFAULT '',
            subagent_api_key_masked TEXT DEFAULT '',
            subagent_api_key_raw TEXT DEFAULT '',
            api_base TEXT DEFAULT '',
            api_key_masked TEXT DEFAULT '',
            api_key_raw TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            pid INTEGER DEFAULT NULL,
            run_dir_name TEXT DEFAULT '',
            vulns_count INTEGER DEFAULT 0,
            duration_seconds INTEGER DEFAULT 0,
            log_preview TEXT DEFAULT '',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)
        conn.commit()

        # Dynamic Schema Migration (add columns if older table exists)
        cursor = conn.cursor()
        existing_cols = {row["name"] for row in cursor.execute("PRAGMA table_info(tasks)").fetchall()}
        new_columns = [
            ("root_api_base", "TEXT DEFAULT ''"),
            ("root_api_key_masked", "TEXT DEFAULT ''"),
            ("root_api_key_raw", "TEXT DEFAULT ''"),
            ("subagent_api_base", "TEXT DEFAULT ''"),
            ("subagent_api_key_masked", "TEXT DEFAULT ''"),
            ("subagent_api_key_raw", "TEXT DEFAULT ''"),
        ]
        for col_name, col_type in new_columns:
            if col_name not in existing_cols:
                try:
                    cursor.execute(f"ALTER TABLE tasks ADD COLUMN {col_name} {col_type}")
                except Exception:
                    pass
        conn.commit()

    # Seed default admin user if table is empty
    ensure_admin_user()


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return key.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    key, _ = hash_password(password, salt)
    return hmac.compare_digest(key, password_hash)


def ensure_admin_user() -> None:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
        if cursor.fetchone() is None:
            admin_id = f"user_{secrets.token_hex(6)}"
            initial_password = os.environ.get("STRIX_HUB_ADMIN_PASSWORD", "admin123")
            p_hash, salt = hash_password(initial_password)
            cursor.execute(
                "INSERT INTO users (id, username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (admin_id, "admin", p_hash, salt, "admin", int(time.time())),
            )
            conn.commit()
            if initial_password == "admin123":
                logger.warning(
                    "Default administrator account initialized (username: admin, password: admin123). "
                    "Please change your password immediately in user settings or set STRIX_HUB_ADMIN_PASSWORD."
                )


# --- User Operations ---

def create_user(username: str, password: str, role: str = "user") -> dict[str, Any] | None:
    user_id = f"user_{secrets.token_hex(6)}"
    p_hash, salt = hash_password(password)
    now = int(time.time())
    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO users (id, username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, username.strip(), p_hash, salt, role, now),
            )
            conn.commit()
        return {"id": user_id, "username": username.strip(), "role": role, "created_at": now}
    except sqlite3.IntegrityError:
        return None


def get_user_by_username(username: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username.strip(),)).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute("SELECT id, username, role, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def list_users() -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY created_at ASC").fetchall()
        return [dict(r) for r in rows]


def delete_user(user_id: str) -> bool:
    with get_connection() as conn:
        cursor = conn.execute("DELETE FROM users WHERE id = ? AND role != 'admin'", (user_id,))
        conn.commit()
        return cursor.rowcount > 0


# --- Session Operations ---

def create_session(user_id: str, ttl_seconds: int = 86400 * 7) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + ttl_seconds
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
            (token, user_id, expires_at),
        )
        conn.commit()
    return token


def validate_session(token: str) -> dict[str, Any] | None:
    now = int(time.time())
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.username, u.role
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ? AND s.expires_at > ?
            """,
            (token, now),
        ).fetchone()
        return dict(row) if row else None


def delete_session(token: str) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


# --- Task Operations ---

def mask_api_key(key: str) -> str:
    if not key:
        return ""
    if len(key) <= 8:
        return "****"
    return f"{key[:4]}...{key[-4:]}"


def create_task(
    owner_id: str,
    owner_username: str,
    target: str,
    scan_mode: str = "deep",
    instruction: str = "",
    root_model: str = "openai/gemini-3.1-pro-preview",
    root_api_base: str = "",
    root_api_key: str = "",
    subagent_model: str = "openai/gemini-3.5-flash",
    subagent_api_base: str = "",
    subagent_api_key: str = "",
) -> dict[str, Any]:
    task_id = f"task_{secrets.token_hex(6)}"
    now = int(time.time())
    root_masked = mask_api_key(root_api_key)
    sub_masked = mask_api_key(subagent_api_key)

    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO tasks (
                id, owner_id, owner_username, target, scan_mode, instruction,
                root_model, root_api_base, root_api_key_masked, root_api_key_raw,
                subagent_model, subagent_api_base, subagent_api_key_masked, subagent_api_key_raw,
                status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
            """,
            (
                task_id,
                owner_id,
                owner_username,
                target.strip(),
                scan_mode,
                instruction.strip(),
                root_model.strip(),
                root_api_base.strip(),
                root_masked,
                root_api_key.strip(),
                subagent_model.strip(),
                subagent_api_base.strip(),
                sub_masked,
                subagent_api_key.strip(),
                now,
                now,
            ),
        )
        conn.commit()
    return get_task_by_id(task_id) or {}


def get_task_by_id(task_id: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT id, owner_id, owner_username, target, scan_mode, instruction,
                   root_model, root_api_base, root_api_key_masked,
                   subagent_model, subagent_api_base, subagent_api_key_masked,
                   status, pid, run_dir_name, vulns_count, duration_seconds,
                   log_preview, created_at, updated_at
            FROM tasks WHERE id = ?
            """,
            (task_id,),
        ).fetchone()
        return dict(row) if row else None


def get_task_full(task_id: str) -> dict[str, Any] | None:
    """Internal use: returns raw api_keys for task runner."""
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return dict(row) if row else None


def list_tasks(user_id: str | None = None, is_admin: bool = False) -> list[dict[str, Any]]:
    with get_connection() as conn:
        if is_admin or user_id is None:
            rows = conn.execute(
                """
                SELECT id, owner_id, owner_username, target, scan_mode, instruction,
                       root_model, root_api_base, root_api_key_masked,
                       subagent_model, subagent_api_base, subagent_api_key_masked,
                       status, pid, run_dir_name, vulns_count, duration_seconds,
                       created_at, updated_at
                FROM tasks ORDER BY created_at DESC
                """
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, owner_id, owner_username, target, scan_mode, instruction,
                       root_model, root_api_base, root_api_key_masked,
                       subagent_model, subagent_api_base, subagent_api_key_masked,
                       status, pid, run_dir_name, vulns_count, duration_seconds,
                       created_at, updated_at
                FROM tasks WHERE owner_id = ? ORDER BY created_at DESC
                """,
                (user_id,),
            ).fetchall()
        return [dict(r) for r in rows]


def update_task_status(
    task_id: str,
    status: str,
    pid: int | None = None,
    run_dir_name: str | None = None,
    vulns_count: int | None = None,
    duration_seconds: int | None = None,
    log_preview: str | None = None,
) -> None:
    now = int(time.time())
    updates = ["status = ?", "updated_at = ?"]
    params: list[Any] = [status, now]

    if pid is not None:
        updates.append("pid = ?")
        params.append(pid)
    if run_dir_name is not None:
        updates.append("run_dir_name = ?")
        params.append(run_dir_name)
    if vulns_count is not None:
        updates.append("vulns_count = ?")
        params.append(vulns_count)
    if duration_seconds is not None:
        updates.append("duration_seconds = ?")
        params.append(duration_seconds)
    if log_preview is not None:
        updates.append("log_preview = ?")
        params.append(log_preview)

    params.append(task_id)
    with get_connection() as conn:
        conn.execute(f"UPDATE tasks SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()


def update_task_model_config(
    task_id: str,
    root_model: str | None = None,
    root_api_base: str | None = None,
    root_api_key: str | None = None,
    subagent_model: str | None = None,
    subagent_api_base: str | None = None,
    subagent_api_key: str | None = None,
) -> None:
    """Hot update task model and channel configuration."""
    now = int(time.time())
    updates = ["updated_at = ?"]
    params: list[Any] = [now]

    if root_model is not None:
        updates.append("root_model = ?")
        params.append(root_model.strip())
    if root_api_base is not None:
        updates.append("root_api_base = ?")
        params.append(root_api_base.strip())
    if root_api_key is not None:
        updates.append("root_api_key_masked = ?")
        updates.append("root_api_key_raw = ?")
        params.append(mask_api_key(root_api_key))
        params.append(root_api_key.strip())

    if subagent_model is not None:
        updates.append("subagent_model = ?")
        params.append(subagent_model.strip())
    if subagent_api_base is not None:
        updates.append("subagent_api_base = ?")
        params.append(subagent_api_base.strip())
    if subagent_api_key is not None:
        updates.append("subagent_api_key_masked = ?")
        updates.append("subagent_api_key_raw = ?")
        params.append(mask_api_key(subagent_api_key))
        params.append(subagent_api_key.strip())

    params.append(task_id)
    with get_connection() as conn:
        conn.execute(f"UPDATE tasks SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()


def delete_task(task_id: str) -> bool:
    with get_connection() as conn:
        cursor = conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        conn.commit()
        return cursor.rowcount > 0
