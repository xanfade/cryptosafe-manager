import sqlite3
import threading
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime

from .models import SCHEMA_V1


class Database:
    def __init__(self, db_path: str):
        self.db_path = str(Path(db_path))
        self._local = threading.local()

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.execute("PRAGMA journal_mode=WAL;")
            self._local.conn = conn
        return conn

    @contextmanager
    def connection(self):
        conn = self._get_conn()
        yield conn

    def migrate(self):
        with self.connection() as conn:
            v = conn.execute("PRAGMA user_version;").fetchone()[0]
            if v < 1:
                conn.executescript(SCHEMA_V1)
                conn.execute("PRAGMA user_version=1;")
                conn.commit()

    def close_thread_connection(self):
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # ----------------------------
    # CRUD для vault_entries
    # ----------------------------

    def get_all_entries(self):
        with self.connection() as conn:
            rows = conn.execute("""
                SELECT id, title, username, encrypted_password, url, notes, created_at, updated_at, tags
                FROM vault_entries
                ORDER BY id DESC
            """).fetchall()

        result = []
        for row in rows:
            result.append({
                "id": row["id"],
                "title": row["title"] or "",
                "username": row["username"] or "",
                "password": self._decode_blob(row["encrypted_password"]),
                "url": row["url"] or "",
                "notes": self._decode_blob(row["notes"]),
                "created_at": row["created_at"] or "",
                "updated_at": row["updated_at"] or "",
                "tags": row["tags"] or "",
            })
        return result

    def add_entry(self, title: str, username: str, password: str, url: str, notes: str, tags: str = "") -> int:
        now = datetime.now().isoformat(sep=" ", timespec="seconds")

        with self.connection() as conn:
            cursor = conn.execute("""
                INSERT INTO vault_entries (
                    title, username, encrypted_password, url, notes, created_at, updated_at, tags
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                title,
                username,
                self._encode_blob(password),
                url,
                self._encode_blob(notes),
                now,
                now,
                tags
            ))
            conn.commit()
            return cursor.lastrowid

    def update_entry(self, entry_id: int, title: str, username: str, password: str, url: str, notes: str, tags: str = ""):
        now = datetime.now().isoformat(sep=" ", timespec="seconds")

        with self.connection() as conn:
            conn.execute("""
                UPDATE vault_entries
                SET
                    title = ?,
                    username = ?,
                    encrypted_password = ?,
                    url = ?,
                    notes = ?,
                    updated_at = ?,
                    tags = ?
                WHERE id = ?
            """, (
                title,
                username,
                self._encode_blob(password),
                url,
                self._encode_blob(notes),
                now,
                tags,
                entry_id
            ))
            conn.commit()

    def delete_entry(self, entry_id: int):
        with self.connection() as conn:
            conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
            conn.commit()

    @staticmethod
    def _encode_blob(value: str) -> bytes:
        return (value or "").encode("utf-8")

    @staticmethod
    def _decode_blob(value) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        return str(value)