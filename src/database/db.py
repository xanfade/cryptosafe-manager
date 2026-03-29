import sqlite3
import threading
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime, timezone

from .models import SCHEMA_V1, SCHEMA_V2, SCHEMA_V3


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
            version = conn.execute("PRAGMA user_version;").fetchone()[0]

            if version < 1:
                conn.executescript(SCHEMA_V1)
                conn.execute("PRAGMA user_version = 1;")
                conn.commit()
                version = 1

            if version < 2:
                self._migrate_v1_to_v2(conn)
                conn.execute("PRAGMA user_version = 2;")
                conn.commit()
                version = 2

            if version < 3:
                self._migrate_v2_to_v3(conn)
                conn.execute("PRAGMA user_version = 3;")
                conn.commit()

    def _migrate_v1_to_v2(self, conn: sqlite3.Connection):
        conn.executescript(SCHEMA_V2)

        now = datetime.now(timezone.utc).isoformat(timespec="seconds")

        old_table = conn.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type='table' AND name='key_store'
        """).fetchone()

        if old_table:
            columns_info = conn.execute("PRAGMA table_info(key_store)").fetchall()
            columns = {row["name"] for row in columns_info}
            rows = conn.execute("SELECT * FROM key_store").fetchall()

            if {"key_type", "key_data", "version", "created_at"}.issubset(columns):
                for row in rows:
                    conn.execute("""
                        INSERT INTO key_store_new (key_type, key_data, version, created_at)
                        VALUES (?, ?, ?, ?)
                    """, (
                        row["key_type"],
                        row["key_data"],
                        row["version"] if row["version"] is not None else 1,
                        row["created_at"] if row["created_at"] else now,
                    ))
            else:
                for row in rows:
                    row_keys = set(row.keys())
                    old_key_type = row["key_type"] if "key_type" in row_keys else "master"
                    salt = row["salt"] if "salt" in row_keys else None
                    hash_value = row["hash"] if "hash" in row_keys else None
                    params = row["params"] if "params" in row_keys else None

                    if hash_value is not None:
                        conn.execute("""
                            INSERT INTO key_store_new (key_type, key_data, version, created_at)
                            VALUES (?, ?, ?, ?)
                        """, ("auth_hash", hash_value, 1, now))

                    if salt is not None:
                        migrated_type = "enc_salt" if old_key_type == "enc_salt" else "auth_salt"
                        conn.execute("""
                            INSERT INTO key_store_new (key_type, key_data, version, created_at)
                            VALUES (?, ?, ?, ?)
                        """, (migrated_type, salt, 1, now))

                    if params is not None:
                        if isinstance(params, bytes):
                            key_data = params
                        elif isinstance(params, str):
                            key_data = params.encode("utf-8")
                        else:
                            key_data = str(params).encode("utf-8")

                        conn.execute("""
                            INSERT INTO key_store_new (key_type, key_data, version, created_at)
                            VALUES (?, ?, ?, ?)
                        """, ("params", key_data, 1, now))

            conn.execute("DROP TABLE key_store")
            conn.execute("ALTER TABLE key_store_new RENAME TO key_store")

    def _migrate_v2_to_v3(self, conn: sqlite3.Connection):
        conn.executescript(SCHEMA_V3)

    def close_thread_connection(self):
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def get_setting(self, key: str, default=None):
        with self.connection() as conn:
            row = conn.execute(
                "SELECT setting_value FROM settings WHERE setting_key = ?",
                (key,)
            ).fetchone()
            if row is None:
                return default
            return row["setting_value"]

    def set_setting(self, key: str, value: str, encrypted: int = 0):
        with self.connection() as conn:
            conn.execute("""
                INSERT INTO settings(setting_key, setting_value, encrypted)
                VALUES (?, ?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET
                    setting_value = excluded.setting_value,
                    encrypted = excluded.encrypted
            """, (key, value, encrypted))
            conn.commit()

    def get_all_entries(self):
        with self.connection() as conn:
            rows = conn.execute("""
                SELECT id, title, username, encrypted_password, url, notes,
                       created_at, updated_at, tags
                FROM vault_entries
                ORDER BY id DESC
            """).fetchall()

            result = []
            for row in rows:
                result.append({
                    "id": row["id"],
                    "title": row["title"] or "",
                    "username": row["username"] or "",
                    "password": self._decode_value(row["encrypted_password"]),
                    "url": row["url"] or "",
                    "notes": self._decode_value(row["notes"]),
                    "created_at": row["created_at"] or "",
                    "updated_at": row["updated_at"] or "",
                    "tags": row["tags"] or "",
                })
            return result

    def add_entry(self, title: str, username: str, password: str, url: str, notes: str, tags: str = "") -> int:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.connection() as conn:
            cursor = conn.execute("""
                INSERT INTO vault_entries (
                    title, username, encrypted_password, url, notes,
                    created_at, updated_at, tags
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                title,
                username,
                self._encode_value(password),
                url,
                self._encode_value(notes),
                now,
                now,
                tags
            ))
            conn.commit()
            return cursor.lastrowid

    def update_entry(self, entry_id: int, title: str, username: str, password: str, url: str, notes: str, tags: str = ""):
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.connection() as conn:
            conn.execute("""
                UPDATE vault_entries
                SET title = ?, username = ?, encrypted_password = ?, url = ?,
                    notes = ?, updated_at = ?, tags = ?
                WHERE id = ?
            """, (
                title,
                username,
                self._encode_value(password),
                url,
                self._encode_value(notes),
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
    def _encode_value(value: str) -> bytes:
        return (value or "").encode("utf-8")

    @staticmethod
    def _decode_value(value) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        return str(value)