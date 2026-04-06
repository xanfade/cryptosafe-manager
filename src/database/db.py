from __future__ import annotations

import queue
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .models import SCHEMA_V1, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4


class SQLiteConnectionPool:
    def __init__(self, db_path: str, max_size: int = 4):
        self.db_path = str(Path(db_path))
        self.max_size = max(1, max_size)
        self._pool: queue.Queue[sqlite3.Connection] = queue.Queue(maxsize=self.max_size)
        self._created = 0
        self._lock = threading.Lock()

    def _create_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def acquire(self, timeout: float | None = None) -> sqlite3.Connection:
        try:
            return self._pool.get_nowait()
        except queue.Empty:
            pass

        with self._lock:
            if self._created < self.max_size:
                conn = self._create_connection()
                self._created += 1
                return conn

        return self._pool.get(timeout=timeout)

    def release(self, conn: sqlite3.Connection):
        if conn is None:
            return

        try:
            self._pool.put_nowait(conn)
        except queue.Full:
            try:
                conn.close()
            finally:
                with self._lock:
                    self._created = max(0, self._created - 1)

    def close_all(self):
        while True:
            try:
                conn = self._pool.get_nowait()
            except queue.Empty:
                break
            try:
                conn.close()
            except Exception:
                pass

        with self._lock:
            self._created = 0


class Database:
    def __init__(self, db_path: str, pool_size: int = 4):
        self.db_path = str(Path(db_path))
        self._pool = SQLiteConnectionPool(self.db_path, max_size=pool_size)

    @contextmanager
    def connection(self):
        conn = self._pool.acquire(timeout=10)
        try:
            yield conn
        finally:
            self._pool.release(conn)

    def migrate(self):
        with self.connection() as conn:
            version = conn.execute("PRAGMA user_version;").fetchone()[0]

            if version < 1:
                self._apply_v1(conn)
                version = 1

            if version < 2:
                self._migrate_v1_to_v2(conn)
                version = 2

            if version < 3:
                self._migrate_v2_to_v3(conn)
                version = 3

            if version < 4:
                self._migrate_v3_to_v4(conn)
                version = 4

    def _apply_v1(self, conn: sqlite3.Connection):
        conn.executescript(SCHEMA_V1)
        conn.execute("PRAGMA user_version = 1;")
        conn.commit()

    def _migrate_v1_to_v2(self, conn: sqlite3.Connection):
        """
        Приводит key_store к новой схеме:
        id, key_type, key_data, version, created_at

        Поддерживает:
        1) уже новую схему key_store
        2) старую схему с полями salt/hash/params
        3) отсутствие key_store вообще
        """
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")

        old_exists = conn.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type='table' AND name='key_store'
            """
        ).fetchone()

        conn.executescript(SCHEMA_V2)

        if old_exists:
            columns_info = conn.execute("PRAGMA table_info(key_store)").fetchall()
            old_columns = {row["name"] for row in columns_info}
            rows = conn.execute("SELECT * FROM key_store").fetchall()

            if {"key_type", "key_data", "version", "created_at"}.issubset(old_columns):
                for row in rows:
                    conn.execute(
                        """
                        INSERT INTO key_store_new (key_type, key_data, version, created_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            row["key_type"],
                            row["key_data"],
                            row["version"] if row["version"] is not None else 1,
                            row["created_at"] or now,
                        ),
                    )
            else:
                for row in rows:
                    row_keys = set(row.keys())

                    old_key_type = row["key_type"] if "key_type" in row_keys else "master"
                    salt = row["salt"] if "salt" in row_keys else None
                    hash_value = row["hash"] if "hash" in row_keys else None
                    params = row["params"] if "params" in row_keys else None

                    if hash_value is not None:
                        conn.execute(
                            """
                            INSERT INTO key_store_new (key_type, key_data, version, created_at)
                            VALUES (?, ?, ?, ?)
                            """,
                            ("auth_hash", hash_value, 1, now),
                        )

                    if salt is not None:
                        migrated_type = "enc_salt" if old_key_type == "enc_salt" else "auth_salt"
                        conn.execute(
                            """
                            INSERT INTO key_store_new (key_type, key_data, version, created_at)
                            VALUES (?, ?, ?, ?)
                            """,
                            (migrated_type, salt, 1, now),
                        )

                    if params is not None:
                        if isinstance(params, bytes):
                            key_data = params
                        elif isinstance(params, str):
                            key_data = params.encode("utf-8")
                        else:
                            key_data = str(params).encode("utf-8")

                        conn.execute(
                            """
                            INSERT INTO key_store_new (key_type, key_data, version, created_at)
                            VALUES (?, ?, ?, ?)
                            """,
                            ("params", key_data, 1, now),
                        )

            conn.execute("DROP TABLE key_store")
            conn.execute("ALTER TABLE key_store_new RENAME TO key_store")

        conn.execute("PRAGMA user_version = 2;")
        conn.commit()

    def _migrate_v2_to_v3(self, conn: sqlite3.Connection):
        """
        Версия 3 не меняет key_store,
        но должна проходить отдельным шагом.
        Это важно, чтобы миграции были последовательными и расширяемыми.
        """
        conn.executescript(SCHEMA_V3)
        conn.execute("PRAGMA user_version = 3;")
        conn.commit()

    def _migrate_v3_to_v4(self, conn: sqlite3.Connection):
        """
        Переводит vault_entries на encrypted_data без потери записей.
        Если таблица уже новая — просто применяет схему.
        """
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")

        columns_info = conn.execute("PRAGMA table_info(vault_entries)").fetchall()
        old_columns = {row["name"] for row in columns_info}

        if {"encrypted_data", "created_at", "updated_at", "tags"}.issubset(old_columns):
            conn.executescript(SCHEMA_V4)
            conn.execute("PRAGMA user_version = 4;")
            conn.commit()
            return

        conn.executescript(SCHEMA_V4)

        if {"encrypted_password", "created_at", "updated_at", "tags"}.issubset(old_columns):
            rows = conn.execute(
                """
                SELECT id, encrypted_password, created_at, updated_at, tags
                FROM vault_entries
                """
            ).fetchall()

            for row in rows:
                conn.execute(
                    """
                    INSERT INTO vault_entries_new (id, encrypted_data, created_at, updated_at, tags)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        row["id"],
                        row["encrypted_password"],
                        row["created_at"] or now,
                        row["updated_at"] or now,
                        row["tags"],
                    ),
                )

            conn.execute("DROP TABLE vault_entries")
            conn.execute("ALTER TABLE vault_entries_new RENAME TO vault_entries")

        conn.execute("PRAGMA user_version = 4;")
        conn.commit()

    def close_thread_connection(self):
        # Оставлено для совместимости со старым кодом.
        # Теперь соединения управляются пулом.
        pass

    def close(self):
        self._pool.close_all()

    def get_setting(self, key: str, default=None):
        with self.connection() as conn:
            row = conn.execute(
                "SELECT setting_value FROM settings WHERE setting_key = ?",
                (key,),
            ).fetchone()
            if row is None:
                return default
            return row["setting_value"]

    def set_setting(self, key: str, value: str, encrypted: int = 0):
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO settings(setting_key, setting_value, encrypted)
                VALUES (?, ?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET
                    setting_value = excluded.setting_value,
                    encrypted = excluded.encrypted
                """,
                (key, value, encrypted),
            )
            conn.commit()