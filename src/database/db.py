import sqlite3
import threading
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime, timezone

from .models import SCHEMA_V1, SCHEMA_V2


class Database:
    def __init__(self, db_path: str):
        self.db_path = str(Path(db_path))
        self._local = threading.local()

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
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

            # Создание схемы v1 для новой пустой БД
            if version < 1:
                conn.executescript(SCHEMA_V1)
                conn.execute("PRAGMA user_version = 1;")
                conn.commit()
                version = 1

            # Миграция с v1 на v2
            if version < 2:
                self._migrate_v1_to_v2(conn)
                conn.execute("PRAGMA user_version = 2;")
                conn.commit()

    def _migrate_v1_to_v2(self, conn: sqlite3.Connection):
        conn.executescript(SCHEMA_V2)

        now = datetime.now(timezone.utc).isoformat(timespec="seconds")

        # Проверяем, есть ли старая key_store
        old_table = conn.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type='table' AND name='key_store'
        """).fetchone()

        if old_table:
            rows = conn.execute("""
                SELECT id, key_type, salt, hash, params
                FROM key_store
            """).fetchall()

            for _, old_key_type, salt, hash_value, params in rows:
                if hash_value is not None:
                    conn.execute("""
                        INSERT INTO key_store_new (key_type, key_data, version, created_at)
                        VALUES (?, ?, ?, ?)
                    """, ("auth_hash", hash_value, 1, now))

                if salt is not None:
                    # если хочешь, можно точнее определить тип соли
                    migrated_type = "enc_salt" if old_key_type == "enc_salt" else "auth_salt"
                    conn.execute("""
                        INSERT INTO key_store_new (key_type, key_data, version, created_at)
                        VALUES (?, ?, ?, ?)
                    """, (migrated_type, salt, 1, now))

                if params is not None:
                    conn.execute("""
                        INSERT INTO key_store_new (key_type, key_data, version, created_at)
                        VALUES (?, ?, ?, ?)
                    """, ("params", params.encode("utf-8"), 1, now))

            conn.execute("DROP TABLE key_store")

        conn.execute("ALTER TABLE key_store_new RENAME TO key_store")

    def close_thread_connection(self):
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

