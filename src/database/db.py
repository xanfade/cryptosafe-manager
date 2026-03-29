import sqlite3
import threading
import json
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime
from .models import SCHEMA_V1, SCHEMA_V2


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

            if v == 0:
                conn.executescript(SCHEMA_V1)
                conn.execute("PRAGMA user_version=2;")
                conn.commit()
                return

            if v == 1:
                self._migrate_key_store_to_v2(conn)
                conn.execute("PRAGMA user_version=2;")
                conn.commit()

    def _migrate_key_store_to_v2(self, conn: sqlite3.Connection) -> None:
        # создаём новую таблицу под нормализованный key_store
        conn.executescript(SCHEMA_V2)

        # пытаемся прочитать старую key_store
        old_rows = conn.execute("SELECT * FROM key_store ORDER BY id").fetchall()
        if not old_rows:
            conn.execute("DROP TABLE IF EXISTS key_store")
            conn.execute("ALTER TABLE key_store_new RENAME TO key_store")
            return

        # смотрим структуру старой таблицы
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(key_store)").fetchall()
        }

        # если таблица уже нового формата — просто копируем
        if {"key_type", "key_data", "version", "created_at"}.issubset(columns):
            conn.execute("""
                INSERT INTO key_store_new (key_type, key_data, version, created_at)
                SELECT key_type, key_data, version, created_at
                FROM key_store
            """)
        else:
            # ожидаем старый формат вида: key_type, salt, hash, params, created_at
            for row in old_rows:
                version = row["version"] if "version" in row.keys() and row["version"] else 1
                created_at = row["created_at"] if "created_at" in row.keys() and row["created_at"] else datetime.utcnow().isoformat(timespec="seconds")

                key_type = row["key_type"] if "key_type" in row.keys() else "master"

                salt = row["salt"] if "salt" in row.keys() else None
                hash_value = row["hash"] if "hash" in row.keys() else None
                params = row["params"] if "params" in row.keys() else None

                # auth_hash
                if hash_value is not None:
                    conn.execute(
                        """
                        INSERT INTO key_store_new(key_type, key_data, version, created_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        ("auth_hash", hash_value, version, created_at),
                    )

                # auth_salt / enc_salt
                if salt is not None:
                    conn.execute(
                        """
                        INSERT INTO key_store_new(key_type, key_data, version, created_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        ("auth_salt", salt, version, created_at),
                    )
                    conn.execute(
                        """
                        INSERT INTO key_store_new(key_type, key_data, version, created_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        ("enc_salt", salt, version, created_at),
                    )

                # params -> раскладываем отдельно
                if params:
                    try:
                        raw = params.decode("utf-8") if isinstance(params, bytes) else str(params)
                        parsed = json.loads(raw)

                        argon2_params = parsed.get("argon2") or parsed.get("argon2_params")
                        pbkdf2_params = parsed.get("pbkdf2") or parsed.get("pbkdf2_params")

                        if argon2_params is not None:
                            if not isinstance(argon2_params, str):
                                argon2_params = json.dumps(argon2_params)
                            conn.execute(
                                """
                                INSERT INTO key_store_new(key_type, key_data, version, created_at)
                                VALUES (?, ?, ?, ?)
                                """,
                                ("argon2_params", argon2_params.encode("utf-8"), version, created_at),
                            )

                        if pbkdf2_params is not None:
                            if not isinstance(pbkdf2_params, str):
                                pbkdf2_params = json.dumps(pbkdf2_params)
                            conn.execute(
                                """
                                INSERT INTO key_store_new(key_type, key_data, version, created_at)
                                VALUES (?, ?, ?, ?)
                                """,
                                ("pbkdf2_params", pbkdf2_params.encode("utf-8"), version, created_at),
                            )

                    except Exception:
                        # если старые params невозможно разобрать — лучше не падать на миграции
                        pass

        conn.execute("DROP TABLE IF EXISTS key_store")
        conn.execute("ALTER TABLE key_store_new RENAME TO key_store")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_keystore_type_version ON key_store(key_type, version)")