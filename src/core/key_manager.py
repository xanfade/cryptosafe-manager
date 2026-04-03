from __future__ import annotations
from datetime import datetime, timezone

from src.core.crypto.key_derivation import (
    Argon2Params,
    PBKDF2Params,
    generate_salt,
    derive_auth_hash,
)
from src.core.crypto.key_storage import SecureKeyCache
from src.database.db import Database


class KeyManager:
    REQUIRED_KEY_TYPES = {
        "auth_hash",
        "auth_salt",
        "enc_salt",
        "argon2_params",
        "pbkdf2_params",
    }

    def __init__(
        self,
        db: Database,
        cache_ttl_sec: int = 3600,
        clear_on_focus_loss: bool = True,
        clear_on_minimize: bool = True,
    ):
        self.db = db
        self.cache = SecureKeyCache(
            ttl_seconds=cache_ttl_sec,
            clear_on_focus_loss=clear_on_focus_loss,
            clear_on_minimize=clear_on_minimize,
        )

    def _insert_key_record(self, key_type: str, key_data: bytes, version: int = 1) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO key_store(key_type, key_data, version, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (key_type, key_data, version, now),
            )
            conn.commit()

    def _get_latest_key_record(self, key_type: str):
        with self.db.connection() as conn:
            row = conn.execute(
                """
                SELECT key_data, version, created_at
                FROM key_store
                WHERE key_type = ?
                ORDER BY version DESC, id DESC
                LIMIT 1
                """,
                (key_type,),
            ).fetchone()
        return row

    def _insert_key_bundle(self, bundle: dict[str, bytes], version: int) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")

        with self.db.connection() as conn:
            for key_type, key_data in bundle.items():
                conn.execute(
                    """
                    INSERT INTO key_store(key_type, key_data, version, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (key_type, key_data, version, now),
                )
            conn.commit()

    def _get_latest_complete_version(self, conn) -> int | None:
        rows = conn.execute(
            """
            SELECT version, COUNT(DISTINCT key_type) AS cnt
            FROM key_store
            WHERE key_type IN ('auth_hash', 'auth_salt', 'enc_salt', 'argon2_params', 'pbkdf2_params')
            GROUP BY version
            HAVING cnt = 5
            ORDER BY version DESC
            LIMIT 1
            """
        ).fetchone()

        if rows is None:
            return None

        return int(rows["version"])

    def _load_bundle_by_version(self, version: int) -> dict:
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT key_type, key_data
                FROM key_store
                WHERE version = ?
                """,
                (version,),
            ).fetchall()

        bundle = {row["key_type"]: row["key_data"] for row in rows}

        missing = self.REQUIRED_KEY_TYPES - set(bundle.keys())
        if missing:
            raise RuntimeError(
                f"Версия key bundle {version} неполная. Отсутствуют: {', '.join(sorted(missing))}"
            )

        return {
            "auth_hash": bundle["auth_hash"],
            "auth_salt": bundle["auth_salt"],
            "enc_salt": bundle["enc_salt"],
            "argon2_params": Argon2Params.from_json(bundle["argon2_params"]),
            "pbkdf2_params": PBKDF2Params.from_json(bundle["pbkdf2_params"]),
            "version": version,
        }

    def initialize_master_password(self, password: str) -> None:
        argon2_params = Argon2Params()
        pbkdf2_params = PBKDF2Params()

        auth_salt = generate_salt(argon2_params.salt_len)
        enc_salt = generate_salt(pbkdf2_params.salt_len)
        auth_hash = derive_auth_hash(password, auth_salt, argon2_params)

        bundle = {
            "auth_hash": auth_hash,
            "auth_salt": auth_salt,
            "enc_salt": enc_salt,
            "argon2_params": argon2_params.to_json(),
            "pbkdf2_params": pbkdf2_params.to_json(),
        }

        with self.db.connection() as conn:
            version = self.get_next_version(conn)
            for key_type, key_data in bundle.items():
                conn.execute(
                    """
                    INSERT INTO key_store(key_type, key_data, version, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        key_type,
                        key_data,
                        version,
                        datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    ),
                )
            conn.commit()

    def is_initialized(self) -> bool:
        with self.db.connection() as conn:
            return self._get_latest_complete_version(conn) is not None

    def load_bundle(self) -> dict:
        with self.db.connection() as conn:
            version = self._get_latest_complete_version(conn)

        if version is None:
            raise RuntimeError("Хранилище ключей не инициализировано полностью")

        return self._load_bundle_by_version(version)

    def cache_encryption_key(self, key: bytes) -> None:
        self.cache.put(key)

    def get_encryption_key(self) -> bytes | None:
        return self.cache.get()

    def has_cached_key(self) -> bool:
        return self.cache.has_key()

    def touch_cache(self) -> None:
        self.cache.touch()

    def clear_cache(self) -> None:
        self.cache.clear()

    def on_app_focus_lost(self) -> None:
        self.cache.on_app_focus_lost()

    def on_app_focus_gained(self) -> None:
        self.cache.on_app_focus_gained()

    def on_app_minimized(self) -> None:
        self.cache.on_app_minimized()

    def on_app_restored(self) -> None:
        self.cache.on_app_restored()

    def is_cache_expired(self) -> bool:
        return self.cache.is_expired()

    def get_next_version(self, conn=None) -> int:
        if conn is None:
            with self.db.connection() as local_conn:
                row = local_conn.execute(
                    "SELECT COALESCE(MAX(version), 0) FROM key_store"
                ).fetchone()
        else:
            row = conn.execute(
                "SELECT COALESCE(MAX(version), 0) FROM key_store"
            ).fetchone()

        return int(row[0]) + 1