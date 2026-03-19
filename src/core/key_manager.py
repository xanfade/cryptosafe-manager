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
    def __init__(self, db: Database, cache_ttl_sec: int = 3600):
        self.db = db
        self.cache = SecureKeyCache(ttl_seconds=cache_ttl_sec)

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

    def initialize_master_password(self, password: str) -> None:
        argon2_params = Argon2Params()
        pbkdf2_params = PBKDF2Params()

        auth_salt = generate_salt(argon2_params.salt_len)
        enc_salt = generate_salt(pbkdf2_params.salt_len)
        auth_hash = derive_auth_hash(password, auth_salt, argon2_params)

        self._insert_key_record("auth_hash", auth_hash, 1)
        self._insert_key_record("auth_salt", auth_salt, 1)
        self._insert_key_record("enc_salt", enc_salt, 1)
        self._insert_key_record("argon2_params", argon2_params.to_json(), 1)
        self._insert_key_record("pbkdf2_params", pbkdf2_params.to_json(), 1)

    def is_initialized(self) -> bool:
        return self._get_latest_key_record("auth_hash") is not None

    def load_bundle(self) -> dict:
        auth_hash = self._get_latest_key_record("auth_hash")
        auth_salt = self._get_latest_key_record("auth_salt")
        enc_salt = self._get_latest_key_record("enc_salt")
        argon2_params = self._get_latest_key_record("argon2_params")
        pbkdf2_params = self._get_latest_key_record("pbkdf2_params")

        if not all([auth_hash, auth_salt, enc_salt, argon2_params, pbkdf2_params]):
            raise RuntimeError("Хранилище ключей не инициализировано полностью")

        return {
            "auth_hash": auth_hash[0],
            "auth_salt": auth_salt[0],
            "enc_salt": enc_salt[0],
            "argon2_params": Argon2Params.from_json(argon2_params[0]),
            "pbkdf2_params": PBKDF2Params.from_json(pbkdf2_params[0]),
        }

    def cache_encryption_key(self, key: bytes) -> None:
        self.cache.put(key)

    def get_encryption_key(self) -> bytes | None:
        return self.cache.get()

    def touch_cache(self) -> None:
        self.cache.touch()

    def clear_cache(self) -> None:
        self.cache.clear()
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