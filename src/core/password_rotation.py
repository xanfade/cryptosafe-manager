from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from src.core.crypto.authentication import validate_password_strength
from src.core.crypto.key_derivation import (
    Argon2Params,
    PBKDF2Params,
    derive_auth_hash,
    derive_encryption_key,
    verify_auth_hash,
    generate_salt,
)
from src.core.crypto.vault_crypto import encrypt_record, decrypt_record


@dataclass
class RotationProgress:
    phase: str
    current: int
    total: int
    percent: float
    message: str


class PasswordRotationService:
    def __init__(self, db, key_manager):
        self.db = db
        self.key_manager = key_manager
        self._pause_event = threading.Event()
        self._pause_event.set()
        self._cancel_requested = False

    def pause(self):
        self._pause_event.clear()

    def resume(self):
        self._pause_event.set()

    def cancel(self):
        self._cancel_requested = True
        self._pause_event.set()

    def _wait_if_paused(self):
        self._pause_event.wait()
        if self._cancel_requested:
            raise RuntimeError("Операция отменена пользователем")

    def _decrypt_or_legacy_plaintext(self, old_enc_key: bytes, value) -> str:
        """
        Поддержка двух форматов:
        1) нормальный XOR-шифротекст
        2) старые legacy-данные, сохранённые как обычные utf-8 bytes
        """
        if value is None:
            return ""

        if isinstance(value, str):
            return value

        if not isinstance(value, (bytes, bytearray)):
            return str(value)

        raw = bytes(value)
        if not raw:
            return ""

        # Сначала пробуем как нормальный шифротекст
        try:
            return decrypt_record(old_enc_key, raw)
        except UnicodeDecodeError:
            # Если это не шифротекст, пробуем как старые plain utf-8 bytes
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError(
                    "Обнаружены повреждённые или несовместимые данные в vault_entries. "
                    "Невозможно безопасно выполнить ротацию."
                )

    def rotate_password(
        self,
        current_password: str,
        new_password: str,
        progress_cb: Callable[[RotationProgress], None] | None = None,
    ) -> None:
        if current_password == new_password:
            raise ValueError("Новый пароль должен отличаться от текущего")

        validate_password_strength(new_password)

        bundle = self.key_manager.load_bundle()

        ok = verify_auth_hash(
            password=current_password,
            salt=bundle["auth_salt"],
            expected_hash=bundle["auth_hash"],
            params=bundle["argon2_params"],
        )
        if not ok:
            raise ValueError("Текущий пароль введён неверно")

        old_enc_key = derive_encryption_key(
            password=current_password,
            salt=bundle["enc_salt"],
            params=bundle["pbkdf2_params"],
        )

        new_argon2_params = Argon2Params()
        new_pbkdf2_params = PBKDF2Params()

        new_auth_salt = generate_salt(new_argon2_params.salt_len)
        new_enc_salt = generate_salt(new_pbkdf2_params.salt_len)

        new_auth_hash = derive_auth_hash(
            new_password,
            new_auth_salt,
            new_argon2_params,
        )
        new_enc_key = derive_encryption_key(
            password=new_password,
            salt=new_enc_salt,
            params=new_pbkdf2_params,
        )

        now = datetime.now(timezone.utc).isoformat(timespec="seconds")

        with self.db.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                rows = conn.execute(
                    """
                    SELECT id, encrypted_password, notes
                    FROM vault_entries
                    ORDER BY id
                    """
                ).fetchall()

                total = len(rows)

                if progress_cb:
                    progress_cb(
                        RotationProgress(
                            phase="scan",
                            current=0,
                            total=total,
                            percent=0.0,
                            message="Подготовка к перешифрованию",
                        )
                    )

                updated_rows = []

                for i, row in enumerate(rows, start=1):
                    self._wait_if_paused()

                    entry_id, encrypted_password, notes = row

                    plain_password = self._decrypt_or_legacy_plaintext(old_enc_key, encrypted_password)
                    plain_notes = self._decrypt_or_legacy_plaintext(old_enc_key, notes)

                    new_encrypted_password = encrypt_record(new_enc_key, plain_password) if plain_password else b""
                    new_encrypted_notes = encrypt_record(new_enc_key, plain_notes) if plain_notes else b""

                    updated_rows.append(
                        (
                            new_encrypted_password,
                            new_encrypted_notes,
                            entry_id,
                        )
                    )

                    if progress_cb:
                        percent = (i / total * 100.0) if total else 100.0
                        progress_cb(
                            RotationProgress(
                                phase="reencrypt",
                                current=i,
                                total=total,
                                percent=percent,
                                message=f"Перешифровано записей: {i}/{total}",
                            )
                        )

                conn.executemany(
                    """
                    UPDATE vault_entries
                    SET encrypted_password = ?, notes = ?
                    WHERE id = ?
                    """,
                    updated_rows,
                )

                next_version = self.key_manager.get_next_version(conn)

                key_rows = [
                    ("auth_hash", new_auth_hash, next_version, now),
                    ("auth_salt", new_auth_salt, next_version, now),
                    ("enc_salt", new_enc_salt, next_version, now),
                    ("argon2_params", new_argon2_params.to_json(), next_version, now),
                    ("pbkdf2_params", new_pbkdf2_params.to_json(), next_version, now),
                ]

                conn.executemany(
                    """
                    INSERT INTO key_store (key_type, key_data, version, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    key_rows,
                )

                conn.commit()

            except Exception:
                conn.rollback()
                raise

        self.key_manager.cache_encryption_key(new_enc_key)

        if progress_cb:
            progress_cb(
                RotationProgress(
                    phase="done",
                    current=1,
                    total=1,
                    percent=100.0,
                    message="Смена пароля завершена",
                )
            )