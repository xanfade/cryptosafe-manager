from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.crypto.authentication import validate_password_strength
from src.core.crypto.key_derivation import (
    Argon2Params,
    PBKDF2Params,
    derive_auth_hash,
    derive_encryption_key,
    generate_salt,
    verify_auth_hash,
)


@dataclass
class RotationProgress:
    phase: str
    current: int
    total: int
    percent: float
    message: str


class PasswordRotationService:
    NONCE_SIZE = 12

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

    def _emit_progress(
        self,
        progress_cb: Callable[[RotationProgress], None] | None,
        phase: str,
        current: int,
        total: int,
        message: str,
    ) -> None:
        if progress_cb is None:
            return

        percent = 100.0 if total == 0 else (current / total) * 100.0
        progress_cb(
            RotationProgress(
                phase=phase,
                current=current,
                total=total,
                percent=percent,
                message=message,
            )
        )

    def _ensure_v4_schema(self, conn) -> None:
        columns_info = conn.execute("PRAGMA table_info(vault_entries)").fetchall()
        column_names = {row["name"] for row in columns_info}

        required = {"id", "encrypted_data", "created_at", "updated_at", "tags"}
        missing = required - column_names
        if missing:
            raise ValueError(
                "Текущая схема vault_entries не поддерживает ротацию пароля. "
                f"Отсутствуют поля: {', '.join(sorted(missing))}"
            )

    def _normalize_payload(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ValueError("Расшифрованные данные записи должны быть словарем.")

        normalized = {
            "title": payload.get("title", "") or "",
            "username": payload.get("username", "") or "",
            "password": payload.get("password", "") or "",
            "url": payload.get("url", "") or "",
            "notes": payload.get("notes", "") or "",
            "created_at": payload.get("created_at", "") or "",
            "version": payload.get("version", 1),
        }

        required = ["title", "username", "password", "version"]
        missing = [field for field in required if normalized.get(field, "") == ""]
        if missing:
            raise ValueError(
                "В payload отсутствуют обязательные поля: "
                + ", ".join(missing)
            )

        return normalized

    def _decrypt_entry_payload_with_key(self, encrypted_data: bytes, key: bytes) -> dict:
        if not encrypted_data or len(encrypted_data) <= self.NONCE_SIZE:
            raise ValueError("Некорректные зашифрованные данные записи.")

        nonce = encrypted_data[:self.NONCE_SIZE]
        ciphertext = encrypted_data[self.NONCE_SIZE:]

        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise ValueError(
                "Не удалось расшифровать запись старым ключом. "
                "Данные повреждены или текущий пароль неверный."
            ) from exc

        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                "Расшифрованные данные записи имеют некорректный формат."
            ) from exc

        return self._normalize_payload(payload)

    def _encrypt_entry_payload_with_key(self, payload: dict, key: bytes) -> bytes:
        normalized = self._normalize_payload(payload)

        plaintext = json.dumps(
            normalized,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        nonce = os.urandom(self.NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def rotate_password(
        self,
        current_password: str,
        new_password: str,
        progress_cb: Callable[[RotationProgress], None] | None = None,
    ) -> None:
        self._cancel_requested = False

        if not current_password:
            raise ValueError("Введите текущий пароль")
        if not new_password:
            raise ValueError("Введите новый пароль")
        if current_password == new_password:
            raise ValueError("Новый пароль должен отличаться от текущего")

        validate_password_strength(new_password)

        bundle = self.key_manager.load_bundle()

        is_valid = verify_auth_hash(
            password=current_password,
            salt=bundle["auth_salt"],
            expected_hash=bundle["auth_hash"],
            params=bundle["argon2_params"],
        )
        if not is_valid:
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
            self._ensure_v4_schema(conn)

            conn.execute("BEGIN IMMEDIATE")
            try:
                rows = conn.execute(
                    """
                    SELECT id, encrypted_data
                    FROM vault_entries
                    ORDER BY id
                    """
                ).fetchall()

                total = len(rows)
                self._emit_progress(
                    progress_cb,
                    phase="scan",
                    current=0,
                    total=total,
                    message="Подготовка к перешифрованию",
                )

                updated_rows: list[tuple[bytes, str, int]] = []

                for i, row in enumerate(rows, start=1):
                    self._wait_if_paused()

                    entry_id = row["id"]
                    encrypted_data = row["encrypted_data"]

                    payload = self._decrypt_entry_payload_with_key(
                        encrypted_data=encrypted_data,
                        key=old_enc_key,
                    )
                    reencrypted_data = self._encrypt_entry_payload_with_key(
                        payload=payload,
                        key=new_enc_key,
                    )

                    updated_rows.append((reencrypted_data, now, entry_id))

                    self._emit_progress(
                        progress_cb,
                        phase="reencrypt",
                        current=i,
                        total=total,
                        message=f"Перешифровано записей: {i}/{total}",
                    )

                if updated_rows:
                    conn.executemany(
                        """
                        UPDATE vault_entries
                        SET encrypted_data = ?, updated_at = ?
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

        self._emit_progress(
            progress_cb,
            phase="done",
            current=1,
            total=1,
            message="Смена пароля завершена",
        )