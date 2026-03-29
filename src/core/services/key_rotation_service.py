from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from src.core.crypto.authentication import validate_password_strength
from src.core.crypto.key_derivation import (
    Argon2Params,
    PBKDF2Params,
    derive_auth_hash,
    derive_encryption_key,
    generate_salt,
    verify_auth_hash,
)


ProgressCallback = Callable[[int, int, str], None]


@dataclass
class RotationResult:
    success: bool
    message: str
    rotated_entries: int = 0
    new_version: int = 1


class KeyRotationService:
    """
    Сервис смены мастер-пароля и ротации ключей.

    Важно:
    - работает атомарно через транзакцию;
    - при любой ошибке выполняется rollback;
    - поддерживает фоновой запуск, pause/resume и прогресс.
    """

    def __init__(self, db, key_manager):
        self.db = db
        self.key_manager = key_manager

        self._thread: Optional[threading.Thread] = None
        self._pause_event = threading.Event()
        self._pause_event.set()
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    def pause(self) -> None:
        self._pause_event.clear()

    def resume(self) -> None:
        self._pause_event.set()

    def change_master_password(
        self,
        current_password: str,
        new_password: str,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> RotationResult:
        """
        Синхронная смена пароля.
        Используется внутри фонового worker или напрямую в тестах.
        """
        validate_password_strength(new_password)

        bundle = self.key_manager.load_bundle()

        ok = verify_auth_hash(
            password=current_password,
            salt=bundle["auth_salt"],
            expected_hash=bundle["auth_hash"],
            params=bundle["argon2_params"],
        )
        if not ok:
            raise ValueError("Текущий мастер-пароль неверный")

        old_key = derive_encryption_key(
            password=current_password,
            salt=bundle["enc_salt"],
            params=bundle["pbkdf2_params"],
        )

        new_argon2 = Argon2Params()
        new_pbkdf2 = PBKDF2Params()

        new_auth_salt = generate_salt(new_argon2.salt_len)
        new_enc_salt = generate_salt(new_pbkdf2.salt_len)

        new_auth_hash = derive_auth_hash(new_password, new_auth_salt, new_argon2)
        new_key = derive_encryption_key(new_password, new_enc_salt, new_pbkdf2)

        current_version = self._get_current_version()
        new_version = current_version + 1

        with self.db.connection() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")

                rows = conn.execute(
                    """
                    SELECT id, encrypted_password, notes
                    FROM vault_entries
                    ORDER BY id
                    """
                ).fetchall()

                total = len(rows)
                if progress_callback:
                    progress_callback(0, total, "Подготовка к перешифрованию")

                rotated = 0
                for index, row in enumerate(rows, start=1):
                    self._pause_event.wait()

                    entry_id = row[0]
                    encrypted_password = row[1]
                    encrypted_notes = row[2]

                    decrypted_password = self._xor(encrypted_password, old_key)
                    reencrypted_password = self._xor(decrypted_password, new_key)

                    reencrypted_notes = None
                    if encrypted_notes:
                        decrypted_notes = self._xor(encrypted_notes, old_key)
                        reencrypted_notes = self._xor(decrypted_notes, new_key)

                    conn.execute(
                        """
                        UPDATE vault_entries
                        SET encrypted_password = ?, notes = ?
                        WHERE id = ?
                        """,
                        (reencrypted_password, reencrypted_notes, entry_id),
                    )

                    rotated += 1
                    if progress_callback:
                        progress_callback(index, total, f"Перешифровано записей: {index}/{total}")

                now = datetime.now(timezone.utc).isoformat(timespec="seconds")

                conn.execute(
                    """
                    INSERT INTO key_store(key_type, key_data, version, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    ("auth_hash", new_auth_hash, new_version, now),
                )
                conn.execute(
                    """
                    INSERT INTO key_store(key_type, key_data, version, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    ("auth_salt", new_auth_salt, new_version, now),
                )
                conn.execute(
                    """
                    INSERT INTO key_store(key_type, key_data, version, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    ("enc_salt", new_enc_salt, new_version, now),
                )
                conn.execute(
                    """
                    INSERT INTO key_store(key_type, key_data, version, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    ("argon2_params", new_argon2.to_json(), new_version, now),
                )
                conn.execute(
                    """
                    INSERT INTO key_store(key_type, key_data, version, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    ("pbkdf2_params", new_pbkdf2.to_json(), new_version, now),
                )

                conn.commit()

            except Exception:
                conn.rollback()
                raise

        self.key_manager.clear_cache()
        self.key_manager.cache_encryption_key(new_key)

        if progress_callback:
            progress_callback(len(rows), len(rows), "Смена мастер-пароля завершена")

        return RotationResult(
            success=True,
            message="Мастер-пароль успешно изменён",
            rotated_entries=len(rows),
            new_version=new_version,
        )

    def start_background_rotation(
        self,
        current_password: str,
        new_password: str,
        progress_callback: Optional[ProgressCallback] = None,
        done_callback: Optional[Callable[[RotationResult | Exception], None]] = None,
    ) -> None:
        if self._running:
            raise RuntimeError("Ротация уже выполняется")

        self._running = True
        self._pause_event.set()

        def worker():
            try:
                result = self.change_master_password(
                    current_password=current_password,
                    new_password=new_password,
                    progress_callback=progress_callback,
                )
                if done_callback:
                    done_callback(result)
            except Exception as exc:
                if done_callback:
                    done_callback(exc)
            finally:
                self._running = False

        self._thread = threading.Thread(target=worker, daemon=True)
        self._thread.start()

    def _get_current_version(self) -> int:
        with self.db.connection() as conn:
            row = conn.execute(
                """
                SELECT COALESCE(MAX(version), 0)
                FROM key_store
                """
            ).fetchone()
        return int(row[0] or 0)

    @staticmethod
    def _xor(data: bytes, key: bytes) -> bytes:
        if not data:
            return data
        k = key * (len(data) // len(key) + 1)
        return bytes(b ^ k[i] for i, b in enumerate(data))