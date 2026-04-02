from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultEncryptionService:
    NONCE_SIZE = 12
    CURRENT_VERSION = 1

    def __init__(self, key_manager):
        self.key_manager = key_manager

    def _require_key(self) -> bytes:
        key = self.key_manager.get_encryption_key()
        if not key:
            raise ValueError("Хранилище заблокировано. Сначала выполните вход.")
        if len(key) != 32:
            raise ValueError("Ключ шифрования должен быть длиной 32 байта для AES-256-GCM.")
        return key

    def _build_payload(
        self,
        title: str,
        username: str,
        password: str,
        url: str,
        notes: str,
        created_at: str | None = None,
    ) -> bytes:
        payload = {
            "version": self.CURRENT_VERSION,
            "created_at": created_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def encrypt_entry(
        self,
        *,
        title: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
        created_at: str | None = None,
    ) -> bytes:
        key = self._require_key()
        nonce = os.urandom(self.NONCE_SIZE)
        plaintext = self._build_payload(
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
            created_at=created_at,
        )
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt_entry(self, encrypted: bytes) -> dict:
        key = self._require_key()

        if not encrypted or len(encrypted) <= self.NONCE_SIZE:
            raise ValueError("Некорректные зашифрованные данные.")

        nonce = encrypted[:self.NONCE_SIZE]
        ciphertext = encrypted[self.NONCE_SIZE:]

        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise ValueError("Проверка целостности не пройдена. Данные были изменены или ключ неверный.") from exc

        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Не удалось разобрать расшифрованный JSON-пакет.") from exc

        required_fields = {
            "version",
            "created_at",
            "title",
            "username",
            "password",
            "url",
            "notes",
        }
        missing = required_fields - payload.keys()
        if missing:
            raise ValueError(f"В зашифрованном пакете отсутствуют поля: {', '.join(sorted(missing))}")

        return payload