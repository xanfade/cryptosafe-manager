from __future__ import annotations

import json
import os
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.crypto.abstract import EncryptionService
from src.core.security.memory_guard import MemoryGuard
from src.core.security.side_channel_protection import normalize_timing


class VaultEncryptionService(EncryptionService):
    NONCE_SIZE = 12
    PAYLOAD_VERSION = 1
    MIN_CRYPTO_DELAY_SEC = 0.001

    def __init__(self, key_manager, memory_guard: MemoryGuard | None = None):
        super().__init__(key_manager)
        self.memory_guard = memory_guard or MemoryGuard()

    def encrypt(self, data: bytes) -> bytes:
        started_at = time.perf_counter()
        key = self._require_key()

        if not isinstance(data, (bytes, bytearray)):
            raise ValueError("Для шифрования ожидаются байты.")

        try:
            nonce = os.urandom(self.NONCE_SIZE)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, bytes(data), None)
            return nonce + ciphertext
        finally:
            normalize_timing(started_at, self.MIN_CRYPTO_DELAY_SEC)

    def decrypt(self, ciphertext: bytes) -> bytes:
        started_at = time.perf_counter()
        key = self._require_key()

        if not ciphertext or len(ciphertext) <= self.NONCE_SIZE:
            raise ValueError("Некорректные зашифрованные данные.")

        nonce = ciphertext[:self.NONCE_SIZE]
        encrypted_payload = ciphertext[self.NONCE_SIZE:]

        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, encrypted_payload, None)
        except InvalidTag as exc:
            raise ValueError(
                "Проверка целостности не пройдена. Данные повреждены или ключ неверный."
            ) from exc
        finally:
            normalize_timing(started_at, self.MIN_CRYPTO_DELAY_SEC)

    def _normalize_payload(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ValueError("Payload должен быть словарем.")

        normalized = {
            "title": payload.get("title", "") or "",
            "username": payload.get("username", "") or "",
            "password": payload.get("password", "") or "",
            "url": payload.get("url", "") or "",
            "notes": payload.get("notes", "") or "",
            "category": payload.get("category", "") or "",
            "created_at": payload.get("created_at", "") or "",
            "version": payload.get("version", self.PAYLOAD_VERSION),
        }

        required = ["title", "username", "password", "version"]
        missing = [field for field in required if normalized.get(field, "") == ""]

        if missing:
            raise ValueError(f"В payload отсутствуют обязательные поля: {', '.join(missing)}")

        return normalized

    def encrypt_entry_payload(self, payload: dict) -> bytes:
        normalized = self._normalize_payload(payload)
        plaintext = json.dumps(
            normalized,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        with self.memory_guard.scoped_buffer(plaintext, critical=True) as buf:
            return self.encrypt(buf.to_bytes())

    def decrypt_entry_payload(self, encrypted_data: bytes) -> dict:
        plaintext = self.decrypt(encrypted_data)
        with self.memory_guard.scoped_buffer(plaintext, critical=True) as buf:
            plaintext = buf.to_bytes()

        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Не удалось разобрать расшифрованный payload.") from exc

        payload.setdefault("url", "")
        payload.setdefault("notes", "")
        payload.setdefault("category", "")
        payload.setdefault("created_at", "")
        payload.setdefault("version", 1)

        required_fields = {
            "title",
            "username",
            "password",
            "url",
            "notes",
            "category",
            "created_at",
            "version",
        }
        missing = required_fields - payload.keys()
        if missing:
            raise ValueError(f"В расшифрованном payload отсутствуют поля: {', '.join(sorted(missing))}")

        return payload
