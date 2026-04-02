from __future__ import annotations

import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultEncryptionService:
    NONCE_SIZE = 12
    PAYLOAD_VERSION = 1

    def __init__(self, key_manager):
        self.key_manager = key_manager

    def _require_key(self) -> bytes:
        key = self.key_manager.get_encryption_key()
        if not key:
            raise ValueError("Хранилище заблокировано. Сначала выполните вход.")
        if len(key) != 32:
            raise ValueError("Ключ шифрования должен быть длиной 32 байта для AES-256-GCM.")
        return key

    def _normalize_payload(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ValueError("Payload должен быть словарем.")

        normalized = {
            "title": payload.get("title", "") or "",
            "username": payload.get("username", "") or "",
            "password": payload.get("password", "") or "",
            "url": payload.get("url", "") or "",
            "notes": payload.get("notes", "") or "",
            "category": payload.get("category", "Без категории") or "Без категории",
            "version": payload.get("version", self.PAYLOAD_VERSION),
        }

        required = ["title", "username", "password", "version"]
        missing = [field for field in required if normalized.get(field, "") == ""]
        if missing:
            raise ValueError(f"В payload отсутствуют обязательные поля: {', '.join(missing)}")

        return normalized

    def encrypt_entry_payload(self, payload: dict) -> bytes:
        key = self._require_key()
        normalized = self._normalize_payload(payload)

        plaintext = json.dumps(
            normalized,
            ensure_ascii=False,
            separators=(",", ":")
        ).encode("utf-8")

        nonce = os.urandom(self.NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        return nonce + ciphertext

    def decrypt_entry_payload(self, encrypted_data: bytes) -> dict:
        key = self._require_key()

        if not encrypted_data or len(encrypted_data) <= self.NONCE_SIZE:
            raise ValueError("Некорректные зашифрованные данные.")

        nonce = encrypted_data[:self.NONCE_SIZE]
        ciphertext = encrypted_data[self.NONCE_SIZE:]

        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise ValueError(
                "Проверка целостности не пройдена. Данные повреждены или ключ неверный."
            ) from exc

        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Не удалось разобрать расшифрованный payload.") from exc

        required_fields = {
            "title",
            "username",
            "password",
            "url",
            "notes",
            "category",
            "version",
        }
        missing = required_fields - payload.keys()
        if missing:
            raise ValueError(
                f"В расшифрованном payload отсутствуют поля: {', '.join(sorted(missing))}"
            )

        return payload