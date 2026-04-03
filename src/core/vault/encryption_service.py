from __future__ import annotations

import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.crypto.abstract import EncryptionService


class VaultEncryptionService(EncryptionService):
    NONCE_SIZE = 12
    PAYLOAD_VERSION = 1

    def encrypt(self, data: bytes) -> bytes:
        key = self._require_key()

        if not isinstance(data, (bytes, bytearray)):
            raise ValueError("Для шифрования ожидаются байты.")

        nonce = os.urandom(self.NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, bytes(data), None)
        return nonce + ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
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

    def _normalize_payload(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ValueError("Payload должен быть словарем.")

        normalized = {
            "title": payload.get("title", "") or "",
            "username": payload.get("username", "") or "",
            "password": payload.get("password", "") or "",
            "url": payload.get("url", "") or "",
            "notes": payload.get("notes", "") or "",
            "created_at": payload.get("created_at", "") or "",
            "version": payload.get("version", self.PAYLOAD_VERSION),
        }

        required = ["title", "username", "password", "version"]
        missing = [field for field in required if normalized.get(field, "") == ""]
        if missing:
            raise ValueError(
                f"В payload отсутствуют обязательные поля: {', '.join(missing)}"
            )

        return normalized

    def encrypt_entry_payload(self, payload: dict) -> bytes:
        normalized = self._normalize_payload(payload)
        plaintext = json.dumps(
            normalized,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return self.encrypt(plaintext)

    def decrypt_entry_payload(self, encrypted_data: bytes) -> dict:
        plaintext = self.decrypt(encrypted_data)

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
            "created_at",
            "version",
        }
        missing = required_fields - payload.keys()
        if missing:
            raise ValueError(
                f"В расшифрованном payload отсутствуют поля: {', '.join(sorted(missing))}"
            )

        return payload