import json
import os
from typing import Any, Dict

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultEncryptionService:
    NONCE_SIZE = 12
    KEY_SIZE = 32
    PAYLOAD_VERSION = 1

    def __init__(self, key_manager):
        self.key_manager = key_manager

    def _get_key(self) -> bytes:
        key = self.key_manager.get_encryption_key()
        if not key:
            raise ValueError("Хранилище заблокировано. Сначала выполните вход.")

        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Ключ шифрования должен быть bytes.")

        key = bytes(key)

        if len(key) != self.KEY_SIZE:
            raise ValueError("Ключ AES-256-GCM должен быть длиной 32 байта.")

        return key

    @staticmethod
    def encrypt_with_key(key: bytes, plaintext: bytes) -> bytes:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Ключ должен быть bytes.")
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("Открытый текст должен быть bytes.")

        key = bytes(key)
        plaintext = bytes(plaintext)

        if len(key) != VaultEncryptionService.KEY_SIZE:
            raise ValueError("Ключ AES-256-GCM должен быть длиной 32 байта.")

        nonce = os.urandom(VaultEncryptionService.NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    @staticmethod
    def decrypt_with_key(key: bytes, encrypted_blob: bytes) -> bytes:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Ключ должен быть bytes.")
        if not isinstance(encrypted_blob, (bytes, bytearray)):
            raise TypeError("Зашифрованные данные должны быть bytes.")

        key = bytes(key)
        encrypted_blob = bytes(encrypted_blob)

        if len(key) != VaultEncryptionService.KEY_SIZE:
            raise ValueError("Ключ AES-256-GCM должен быть длиной 32 байта.")
        if len(encrypted_blob) <= VaultEncryptionService.NONCE_SIZE:
            raise ValueError("Зашифрованный пакет слишком короткий.")

        nonce = encrypted_blob[:VaultEncryptionService.NONCE_SIZE]
        ciphertext = encrypted_blob[VaultEncryptionService.NONCE_SIZE:]

        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise ValueError(
                "Проверка целостности не пройдена: данные повреждены или были подменены."
            ) from exc

    def encrypt(self, plaintext: bytes) -> bytes:
        key = self._get_key()
        return self.encrypt_with_key(key, plaintext)

    def decrypt(self, encrypted_blob: bytes) -> bytes:
        key = self._get_key()
        return self.decrypt_with_key(key, encrypted_blob)

    @classmethod
    def _normalize_payload(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            raise TypeError("Payload записи должен быть словарем.")

        normalized = {
            "version": payload.get("version", cls.PAYLOAD_VERSION),
            "created_at": str(payload.get("created_at", "")),
            "title": str(payload.get("title", "")),
            "username": str(payload.get("username", "")),
            "password": str(payload.get("password", "")),
            "url": str(payload.get("url", "")),
            "notes": str(payload.get("notes", "")),
        }

        if not normalized["created_at"]:
            raise ValueError("Поле created_at обязательно для шифруемого payload.")

        return normalized

    def encrypt_entry_payload(self, payload: Dict[str, Any]) -> bytes:
        normalized = self._normalize_payload(payload)
        json_bytes = json.dumps(
            normalized,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return self.encrypt(json_bytes)

    def decrypt_entry_payload(self, encrypted_blob: bytes) -> Dict[str, Any]:
        plaintext = self.decrypt(encrypted_blob)

        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Расшифрованные данные записи имеют неверный JSON-формат.") from exc

        if not isinstance(payload, dict):
            raise ValueError("Расшифрованные данные записи должны быть JSON-объектом.")

        version = payload.get("version")
        if version != self.PAYLOAD_VERSION:
            raise ValueError(f"Неподдерживаемая версия payload: {version}")

        required_fields = ("created_at", "title", "username", "password", "url", "notes")
        for field in required_fields:
            if field not in payload:
                raise ValueError(f"В payload отсутствует обязательное поле: {field}")

        return payload

    @classmethod
    def encrypt_entry_payload_with_key(cls, key: bytes, payload: Dict[str, Any]) -> bytes:
        normalized = cls._normalize_payload(payload)
        json_bytes = json.dumps(
            normalized,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return cls.encrypt_with_key(key, json_bytes)

    @classmethod
    def decrypt_entry_payload_with_key(cls, key: bytes, encrypted_blob: bytes) -> Dict[str, Any]:
        plaintext = cls.decrypt_with_key(key, encrypted_blob)

        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Расшифрованные данные записи имеют неверный JSON-формат.") from exc

        if not isinstance(payload, dict):
            raise ValueError("Расшифрованные данные записи должны быть JSON-объектом.")

        version = payload.get("version")
        if version != cls.PAYLOAD_VERSION:
            raise ValueError(f"Неподдерживаемая версия payload: {version}")

        required_fields = ("created_at", "title", "username", "password", "url", "notes")
        for field in required_fields:
            if field not in payload:
                raise ValueError(f"В payload отсутствует обязательное поле: {field}")

        return payload