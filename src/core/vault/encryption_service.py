from __future__ import annotations

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultEncryptionService:

    NONCE_SIZE = 12

    def __init__(self, key_manager):
        self.key_manager = key_manager

    def _require_key(self) -> bytes:
        key = self.key_manager.get_encryption_key()
        if not key:
            raise ValueError("Хранилище заблокировано. Сначала выполните вход.")
        if len(key) != 32:
            raise ValueError("Ключ шифрования должен быть длиной 32 байта для AES-256-GCM.")
        return key

    def encrypt(self, data: bytes) -> bytes:
        key = self._require_key()
        nonce = os.urandom(self.NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt(self, encrypted: bytes) -> bytes:
        key = self._require_key()
        if not encrypted or len(encrypted) <= self.NONCE_SIZE:
            raise ValueError("Некорректные зашифрованные данные.")
        nonce = encrypted[:self.NONCE_SIZE]
        ciphertext = encrypted[self.NONCE_SIZE:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)