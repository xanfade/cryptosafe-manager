from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.core.key_manager import KeyManager


class EncryptionService(ABC):
    def __init__(self, key_manager: "KeyManager"):
        self.key_manager = key_manager

    def _require_key(self) -> bytes:
        key = self.key_manager.get_encryption_key()
        if not key:
            raise ValueError("Хранилище заблокировано. Сначала выполните вход.")

        if not isinstance(key, (bytes, bytearray)):
            raise ValueError("Ключ шифрования должен быть bytes.")

        key_bytes = bytes(key)
        if len(key_bytes) != 32:
            raise ValueError("Ключ шифрования должен быть длиной 32 байта для AES-256.")

        return key_bytes

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        raise NotImplementedError