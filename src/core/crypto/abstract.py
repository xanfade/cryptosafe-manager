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
        return key

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """
        Шифрует данные, используя ключ из KeyManager.
        """
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Расшифровывает данные, используя ключ из KeyManager.
        """
        raise NotImplementedError