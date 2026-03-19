from __future__ import annotations

from .abstract import EncryptionService


class AES256Placeholder(EncryptionService):
    def _xor(self, data: bytes, key: bytes) -> bytes:
        if not key:
            raise ValueError("Key is empty")

        k = key * (len(data) // len(key) + 1)
        return bytes(b ^ k[i] for i, b in enumerate(data))

    def encrypt(self, data: bytes) -> bytes:
        key = self._require_key()
        return self._xor(data, key)

    def decrypt(self, ciphertext: bytes) -> bytes:
        key = self._require_key()
        return self._xor(ciphertext, key)