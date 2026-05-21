from __future__ import annotations

import hmac
import hashlib
from dataclasses import dataclass
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.core.crypto.key_storage import SecureKeyCache


@dataclass(frozen=True)
class PublicKeyRecord:
    algorithm: str
    public_key_hex: str


class AuditLogSigner:
    """Signs audit records with an HKDF-separated audit key."""

    CONTEXT = b"audit-signing"

    def __init__(self, key_material: bytes):
        if len(key_material) < 16:
            raise ValueError("audit signing key material must be at least 16 bytes")

        signing_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=self.CONTEXT,
        ).derive(key_material)
        self._key_cache = SecureKeyCache()
        self._key_cache.put(signing_key)

        try:
            self._public_key = ed25519.Ed25519PrivateKey.from_private_bytes(signing_key).public_key()
            self.algorithm = "Ed25519"
        except Exception:
            self._public_key = None
            self.algorithm = "HMAC-SHA256"

    @classmethod
    def from_key_manager(cls, key_manager) -> "AuditLogSigner":
        key_material = key_manager.derive_key("audit-signing", 32)
        return cls(key_material)

    def sign(self, data: bytes) -> bytes:
        signing_key = self._get_signing_key()
        if self.algorithm == "Ed25519":
            return ed25519.Ed25519PrivateKey.from_private_bytes(signing_key).sign(data)
        return hmac.new(signing_key, data, sha256).digest()

    def verify(self, data: bytes, signature: bytes) -> bool:
        if self.algorithm == "Ed25519":
            try:
                self._public_key.verify(signature, data)
                return True
            except InvalidSignature:
                return False
        signing_key = self._get_signing_key()
        expected = hmac.new(signing_key, data, sha256).digest()
        return hmac.compare_digest(expected, signature)

    def public_key_record(self) -> PublicKeyRecord:
        if self.algorithm == "Ed25519":
            raw = self._public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return PublicKeyRecord(self.algorithm, raw.hex())
        return PublicKeyRecord(self.algorithm, "")

    def ratchet(self) -> None:
        signing_key = self._get_signing_key()
        next_key = hashlib.sha256(signing_key + b"audit-forward-secure-ratchet").digest()
        self._key_cache.put(next_key)
        if self.algorithm == "Ed25519":
            self._public_key = ed25519.Ed25519PrivateKey.from_private_bytes(next_key).public_key()

    def clear(self) -> None:
        self._key_cache.clear()

    def _get_signing_key(self) -> bytes:
        signing_key = self._key_cache.get()
        if signing_key is None:
            raise RuntimeError("audit signing key is not cached")
        return signing_key
