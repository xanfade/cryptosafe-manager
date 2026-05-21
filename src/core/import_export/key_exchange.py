from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class KeyExchangeService:
    CONTACTS_SETTING = "sharing.contacts"
    IDENTITY_SETTING = "sharing.local_identity"

    def __init__(self, private_key=None, algorithm: str = "x25519", db=None):
        self.algorithm = algorithm
        self.db = db
        if private_key is None:
            private_key = self._generate_private_key(algorithm)
        self.private_key = private_key
        self.public_key = self.private_key.public_key()

    @classmethod
    def from_database(cls, db, algorithm: str = "p256"):
        payload_raw = db.get_setting(cls.IDENTITY_SETTING, "")
        if payload_raw:
            payload = json.loads(payload_raw)
            private = cls._load_private_key(payload["algorithm"], bytes.fromhex(payload["private_key"]))
            return cls(private_key=private, algorithm=payload["algorithm"], db=db)

        service = cls(algorithm=algorithm, db=db)
        service._persist_identity()
        return service

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        private = x25519.X25519PrivateKey.generate()
        public = private.public_key()
        return (
            private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
        )

    @staticmethod
    def generate_p256_keypair() -> tuple[bytes, bytes]:
        private = ec.generate_private_key(ec.SECP256R1())
        public = private.public_key()
        return (
            private.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            public.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint,
            ),
        )

    @staticmethod
    def generate_rsa2048_keypair() -> tuple[bytes, bytes]:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = private.public_key()
        return (
            private.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            public.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )

    def export_public_key(self) -> bytes:
        if self.algorithm == "x25519":
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        if self.algorithm == "rsa2048":
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

    def export_public_bundle(self, owner: str = "local") -> dict[str, str]:
        public_key = self.export_public_key()
        return {
            "owner": owner,
            "algorithm": self.algorithm,
            "public_key": public_key.hex(),
            "fingerprint": self.fingerprint(public_key),
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    def encrypt_for_recipient(self, payload: bytes, recipient_public_key: bytes) -> bytes:
        if self.algorithm != "x25519":
            raise ValueError("direct payload encryption is only supported for x25519 instances")
        recipient = x25519.X25519PublicKey.from_public_bytes(recipient_public_key)
        shared_secret = self.private_key.exchange(recipient)
        key = self._derive_shared_key(shared_secret)
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, payload, None)
        return nonce + ciphertext

    def decrypt_from_sender(self, payload: bytes, sender_public_key: bytes) -> bytes:
        if self.algorithm != "x25519":
            raise ValueError("direct payload decryption is only supported for x25519 instances")
        sender = x25519.X25519PublicKey.from_public_bytes(sender_public_key)
        shared_secret = self.private_key.exchange(sender)
        key = self._derive_shared_key(shared_secret)
        nonce = payload[:12]
        ciphertext = payload[12:]
        return AESGCM(key).decrypt(nonce, ciphertext, None)

    def wrap_key_for_recipient(self, key_material: bytes, recipient_public_key: bytes) -> dict[str, str]:
        sender_public = self.export_public_key()
        if len(recipient_public_key) == 32:
            recipient = x25519.X25519PublicKey.from_public_bytes(recipient_public_key)
            ephemeral_private = x25519.X25519PrivateKey.generate()
            ephemeral_public = ephemeral_private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            shared_secret = ephemeral_private.exchange(recipient)
            algorithm = "X25519+AES-256-GCM"
        elif recipient_public_key.startswith(b"\x30"):
            recipient = serialization.load_der_public_key(recipient_public_key)
            if not isinstance(recipient, rsa.RSAPublicKey):
                raise ValueError("DER public key must be RSA for hybrid RSA sharing")
            wrapped = recipient.encrypt(
                key_material,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return {
                "mode": "public_key",
                "algorithm": "RSA-2048-OAEP+AES-256-GCM",
                "sender_algorithm": self.algorithm,
                "sender_public_key": sender_public.hex(),
                "wrapped_key": wrapped.hex(),
            }
        else:
            recipient = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), recipient_public_key)
            ephemeral_private = ec.generate_private_key(ec.SECP256R1())
            ephemeral_public = ephemeral_private.public_key().public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint,
            )
            shared_secret = ephemeral_private.exchange(ec.ECDH(), recipient)
            algorithm = "P-256+AES-256-GCM"
        wrapping_key = self._derive_shared_key(shared_secret)
        nonce = os.urandom(12)
        wrapped = AESGCM(wrapping_key).encrypt(nonce, key_material, None)
        return {
            "mode": "public_key",
            "algorithm": algorithm,
            "sender_algorithm": self.algorithm,
            "sender_public_key": sender_public.hex(),
            "ephemeral_public_key": ephemeral_public.hex(),
            "nonce": nonce.hex(),
            "wrapped_key": wrapped.hex(),
        }

    def unwrap_key_from_sender(self, package: dict[str, str]) -> bytes:
        algorithm = package.get("algorithm", "")
        if algorithm.startswith("X25519"):
            ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
                bytes.fromhex(package["ephemeral_public_key"])
            )
            shared_secret = self.private_key.exchange(ephemeral_public)
        elif algorithm.startswith("RSA-2048-OAEP"):
            return self.private_key.decrypt(
                bytes.fromhex(package["wrapped_key"]),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        else:
            ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(),
                bytes.fromhex(package["ephemeral_public_key"]),
            )
            shared_secret = self.private_key.exchange(ec.ECDH(), ephemeral_public)
        wrapping_key = self._derive_shared_key(shared_secret)
        nonce = bytes.fromhex(package["nonce"])
        wrapped = bytes.fromhex(package["wrapped_key"])
        return AESGCM(wrapping_key).decrypt(nonce, wrapped, None)

    def store_contact(self, name: str, public_bundle: dict[str, str], verified: bool = False) -> None:
        if self.db is None:
            raise RuntimeError("database-backed key exchange service is required for contacts")
        contacts = self.list_contacts()
        contacts[name] = {
            "name": name,
            "algorithm": public_bundle["algorithm"],
            "public_key": public_bundle["public_key"],
            "fingerprint": public_bundle["fingerprint"],
            "verified": bool(verified),
            "revoked": False,
            "created_at": public_bundle.get("created_at", datetime.now(timezone.utc).isoformat(timespec="seconds")),
            "rotated_at": None,
        }
        self.db.set_setting(self.CONTACTS_SETTING, json.dumps(contacts, ensure_ascii=False))

    def list_contacts(self) -> dict[str, dict]:
        if self.db is None:
            return {}
        raw = self.db.get_setting(self.CONTACTS_SETTING, "{}")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def verify_contact_fingerprint(self, name: str, fingerprint: str) -> bool:
        contacts = self.list_contacts()
        contact = contacts.get(name)
        if not contact:
            return False
        ok = contact["fingerprint"] == fingerprint
        if ok:
            contact["verified"] = True
            self.db.set_setting(self.CONTACTS_SETTING, json.dumps(contacts, ensure_ascii=False))
        return ok

    def revoke_contact(self, name: str) -> None:
        contacts = self.list_contacts()
        if name in contacts:
            contacts[name]["revoked"] = True
            self.db.set_setting(self.CONTACTS_SETTING, json.dumps(contacts, ensure_ascii=False))

    def rotate_identity(self, algorithm: str = "p256") -> dict[str, str]:
        self.algorithm = algorithm
        self.private_key = self._generate_private_key(algorithm)
        self.public_key = self.private_key.public_key()
        self._persist_identity(rotated=True)
        return self.export_public_bundle(owner="local")

    @staticmethod
    def fingerprint(public_key: bytes) -> str:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(public_key)
        raw = digest.finalize().hex()
        return ":".join(raw[i:i + 2] for i in range(0, 32, 2))

    def _persist_identity(self, rotated: bool = False) -> None:
        if self.db is None:
            return
        private_bytes = self._private_key_bytes(self.private_key, self.algorithm)
        payload = {
            "algorithm": self.algorithm,
            "private_key": private_bytes.hex(),
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "rotated": rotated,
        }
        self.db.set_setting(self.IDENTITY_SETTING, json.dumps(payload, ensure_ascii=False))

    @staticmethod
    def _private_key_bytes(private_key, algorithm: str) -> bytes:
        if algorithm == "x25519":
            return private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        return private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @staticmethod
    def _load_private_key(algorithm: str, data: bytes):
        if algorithm == "x25519":
            return x25519.X25519PrivateKey.from_private_bytes(data)
        if algorithm == "rsa2048":
            return serialization.load_der_private_key(data, password=None)
        return serialization.load_der_private_key(data, password=None)

    @staticmethod
    def _generate_private_key(algorithm: str):
        if algorithm == "x25519":
            return x25519.X25519PrivateKey.generate()
        if algorithm == "p256":
            return ec.generate_private_key(ec.SECP256R1())
        if algorithm == "rsa2048":
            return rsa.generate_private_key(public_exponent=65537, key_size=2048)
        raise ValueError(f"unsupported key exchange algorithm: {algorithm}")

    def sign(self, payload: bytes) -> bytes:
        if self.algorithm == "p256":
            return self.private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        if self.algorithm == "rsa2048":
            return self.private_key.sign(
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        raise ValueError("signing is not supported for this key exchange algorithm")

    @staticmethod
    def verify_signature(algorithm: str, public_key: bytes, payload: bytes, signature: bytes) -> bool:
        try:
            if algorithm == "p256":
                key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
                key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
                return True
            if algorithm == "rsa2048":
                key = serialization.load_der_public_key(public_key)
                key.verify(
                    signature,
                    payload,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                return True
        except Exception:
            return False
        return False

    @staticmethod
    def _derive_shared_key(shared_secret: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"cryptosafe-entry-sharing",
        ).derive(shared_secret)
