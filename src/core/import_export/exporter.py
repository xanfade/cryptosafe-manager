from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.core.crypto.key_derivation import PBKDF2Params, derive_encryption_key, verify_auth_hash

from src.core.events import VaultDataExported
from src.core.import_export.formats import get_format_handler
from src.core.import_export.key_exchange import KeyExchangeService


class VaultExporter:
    KEY_PURPOSE = "vault-import-export-encryption"
    KEY_WRAP_PURPOSE = "vault-import-export-wrap"

    def __init__(self, vault_service, key_manager, event_bus=None, key_exchange: KeyExchangeService | None = None):
        self.vault_service = vault_service
        self.key_manager = key_manager
        self.event_bus = event_bus
        self.key_exchange = key_exchange

    def export_vault(
        self,
        fmt: str = "json",
        entry_ids: list[int] | None = None,
        exporter: str = "local",
        include_fields: list[str] | None = None,
        exclude_fields: list[str] | None = None,
        key_bits: int = 256,
        compress: bool = False,
        encrypt: bool = True,
        protection_mode: str = "master",
        confirmation_password: str | None = None,
        export_password: str | None = None,
        recipient_public_key: bytes | None = None,
    ) -> bytes:
        handler = get_format_handler(fmt)
        entries = self._load_entries(entry_ids, include_fields=include_fields, exclude_fields=exclude_fields)
        metadata = {
            "format": "cryptosafe.vault-export.v1",
            "content_format": fmt,
            "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "exporter": exporter,
            "source_application": "CryptoSafe Manager",
            "version": 1,
            "scope": "selective" if entry_ids else "full",
            "entry_ids": entry_ids or [],
            "entry_count": len(entries),
            "include_fields": include_fields or [],
            "exclude_fields": exclude_fields or [],
            "compressed": compress,
            "compression": "gzip" if compress else None,
        }
        if fmt == "bitwarden_encrypted_json":
            if protection_mode != "password":
                raise PermissionError("bitwarden encrypted json export requires password mode")
            if compress:
                raise ValueError("bitwarden encrypted json export does not support gzip compression")
            payload = handler.serialize(entries, password=export_password)
            if self.event_bus is not None:
                self.event_bus.publish(
                    VaultDataExported(
                        format=fmt,
                        entry_count=len(entries),
                        scope="selective" if entry_ids else "full",
                        encrypted=True,
                        protection_mode=protection_mode,
                    )
                )
            return payload
        serialized = handler.serialize(entries, metadata=metadata if fmt in {"csv", "lastpass_csv"} else None)
        payload_bytes = gzip.compress(serialized) if compress else serialized
        if not encrypt:
            return payload_bytes
        document = {
            "metadata": metadata,
            "payload": payload_bytes.hex(),
        }
        if fmt == "json":
            payload = self._build_native_json_export(
                payload_bytes=payload_bytes,
                metadata=metadata,
                protection_mode=protection_mode,
                confirmation_password=confirmation_password,
                export_password=export_password,
                recipient_public_key=recipient_public_key,
            )
        else:
            payload = self._encrypt_document(
                document,
                encrypt=encrypt,
                protection_mode=protection_mode,
                confirmation_password=confirmation_password,
                export_password=export_password,
                recipient_public_key=recipient_public_key,
                key_bits=key_bits,
            )
        if self.event_bus is not None:
            self.event_bus.publish(
                VaultDataExported(
                    format=fmt,
                    entry_count=len(entries),
                    scope="selective" if entry_ids else "full",
                    encrypted=encrypt,
                    protection_mode=protection_mode,
                )
            )
        return payload

    def _build_native_json_export(
        self,
        payload_bytes: bytes,
        metadata: dict[str, Any],
        protection_mode: str,
        confirmation_password: str | None,
        export_password: str | None,
        recipient_public_key: bytes | None,
    ) -> bytes:
        plaintext = payload_bytes
        plaintext_buffer = bytearray(plaintext)
        integrity_hash = hashlib.sha256(plaintext).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        if protection_mode == "password":
            if not export_password:
                raise PermissionError("export password is required")
            params = PBKDF2Params()
            salt = os.urandom(params.salt_len)
            export_key = derive_encryption_key(export_password, salt, params)
            export_key_buffer = bytearray(export_key)
            try:
                nonce = os.urandom(12)
                ciphertext = AESGCM(bytes(export_key_buffer)).encrypt(nonce, bytes(plaintext_buffer), None)
                payload_to_sign = self._native_auth_payload(
                    version="1.0",
                    timestamp=timestamp,
                    encryption={
                        "algorithm": "AES-256-GCM",
                        "key_derivation": "PBKDF2-SHA256",
                        "iterations": params.iterations,
                        "salt": base64.b64encode(salt).decode("ascii"),
                        "nonce": base64.b64encode(nonce).decode("ascii"),
                        "mode": "password",
                    },
                    data_b64=base64.b64encode(ciphertext).decode("ascii"),
                    hash_value=integrity_hash,
                )
                signature = hmac.new(bytes(export_key_buffer), payload_to_sign, hashlib.sha256).digest()
                doc = {
                    "version": "1.0",
                    "cryptosafe_export": True,
                    "timestamp": timestamp,
                    "encryption": {
                        "algorithm": "AES-256-GCM",
                        "key_derivation": "PBKDF2-SHA256",
                        "iterations": params.iterations,
                        "salt": base64.b64encode(salt).decode("ascii"),
                        "nonce": base64.b64encode(nonce).decode("ascii"),
                        "mode": "password",
                    },
                    "data": base64.b64encode(ciphertext).decode("ascii"),
                    "integrity": {
                        "hash": integrity_hash,
                        "signature": base64.b64encode(signature).decode("ascii"),
                        "signature_algorithm": "HMAC-SHA256",
                    },
                    "metadata": metadata,
                }
                return json.dumps(doc, ensure_ascii=False, indent=2).encode("utf-8")
            finally:
                self._wipe_bytes(export_key_buffer)
                self._wipe_bytes(plaintext_buffer)

        document = {
            "metadata": metadata,
            "payload": plaintext.hex(),
        }
        package = self._encrypt_document(
            document,
            encrypt=True,
            protection_mode=protection_mode,
            confirmation_password=confirmation_password,
            export_password=export_password,
            recipient_public_key=recipient_public_key,
            key_bits=256,
        )
        legacy = json.loads(package.decode("utf-8"))
        encryption_info = {
            "algorithm": legacy["metadata"]["algorithm"],
            "key_derivation": "HKDF-SHA256" if protection_mode == "master" else legacy["wrapped_key"]["algorithm"],
            "iterations": 0,
            "salt": base64.b64encode(b"").decode("ascii"),
            "nonce": base64.b64encode(bytes.fromhex(legacy["nonce"])).decode("ascii"),
            "mode": protection_mode,
            "wrapped_key": base64.b64encode(json.dumps(legacy["wrapped_key"], ensure_ascii=False).encode("utf-8")).decode("ascii"),
        }
        if legacy["wrapped_key"].get("sender_public_key"):
            encryption_info["sender_public_key"] = legacy["wrapped_key"]["sender_public_key"]
        doc = {
            "version": "1.0",
            "cryptosafe_export": True,
            "timestamp": timestamp,
            "encryption": encryption_info,
            "data": base64.b64encode(bytes.fromhex(legacy["ciphertext"])).decode("ascii"),
            "integrity": {
                "hash": legacy["metadata"]["integrity_hash"],
                "signature": legacy["metadata"]["signature"],
                "signature_algorithm": legacy["metadata"]["signature_algorithm"],
                "outer_auth": base64.b64encode(
                    json.dumps(legacy["outer_auth"], ensure_ascii=False).encode("utf-8")
                ).decode("ascii"),
            },
            "metadata": metadata,
        }
        return json.dumps(doc, ensure_ascii=False, indent=2).encode("utf-8")

    @staticmethod
    def _native_auth_payload(version: str, timestamp: str, encryption: dict[str, Any], data_b64: str, hash_value: str) -> bytes:
        return json.dumps(
            {
                "version": version,
                "timestamp": timestamp,
                "encryption": encryption,
                "data": data_b64,
                "hash": hash_value,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def export_entry(self, entry_id: int, fmt: str = "json", exporter: str = "local", **kwargs) -> bytes:
        return self.export_vault(fmt=fmt, entry_ids=[entry_id], exporter=exporter, **kwargs)

    def export_query(self, query: str, fmt: str = "json", exporter: str = "local", **kwargs) -> bytes:
        if not hasattr(self.vault_service, "find_entries"):
            raise RuntimeError("vault service does not support query-based export")
        entries = self.vault_service.find_entries(query)
        entry_ids = [int(entry.id) for entry in entries]
        return self.export_vault(fmt=fmt, entry_ids=entry_ids, exporter=exporter, **kwargs)

    def _load_entries(
        self,
        entry_ids: list[int] | None,
        include_fields: list[str] | None = None,
        exclude_fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        if entry_ids:
            entries = []
            for entry_id in entry_ids:
                entry = self.vault_service.get_entry(entry_id)
                if entry is None:
                    raise ValueError(f"entry {entry_id} not found")
                entries.append(self._filter_fields(self._entry_to_dict(entry), include_fields, exclude_fields))
            return entries

        return [
            self._filter_fields(self._entry_to_dict(entry), include_fields, exclude_fields)
            for entry in self.vault_service.get_all_entries()
        ]

    @staticmethod
    def _entry_to_dict(entry) -> dict[str, Any]:
        return {
            "id": int(entry.id),
            "title": entry.title,
            "username": entry.username,
            "password": entry.password,
            "url": entry.url,
            "notes": entry.notes,
            "category": entry.category,
            "tags": entry.tags,
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
            "version": entry.version,
        }

    @staticmethod
    def _filter_fields(entry: dict[str, Any], include_fields: list[str] | None, exclude_fields: list[str] | None) -> dict[str, Any]:
        allowed = set(include_fields) if include_fields else set(entry.keys())
        blocked = set(exclude_fields or [])
        return {key: value for key, value in entry.items() if key in allowed and key not in blocked}

    def _encrypt_document(
        self,
        document: dict[str, Any],
        encrypt: bool,
        protection_mode: str,
        confirmation_password: str | None,
        export_password: str | None,
        recipient_public_key: bytes | None,
        key_bits: int,
    ) -> bytes:
        plaintext = json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        plaintext_buffer = bytearray(plaintext)
        export_key_buffer: bytearray | None = None
        if key_bits not in {128, 256}:
            raise ValueError("encryption strength must be 128 or 256 bits")
        try:
            export_key = os.urandom(16 if key_bits == 128 else 32)
            export_key_buffer = bytearray(export_key)
            nonce = os.urandom(12)
            ciphertext = AESGCM(bytes(export_key_buffer)).encrypt(nonce, bytes(plaintext_buffer), None)
            integrity_hash = hashlib.sha256(bytes(plaintext_buffer)).hexdigest()
            signature = hmac.new(bytes(export_key_buffer), integrity_hash.encode("utf-8"), hashlib.sha256).hexdigest()
            package_core = {
                "metadata": {
                    "package_format": "cryptosafe.vault-export.encrypted.v1",
                    "algorithm": f"AES-{key_bits}-GCM",
                    "key_purpose": self.KEY_PURPOSE,
                    "wrapped_key_mode": protection_mode,
                    "integrity_hash": integrity_hash,
                    "signature_algorithm": "HMAC-SHA256",
                    "signature": signature,
                },
                "nonce": nonce.hex(),
                "ciphertext": ciphertext.hex(),
            }
            wrapped_key, outer_auth = self._wrap_export_key(
                bytes(export_key_buffer),
                protection_mode=protection_mode,
                confirmation_password=confirmation_password,
                export_password=export_password,
                recipient_public_key=recipient_public_key,
                package_core=package_core,
            )
            package = dict(package_core)
            package["wrapped_key"] = wrapped_key
            package["outer_auth"] = outer_auth
            return json.dumps(package, ensure_ascii=False, indent=2).encode("utf-8")
        finally:
            self._wipe_bytes(plaintext_buffer)
            self._wipe_bytes(export_key_buffer)

    def _wrap_export_key(
        self,
        export_key: bytes,
        protection_mode: str,
        confirmation_password: str | None,
        export_password: str | None,
        recipient_public_key: bytes | None,
        package_core: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if protection_mode == "master":
            self._confirm_master_password(confirmation_password)
            wrapping_key = self.key_manager.derive_key(self.KEY_WRAP_PURPOSE, 32)
            wrapping_key_buffer = bytearray(wrapping_key)
            try:
                nonce = os.urandom(12)
                wrapped = AESGCM(bytes(wrapping_key_buffer)).encrypt(nonce, export_key, None)
                wrapped_key = {
                    "mode": "master",
                    "algorithm": "AES-256-GCM",
                    "nonce": nonce.hex(),
                    "wrapped_key": wrapped.hex(),
                }
                return wrapped_key, self._outer_hmac_auth(bytes(wrapping_key_buffer), package_core, wrapped_key)
            finally:
                self._wipe_bytes(wrapping_key_buffer)

        if protection_mode == "password":
            if not export_password:
                raise PermissionError("export password is required")
            params = PBKDF2Params()
            salt = os.urandom(params.salt_len)
            wrapping_key = derive_encryption_key(export_password, salt, params)
            wrapping_key_buffer = bytearray(wrapping_key)
            try:
                nonce = os.urandom(12)
                wrapped = AESGCM(bytes(wrapping_key_buffer)).encrypt(nonce, export_key, None)
                wrapped_key = {
                    "mode": "password",
                    "algorithm": "PBKDF2+AES-256-GCM",
                    "pbkdf2_params": json.loads(params.to_json().decode("utf-8")),
                    "salt": salt.hex(),
                    "nonce": nonce.hex(),
                    "wrapped_key": wrapped.hex(),
                }
                return wrapped_key, self._outer_hmac_auth(bytes(wrapping_key_buffer), package_core, wrapped_key)
            finally:
                self._wipe_bytes(wrapping_key_buffer)

        if protection_mode == "public_key":
            if recipient_public_key is None:
                raise PermissionError("recipient public key is required")
            key_exchange = self.key_exchange or KeyExchangeService(algorithm="p256")
            wrapped_key = key_exchange.wrap_key_for_recipient(export_key, recipient_public_key)
            return wrapped_key, self._outer_signature_auth(key_exchange, package_core, wrapped_key)

        raise ValueError(f"unsupported protection mode: {protection_mode}")

    @staticmethod
    def _canonical_package_auth_payload(package_core: dict[str, Any], wrapped_key: dict[str, Any]) -> bytes:
        return json.dumps(
            {
                "metadata": package_core["metadata"],
                "nonce": package_core["nonce"],
                "ciphertext": package_core["ciphertext"],
                "wrapped_key": wrapped_key,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def _outer_hmac_auth(self, wrapping_key: bytes, package_core: dict[str, Any], wrapped_key: dict[str, Any]) -> dict[str, Any]:
        payload = self._canonical_package_auth_payload(package_core, wrapped_key)
        return {
            "algorithm": "HMAC-SHA256",
            "value": hmac.new(wrapping_key, payload, hashlib.sha256).hexdigest(),
        }

    def _outer_signature_auth(self, key_exchange: KeyExchangeService, package_core: dict[str, Any], wrapped_key: dict[str, Any]) -> dict[str, Any]:
        payload = self._canonical_package_auth_payload(package_core, wrapped_key)
        return {
            "algorithm": f"{key_exchange.algorithm}-signature",
            "sender_algorithm": key_exchange.algorithm,
            "sender_public_key": key_exchange.export_public_key().hex(),
            "value": key_exchange.sign(payload).hex(),
        }

    def _confirm_master_password(self, confirmation_password: str | None) -> None:
        if not confirmation_password:
            raise PermissionError("master password confirmation is required")
        bundle = self.key_manager.load_bundle()
        if not verify_auth_hash(
            password=confirmation_password,
            salt=bundle["auth_salt"],
            expected_hash=bundle["auth_hash"],
            params=bundle["argon2_params"],
        ):
            raise PermissionError("master password confirmation failed")

    @staticmethod
    def _wipe_bytes(buffer: bytearray | None) -> None:
        if buffer is None:
            return
        for index in range(len(buffer)):
            buffer[index] = 0
