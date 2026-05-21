from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.crypto.key_derivation import PBKDF2Params, derive_encryption_key
from src.core.import_export.formats import get_format_handler
from src.core.import_export.key_exchange import KeyExchangeService
from src.core.validators import clean_text, clean_url, validate_required


class VaultImporter:
    KEY_PURPOSE = "vault-import-export-encryption"
    KEY_WRAP_PURPOSE = "vault-import-export-wrap"
    MALICIOUS_PATTERNS = (
        r"<script\b",
        r"javascript:",
        r"vbscript:",
        r"powershell(?:\.exe)?\b",
        r"cmd(?:\.exe)?\b",
        r"/bin/sh\b",
        r"bash\s+-c\b",
        r"os\.system\s*\(",
        r"subprocess\.",
        r"eval\s*\(",
        r"wget\s+https?://",
        r"curl\s+https?://",
    )

    @dataclass(slots=True)
    class ImportResult:
        mode: str
        duplicates: list[dict]
        imported_ids: list[int]
        updated_ids: list[int]
        skipped_duplicates: int
        preview_entries: list[dict]

    def __init__(
        self,
        vault_service,
        key_manager,
        key_exchange: KeyExchangeService | None = None,
        max_file_size_bytes: int = 10 * 1024 * 1024,
        timeout_seconds: int = 30,
    ):
        self.vault_service = vault_service
        self.key_manager = key_manager
        self.key_exchange = key_exchange
        self.max_file_size_bytes = max_file_size_bytes
        self.timeout_seconds = timeout_seconds

    def import_package(
        self,
        payload: bytes | str,
        import_password: str | None = None,
        mode: str = "merge",
        duplicate_handling: str = "update",
        format_hint: str | None = None,
    ) -> ImportResult:
        started_at = time.monotonic()
        raw_payload = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        self._check_limits(raw_payload)
        entries = self._load_entries_from_payload(raw_payload, import_password=import_password, format_hint=format_hint)
        self._check_timeout(started_at)
        sanitized_entries = [self._sanitize_entry(item) for item in entries]
        existing_index = self._build_existing_index()
        duplicates = self._find_duplicates(sanitized_entries, existing_index=existing_index)
        preview = list(sanitized_entries)

        if mode not in {"merge", "replace", "dry-run"}:
            raise ValueError("import mode must be merge, replace, or dry-run")
        if duplicate_handling not in {"skip", "update", "error"}:
            raise ValueError("duplicate handling must be skip, update, or error")

        if mode == "dry-run":
            return self.ImportResult(
                mode=mode,
                duplicates=duplicates,
                imported_ids=[],
                updated_ids=[],
                skipped_duplicates=0,
                preview_entries=preview,
            )

        if mode == "replace":
            self.vault_service.clear_entries()

        imported_ids = []
        updated_ids = []
        skipped_duplicates = 0
        for clean in sanitized_entries:
            duplicate = self._match_existing(clean, existing_index=existing_index)
            if duplicate is not None and mode == "merge":
                if duplicate_handling == "error":
                    raise ValueError("duplicate entries detected during import")
                if duplicate_handling == "skip":
                    skipped_duplicates += 1
                    continue
                updated = self.vault_service.update_entry(duplicate.id, clean)
                updated_ids.append(int(updated.id))
            else:
                entry = self.vault_service.create_entry(clean)
                imported_ids.append(int(entry.id))
                existing_index[self._entry_fingerprint(clean)] = entry
            self._check_timeout(started_at)
        return self.ImportResult(
            mode=mode,
            duplicates=duplicates,
            imported_ids=imported_ids,
            updated_ids=updated_ids,
            skipped_duplicates=skipped_duplicates,
            preview_entries=preview,
        )

    def _load_entries_from_payload(
        self,
        raw_payload: bytes,
        import_password: str | None = None,
        format_hint: str | None = None,
    ) -> list[dict]:
        detected = format_hint or self.detect_format(raw_payload)
        if detected == "encrypted_json":
            package = json.loads(raw_payload.decode("utf-8"))
            if package.get("cryptosafe_export") is True:
                return self._load_entries_from_native_export(package, import_password=import_password)
            self._validate_encrypted_package(package)
            self._verify_outer_auth(package, import_password=import_password)
            document = self._decrypt_document(package, import_password=import_password)
            metadata = document.get("metadata", {})
            payload_bytes = bytes.fromhex(document.get("payload", ""))
            if metadata.get("compressed"):
                payload_bytes = gzip.decompress(payload_bytes)
            handler = get_format_handler(str(metadata.get("content_format", "json")))
            return handler.deserialize(payload_bytes)

        handler_name = {
            "json": "json",
            "csv": "csv",
            "bitwarden_json": "bitwarden_json",
            "lastpass_csv": "lastpass_csv",
        }.get(detected)
        if handler_name is None:
            raise ValueError(f"unsupported import payload format: {detected}")
        return get_format_handler(handler_name).deserialize(raw_payload)

    @staticmethod
    def detect_format(raw_payload: bytes) -> str:
        text = raw_payload.decode("utf-8-sig", errors="ignore").strip()
        if text.startswith("{") or text.startswith("["):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = None
            if isinstance(data, dict) and data.get("cryptosafe_export") is True:
                return "encrypted_json"
            if isinstance(data, dict) and data.get("metadata", {}).get("package_format") == "cryptosafe.vault-export.encrypted.v1":
                return "encrypted_json"
            if isinstance(data, dict) and "items" in data:
                return "bitwarden_json"
            return "json"
        header = text.splitlines()[0].lower() if text else ""
        if "name,url,username,password" in header:
            return "lastpass_csv"
        return "csv"

    def _load_entries_from_native_export(self, package: dict, import_password: str | None = None) -> list[dict]:
        encryption = package["encryption"]
        data_b64 = package["data"]
        integrity = package["integrity"]
        metadata = package.get("metadata", {})
        mode = encryption.get("mode", "password")
        if mode == "password":
            if not import_password:
                raise PermissionError("import password is required")
            salt = base64.b64decode(encryption["salt"])
            nonce = base64.b64decode(encryption["nonce"])
            params = PBKDF2Params(
                iterations=int(encryption.get("iterations", 100000)),
                salt_len=len(salt),
                dklen=32,
                hash_name="sha256",
            )
            export_key = derive_encryption_key(import_password, salt, params)
            export_key_buffer = bytearray(export_key)
            plaintext_buffer: bytearray | None = None
            try:
                auth_payload = self._native_auth_payload(
                    package["version"],
                    package["timestamp"],
                    encryption,
                    data_b64,
                    integrity["hash"],
                )
                expected_sig = hmac.new(bytes(export_key_buffer), auth_payload, hashlib.sha256).digest()
                if not hmac.compare_digest(expected_sig, base64.b64decode(integrity["signature"])):
                    raise ValueError("native export signature verification failed before decryption")
                plaintext = AESGCM(bytes(export_key_buffer)).decrypt(nonce, base64.b64decode(data_b64), None)
                plaintext_buffer = bytearray(plaintext)
            finally:
                self._wipe_bytes(export_key_buffer)
        else:
            legacy = self._native_export_to_legacy_package(package)
            self._validate_encrypted_package(legacy)
            self._verify_outer_auth(legacy, import_password=import_password)
            document = self._decrypt_document(legacy, import_password=import_password)
            payload_bytes = bytes.fromhex(document.get("payload", ""))
            if document.get("metadata", {}).get("compressed"):
                payload_bytes = gzip.decompress(payload_bytes)
            return get_format_handler(str(document.get("metadata", {}).get("content_format", "json"))).deserialize(payload_bytes)

        try:
            if hashlib.sha256(plaintext).hexdigest() != integrity["hash"]:
                raise ValueError("native export integrity hash mismatch")
            if metadata.get("compressed"):
                plaintext = gzip.decompress(plaintext)
            handler = get_format_handler(str(metadata.get("content_format", "json")))
            return handler.deserialize(plaintext)
        finally:
            self._wipe_bytes(plaintext_buffer if mode == "password" else None)

    @staticmethod
    def _native_auth_payload(version: str, timestamp: str, encryption: dict, data_b64: str, hash_value: str) -> bytes:
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

    @staticmethod
    def _native_export_to_legacy_package(package: dict) -> dict:
        wrapped_key = json.loads(base64.b64decode(package["encryption"]["wrapped_key"]).decode("utf-8"))
        outer_auth = json.loads(base64.b64decode(package["integrity"]["outer_auth"]).decode("utf-8"))
        return {
            "metadata": {
                "package_format": "cryptosafe.vault-export.encrypted.v1",
                "algorithm": package["encryption"]["algorithm"],
                "key_purpose": "vault-import-export-encryption",
                "wrapped_key_mode": package["encryption"].get("mode", "master"),
                "integrity_hash": package["integrity"]["hash"],
                "signature_algorithm": package["integrity"]["signature_algorithm"],
                "signature": package["integrity"]["signature"],
            },
            "wrapped_key": wrapped_key,
            "nonce": base64.b64decode(package["encryption"]["nonce"]).hex(),
            "ciphertext": base64.b64decode(package["data"]).hex(),
            "outer_auth": outer_auth,
        }

    def _check_limits(self, payload: bytes) -> None:
        if len(payload) > self.max_file_size_bytes:
            raise ValueError("import package exceeds configured size limit")

    def _check_timeout(self, started_at: float) -> None:
        if self.timeout_seconds <= 0:
            raise TimeoutError("import processing exceeded configured timeout")
        if time.monotonic() - started_at > self.timeout_seconds:
            raise TimeoutError("import processing exceeded configured timeout")

    def _validate_encrypted_package(self, package: dict) -> None:
        metadata = package.get("metadata", {})
        if metadata.get("package_format") != "cryptosafe.vault-export.encrypted.v1":
            raise ValueError("unsupported import package format")
        algorithm = str(metadata.get("algorithm", ""))
        if algorithm not in {"AES-128-GCM", "AES-256-GCM"}:
            raise ValueError("unsupported encryption algorithm")
        wrapped_key = package.get("wrapped_key")
        if not isinstance(wrapped_key, dict) or not wrapped_key.get("mode"):
            raise ValueError("missing wrapped export key")
        outer_auth = package.get("outer_auth")
        if not isinstance(outer_auth, dict) or not outer_auth.get("algorithm") or not outer_auth.get("value"):
            raise ValueError("missing package integrity authentication")
        for field in ("nonce", "ciphertext"):
            value = package.get(field, "")
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]+", value) or len(value) < 24:
                raise ValueError(f"invalid encrypted package field: {field}")

    def _verify_outer_auth(self, package: dict, import_password: str | None = None) -> None:
        payload = self._canonical_package_auth_payload(package)
        wrapped_key = package["wrapped_key"]
        outer_auth = package["outer_auth"]
        mode = wrapped_key.get("mode")

        if mode == "master":
            wrapping_key = self.key_manager.derive_key(self.KEY_WRAP_PURPOSE, 32)
            expected = hmac.new(wrapping_key, payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, outer_auth["value"]):
                raise ValueError("package authentication failed before decryption")
            return

        if mode == "password":
            if not import_password:
                raise PermissionError("import password is required")
            params = PBKDF2Params.from_json(json.dumps(wrapped_key["pbkdf2_params"]).encode("utf-8"))
            wrapping_key = derive_encryption_key(import_password, bytes.fromhex(wrapped_key["salt"]), params)
            expected = hmac.new(wrapping_key, payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, outer_auth["value"]):
                raise ValueError("package authentication failed before decryption")
            return

        if mode == "public_key":
            sender_algorithm = outer_auth.get("sender_algorithm")
            sender_public_key = bytes.fromhex(outer_auth.get("sender_public_key", ""))
            signature = bytes.fromhex(outer_auth["value"])
            if not KeyExchangeService.verify_signature(sender_algorithm, sender_public_key, payload, signature):
                raise ValueError("public-key package signature verification failed")
            return

        raise ValueError(f"unsupported wrapped key mode: {mode}")

    @staticmethod
    def _canonical_package_auth_payload(package: dict) -> bytes:
        return json.dumps(
            {
                "metadata": package["metadata"],
                "nonce": package["nonce"],
                "ciphertext": package["ciphertext"],
                "wrapped_key": package["wrapped_key"],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def _decrypt_document(self, package: dict, import_password: str | None = None) -> dict:
        nonce = bytes.fromhex(package["nonce"])
        ciphertext = bytes.fromhex(package["ciphertext"])
        export_key = self._unwrap_export_key(package["wrapped_key"], import_password=import_password)
        export_key_buffer = bytearray(export_key)
        plaintext_buffer: bytearray | None = None
        try:
            plaintext = AESGCM(bytes(export_key_buffer)).decrypt(nonce, ciphertext, None)
            plaintext_buffer = bytearray(plaintext)
            integrity_hash = hashlib.sha256(bytes(plaintext_buffer)).hexdigest()
            expected_hash = package["metadata"]["integrity_hash"]
            if integrity_hash != expected_hash:
                raise ValueError("export integrity hash mismatch")
            expected_signature = hmac.new(bytes(export_key_buffer), integrity_hash.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_signature, package["metadata"]["signature"]):
                raise ValueError("export signature verification failed")
            return json.loads(bytes(plaintext_buffer).decode("utf-8"))
        finally:
            self._wipe_bytes(export_key_buffer)
            self._wipe_bytes(plaintext_buffer)

    def _unwrap_export_key(self, wrapped_key: dict, import_password: str | None = None) -> bytes:
        mode = wrapped_key.get("mode")
        if mode == "master":
            wrapping_key = self.key_manager.derive_key(self.KEY_WRAP_PURPOSE, 32)
            return AESGCM(wrapping_key).decrypt(
                bytes.fromhex(wrapped_key["nonce"]),
                bytes.fromhex(wrapped_key["wrapped_key"]),
                None,
            )
        if mode == "password":
            if not import_password:
                raise PermissionError("import password is required")
            params = PBKDF2Params.from_json(json.dumps(wrapped_key["pbkdf2_params"]).encode("utf-8"))
            wrapping_key = derive_encryption_key(import_password, bytes.fromhex(wrapped_key["salt"]), params)
            return AESGCM(wrapping_key).decrypt(
                bytes.fromhex(wrapped_key["nonce"]),
                bytes.fromhex(wrapped_key["wrapped_key"]),
                None,
            )
        if mode == "public_key":
            if self.key_exchange is None:
                raise PermissionError("key exchange service is required for public-key import")
            return self.key_exchange.unwrap_key_from_sender(wrapped_key)
        raise ValueError(f"unsupported wrapped key mode: {mode}")

    def _sanitize_entry(self, entry: dict) -> dict:
        self._scan_for_malicious_content(entry)
        title = self._sanitize_text(str(entry.get("title", "")))
        username = self._sanitize_text(str(entry.get("username", "")))
        password = str(entry.get("password", "") or "").strip()
        url = clean_url(str(entry.get("url", "") or "")) if entry.get("url") else ""
        notes = self._sanitize_text(str(entry.get("notes", "") or ""))
        category = self._sanitize_text(str(entry.get("category", "") or ""))
        tags = self._sanitize_text(str(entry.get("tags", "") or ""))

        validate_required(title, "Название")
        validate_required(username, "Имя пользователя")
        validate_required(password, "Пароль")

        return {
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
            "category": category,
            "tags": tags,
        }

    def _sanitize_text(self, value: str) -> str:
        value = re.sub(r"<script.*?>.*?</script>", "", value, flags=re.IGNORECASE | re.DOTALL)
        value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", value)
        return clean_text(value)

    def _scan_for_malicious_content(self, entry: dict) -> None:
        for value in entry.values():
            if not isinstance(value, str):
                continue
            for pattern in self.MALICIOUS_PATTERNS:
                if re.search(pattern, value, flags=re.IGNORECASE):
                    raise ValueError("import rejected due to malicious content pattern")

    def _find_duplicates(self, entries: list[dict], existing_index: dict | None = None) -> list[dict]:
        duplicates = []
        existing_index = existing_index or self._build_existing_index()
        for item in entries:
            existing = self._match_existing(item, existing_index=existing_index)
            if existing is not None:
                duplicates.append(
                    {
                        "entry_id": int(existing.id),
                        "title": existing.title,
                        "username": existing.username,
                        "url": existing.url,
                    }
                )
        return duplicates

    def _match_existing(self, clean: dict, existing_index: dict | None = None):
        existing_index = existing_index or self._build_existing_index()
        return existing_index.get(self._entry_fingerprint(clean))

    def _build_existing_index(self) -> dict:
        index = {}
        for entry in self.vault_service.get_all_entries():
            index[self._entry_fingerprint({
                "title": entry.title,
                "username": entry.username,
                "url": entry.url,
            })] = entry
        return index

    @staticmethod
    def _entry_fingerprint(clean: dict) -> tuple[str, str, str]:
        return (
            clean.get("title", "").strip().lower(),
            clean.get("username", "").strip().lower(),
            clean.get("url", "").strip().lower(),
        )

    @staticmethod
    def _wipe_bytes(buffer: bytearray | None) -> None:
        if buffer is None:
            return
        for index in range(len(buffer)):
            buffer[index] = 0
