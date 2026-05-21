from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

from src.core.import_export.exporter import VaultExporter
from src.core.import_export.importer import VaultImporter
from src.core.import_export.key_exchange import KeyExchangeService


class SecureSharingService:
    def __init__(
        self,
        exporter: VaultExporter,
        importer: VaultImporter | None = None,
        key_exchange: KeyExchangeService | None = None,
    ):
        self.exporter = exporter
        self.importer = importer
        self.key_exchange = key_exchange or KeyExchangeService()

    def share_entry_with_password(
        self,
        entry_id: int,
        export_password: str,
        sharer: str,
        recipient: str,
        expires_in_days: int = 7,
        permission: str = "read-only",
        fmt: str = "json",
        include_fields: list[str] | None = None,
        exclude_fields: list[str] | None = None,
    ) -> bytes:
        package = self.exporter.export_entry(
            entry_id,
            fmt=fmt,
            exporter="sharing",
            protection_mode="password",
            export_password=export_password,
            include_fields=include_fields,
            exclude_fields=exclude_fields,
        )
        return self._wrap_share_package(
            package=package,
            sharer=sharer,
            recipient=recipient,
            expires_in_days=expires_in_days,
            permission=permission,
            method="password",
        )

    def share_entry_with_public_key(
        self,
        entry_id: int,
        recipient_public_key: bytes,
        sharer: str,
        recipient: str,
        expires_in_days: int = 7,
        permission: str = "read-only",
        fmt: str = "json",
        include_fields: list[str] | None = None,
        exclude_fields: list[str] | None = None,
    ) -> bytes:
        package = self.exporter.export_entry(
            entry_id,
            fmt=fmt,
            exporter="sharing",
            protection_mode="public_key",
            recipient_public_key=recipient_public_key,
            include_fields=include_fields,
            exclude_fields=exclude_fields,
        )
        return self._wrap_share_package(
            package=package,
            sharer=sharer,
            recipient=recipient,
            expires_in_days=expires_in_days,
            permission=permission,
            method="public_key",
        )

    def generate_share_link(
        self,
        share_package: bytes,
        base_url: str,
        expires_in_days: int,
    ) -> str:
        if not base_url:
            raise ValueError("base_url is required")
        self._validate_expiration(expires_in_days)
        token = base64.urlsafe_b64encode(share_package).decode("ascii").rstrip("=")
        return f"{base_url.rstrip('/')}/share/{token}"

    def receive_shared_entry(
        self,
        shared_payload: bytes | str,
        import_password: str | None = None,
        save_to_vault: bool = False,
    ):
        if self.importer is None:
            raise RuntimeError("sharing importer is not configured")
        envelope = json.loads(shared_payload.decode("utf-8") if isinstance(shared_payload, bytes) else shared_payload)
        metadata = envelope.get("metadata", {})
        expires_at = metadata.get("expires_at")
        if expires_at and datetime.now(timezone.utc) > datetime.fromisoformat(expires_at):
            raise PermissionError("shared entry has expired")
        package = envelope["package"].encode("utf-8")
        if save_to_vault:
            return self.importer.import_package(package, import_password=import_password, mode="merge")
        result = self.importer.import_package(package, import_password=import_password, mode="dry-run")
        return {
            "metadata": metadata,
            "preview_entries": result.preview_entries,
        }

    def _wrap_share_package(
        self,
        package: bytes,
        sharer: str,
        recipient: str,
        expires_in_days: int,
        permission: str,
        method: str,
    ) -> bytes:
        self._validate_expiration(expires_in_days)
        if permission not in {"read-only", "editable"}:
            raise ValueError("permission must be read-only or editable")
        metadata = {
            "format": "cryptosafe.shared-entry.v1",
            "sharer": sharer,
            "recipient": recipient,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=expires_in_days)).isoformat(timespec="seconds"),
            "permission": permission,
            "method": method,
        }
        payload_text = package.decode("utf-8")
        metadata["package_hash"] = hashlib.sha256(payload_text.encode("utf-8")).hexdigest()
        return json.dumps(
            {
                "metadata": metadata,
                "package": payload_text,
            },
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")

    @staticmethod
    def _validate_expiration(expires_in_days: int) -> None:
        if not 1 <= int(expires_in_days) <= 30:
            raise ValueError("share expiration must be between 1 and 30 days")
