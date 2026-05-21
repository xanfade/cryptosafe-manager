import base64
import json

import pytest

from src.core.events import EventBus
from src.core.events import EntryShared, VaultDataImported
from src.core.import_export import (
    KeyExchangeService,
    SecureSharingService,
    VaultExporter,
    VaultImporter,
)
from src.core.audit import AuditLogSigner, AuditLogger


def test_native_encrypted_json_format_matches_required_structure(vault_service, unlocked_key_manager):
    vault_service.create_entry(
        {
            "title": "Mail",
            "username": "user@example.com",
            "password": "StrongPass123!",
            "url": "https://example.com",
            "notes": "note",
            "category": "work",
            "tags": "mail",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)

    payload = exporter.export_vault(
        fmt="json",
        protection_mode="password",
        export_password="SharePass123!",
    )
    package = json.loads(payload.decode("utf-8"))

    assert package["version"] == "1.0"
    assert package["cryptosafe_export"] is True
    assert package["timestamp"]
    assert package["encryption"]["algorithm"] == "AES-256-GCM"
    assert package["encryption"]["key_derivation"] == "PBKDF2-SHA256"
    assert package["encryption"]["iterations"] == 100000
    assert package["encryption"]["salt"]
    assert package["encryption"]["nonce"]
    assert package["data"]
    assert package["integrity"]["hash"]
    assert package["integrity"]["signature"]


def test_full_vault_export_uses_separate_encryption_key(vault_service, unlocked_key_manager):
    vault_service.create_entry(
        {
            "title": "Mail",
            "username": "user@example.com",
            "password": "StrongPass123!",
            "url": "https://example.com",
            "notes": "note",
            "category": "work",
            "tags": "mail",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)

    payload = exporter.export_vault(fmt="json", confirmation_password="A_StrongPass123!")
    package = json.loads(payload.decode("utf-8"))

    assert package["cryptosafe_export"] is True
    assert package["version"] == "1.0"
    assert package["encryption"]["algorithm"] == "AES-256-GCM"
    assert package["integrity"]["hash"]
    assert package["integrity"]["signature"]
    assert "user@example.com" not in payload.decode("utf-8")


def test_selective_export_contains_only_requested_entries(vault_service, unlocked_key_manager):
    first = vault_service.create_entry(
        {
            "title": "First",
            "username": "first@example.com",
            "password": "StrongPass123!",
            "url": "https://first.example.com",
            "notes": "first",
            "category": "work",
            "tags": "one",
        }
    )
    second = vault_service.create_entry(
        {
            "title": "Second",
            "username": "second@example.com",
            "password": "StrongPass456!",
            "url": "https://second.example.com",
            "notes": "second",
            "category": "personal",
            "tags": "two",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    importer = VaultImporter(vault_service, unlocked_key_manager)

    payload = exporter.export_vault(fmt="json", entry_ids=[first.id], confirmation_password="A_StrongPass123!")
    result = importer.import_package(payload, import_password="A_StrongPass123!")

    target_id = result.imported_ids[0] if result.imported_ids else result.updated_ids[0]
    imported_entry = vault_service.get_entry(target_id)
    assert len(result.imported_ids) + len(result.updated_ids) == 1
    assert imported_entry.title == "First"
    assert imported_entry.username == "first@example.com"
    assert imported_entry.username != second.username


def test_import_validates_and_sanitizes_entries(vault_service, unlocked_key_manager):
    importer = VaultImporter(vault_service, unlocked_key_manager)
    key = unlocked_key_manager.derive_key("vault-import-export-wrap", 32)

    document = {
        "metadata": {
            "format": "cryptosafe.vault-export.v1",
            "content_format": "json",
            "compressed": False,
        },
        "payload": json.dumps(
            [
                {
                    "title": "  Imported Title  ",
                    "username": " imported-user@example.com ",
                    "password": "StrongPass123!",
                    "url": "https://example.com/imported",
                    "notes": "  notes  ",
                    "category": " imported ",
                    "tags": " a,b ",
                    "ignored": "value",
                }
            ]
        ).encode("utf-8").hex(),
    }
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os
    import hashlib
    import hmac

    export_key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(
        nonce,
        export_key,
        None,
    )
    plaintext = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload_nonce = os.urandom(12)
    payload_ciphertext = AESGCM(export_key).encrypt(payload_nonce, plaintext, None)
    integrity_hash = hashlib.sha256(plaintext).hexdigest()
    package = json.dumps(
        {
            "metadata": {
                "package_format": "cryptosafe.vault-export.encrypted.v1",
                "algorithm": "AES-256-GCM",
                "key_purpose": "vault-import-export-encryption",
                "wrapped_key_mode": "master",
                "integrity_hash": integrity_hash,
                "signature_algorithm": "HMAC-SHA256",
                "signature": hmac.new(export_key, integrity_hash.encode("utf-8"), hashlib.sha256).hexdigest(),
            },
            "wrapped_key": {"mode": "master", "algorithm": "AES-256-GCM", "nonce": nonce.hex(), "wrapped_key": ciphertext.hex()},
            "nonce": payload_nonce.hex(),
            "ciphertext": payload_ciphertext.hex(),
            "outer_auth": {
                "algorithm": "HMAC-SHA256",
                "value": hmac.new(
                    key,
                    json.dumps(
                        {
                            "metadata": {
                                "package_format": "cryptosafe.vault-export.encrypted.v1",
                                "algorithm": "AES-256-GCM",
                                "key_purpose": "vault-import-export-encryption",
                                "wrapped_key_mode": "master",
                                "integrity_hash": integrity_hash,
                                "signature_algorithm": "HMAC-SHA256",
                                "signature": hmac.new(export_key, integrity_hash.encode("utf-8"), hashlib.sha256).hexdigest(),
                            },
                            "nonce": payload_nonce.hex(),
                            "ciphertext": payload_ciphertext.hex(),
                            "wrapped_key": {"mode": "master", "algorithm": "AES-256-GCM", "nonce": nonce.hex(), "wrapped_key": ciphertext.hex()},
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ).encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest(),
            },
        }
    ).encode("utf-8")

    result = importer.import_package(package)
    entry = vault_service.get_entry(result.imported_ids[0])

    assert entry.title == "Imported Title"
    assert entry.username == "imported-user@example.com"
    assert entry.notes == "notes"
    assert entry.category == "imported"


def test_import_rejects_invalid_url(vault_service, unlocked_key_manager):
    importer = VaultImporter(vault_service, unlocked_key_manager)
    key = unlocked_key_manager.derive_key("vault-import-export-wrap", 32)

    document = {
        "metadata": {
            "format": "cryptosafe.vault-export.v1",
            "content_format": "json",
            "compressed": False,
        },
        "payload": json.dumps(
            [
                {
                    "title": "Imported",
                    "username": "user@example.com",
                    "password": "StrongPass123!",
                    "url": "javascript:alert(1)",
                    "notes": "",
                    "category": "",
                    "tags": "",
                }
            ]
        ).encode("utf-8").hex(),
    }
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os
    import hashlib
    import hmac

    export_key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(
        nonce,
        export_key,
        None,
    )
    plaintext = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload_nonce = os.urandom(12)
    payload_ciphertext = AESGCM(export_key).encrypt(payload_nonce, plaintext, None)
    integrity_hash = hashlib.sha256(plaintext).hexdigest()
    package = json.dumps(
        {
            "metadata": {
                "package_format": "cryptosafe.vault-export.encrypted.v1",
                "algorithm": "AES-256-GCM",
                "key_purpose": "vault-import-export-encryption",
                "wrapped_key_mode": "master",
                "integrity_hash": integrity_hash,
                "signature_algorithm": "HMAC-SHA256",
                "signature": hmac.new(export_key, integrity_hash.encode("utf-8"), hashlib.sha256).hexdigest(),
            },
            "wrapped_key": {"mode": "master", "algorithm": "AES-256-GCM", "nonce": nonce.hex(), "wrapped_key": ciphertext.hex()},
            "nonce": payload_nonce.hex(),
            "ciphertext": payload_ciphertext.hex(),
            "outer_auth": {
                "algorithm": "HMAC-SHA256",
                "value": hmac.new(
                    key,
                    json.dumps(
                        {
                            "metadata": {
                                "package_format": "cryptosafe.vault-export.encrypted.v1",
                                "algorithm": "AES-256-GCM",
                                "key_purpose": "vault-import-export-encryption",
                                "wrapped_key_mode": "master",
                                "integrity_hash": integrity_hash,
                                "signature_algorithm": "HMAC-SHA256",
                                "signature": hmac.new(export_key, integrity_hash.encode("utf-8"), hashlib.sha256).hexdigest(),
                            },
                            "nonce": payload_nonce.hex(),
                            "ciphertext": payload_ciphertext.hex(),
                            "wrapped_key": {"mode": "master", "algorithm": "AES-256-GCM", "nonce": nonce.hex(), "wrapped_key": ciphertext.hex()},
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ).encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest(),
            },
        }
    ).encode("utf-8")

    with pytest.raises(ValueError):
        importer.import_package(package)


def test_secure_sharing_round_trip(vault_service, unlocked_key_manager):
    entry = vault_service.create_entry(
        {
            "title": "Shared",
            "username": "share@example.com",
            "password": "StrongPass123!",
            "url": "https://share.example.com",
            "notes": "share",
            "category": "work",
            "tags": "share",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    recipient = KeyExchangeService()
    importer = VaultImporter(vault_service, unlocked_key_manager, key_exchange=recipient)
    sharing = SecureSharingService(exporter, importer=importer, key_exchange=recipient)

    encrypted = sharing.share_entry_with_public_key(
        entry.id,
        recipient.export_public_key(),
        sharer="local-user",
        recipient="recipient-user",
        expires_in_days=7,
        permission="editable",
    )
    result = sharing.receive_shared_entry(encrypted, save_to_vault=True)

    target_id = result.imported_ids[0] if result.imported_ids else result.updated_ids[0]
    imported_entry = vault_service.get_entry(target_id)
    assert b"share@example.com" not in encrypted
    assert imported_entry.username == "share@example.com"


def test_password_shared_entry_supports_preview_without_vault_write(vault_service, unlocked_key_manager):
    entry = vault_service.create_entry(
        {
            "title": "Preview",
            "username": "preview@example.com",
            "password": "StrongPass123!",
            "url": "https://preview.example.com",
            "notes": "top secret",
            "category": "work",
            "tags": "share",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    importer = VaultImporter(vault_service, unlocked_key_manager)
    sharing = SecureSharingService(exporter, importer=importer)
    before = len(vault_service.get_all_entries())

    package = sharing.share_entry_with_password(
        entry.id,
        export_password="SharePass123!",
        sharer="alice",
        recipient="bob",
        expires_in_days=3,
        permission="read-only",
        exclude_fields=["notes"],
    )
    preview = sharing.receive_shared_entry(package, import_password="SharePass123!", save_to_vault=False)
    after = len(vault_service.get_all_entries())

    assert before == after
    assert preview["metadata"]["sharer"] == "alice"
    assert preview["metadata"]["permission"] == "read-only"
    assert preview["preview_entries"][0]["title"] == "Preview"


def test_shared_entry_format_uses_plaintext_metadata_and_minimal_entry_fields(vault_service, unlocked_key_manager):
    entry = vault_service.create_entry(
        {
            "title": "Preview",
            "username": "preview@example.com",
            "password": "StrongPass123!",
            "url": "https://preview.example.com",
            "notes": "top secret",
            "category": "work",
            "tags": "share",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    sharing = SecureSharingService(exporter)

    package = json.loads(
        sharing.share_entry_with_password(
            entry.id,
            export_password="SharePass123!",
            sharer="alice",
            recipient="bob",
            expires_in_days=3,
            permission="read-only",
            exclude_fields=["notes"],
        ).decode("utf-8")
    )

    assert package["metadata"]["format"] == "cryptosafe.shared-entry.v1"
    assert package["metadata"]["sharer"] == "alice"
    assert package["metadata"]["recipient"] == "bob"
    assert package["metadata"]["permission"] == "read-only"
    assert "top secret" not in package["package"]


def test_csv_format_supports_metadata_header_and_round_trip(vault_service, unlocked_key_manager):
    vault_service.create_entry(
        {
            "title": "CSV Title",
            "username": "csv@example.com",
            "password": "StrongPass123!",
            "url": "https://example.com",
            "notes": "line1\nline2",
            "category": "work",
            "tags": "mail",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    importer = VaultImporter(vault_service, unlocked_key_manager)

    payload = exporter.export_vault(fmt="csv", encrypt=False)
    text = payload.decode("utf-8")
    assert text.startswith("# cryptosafe_metadata=")
    result = importer.import_package(payload, format_hint="csv", mode="dry-run")

    assert len(result.preview_entries) == 1
    assert result.preview_entries[0]["title"] == "CSV Title"
    assert result.preview_entries[0]["notes"] == "line1\nline2"


def test_shared_entry_metadata_expiration_and_share_link(vault_service, unlocked_key_manager):
    entry = vault_service.create_entry(
        {
            "title": "Link",
            "username": "link@example.com",
            "password": "StrongPass123!",
            "url": "https://link.example.com",
            "notes": "note",
            "category": "work",
            "tags": "share",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    importer = VaultImporter(vault_service, unlocked_key_manager)
    sharing = SecureSharingService(exporter, importer=importer)

    package = sharing.share_entry_with_password(
        entry.id,
        export_password="SharePass123!",
        sharer="alice",
        recipient="bob",
        expires_in_days=5,
        permission="editable",
    )
    envelope = json.loads(package.decode("utf-8"))
    link = sharing.generate_share_link(package, "https://shares.example.com", expires_in_days=5)

    assert envelope["metadata"]["format"] == "cryptosafe.shared-entry.v1"
    assert envelope["metadata"]["recipient"] == "bob"
    assert envelope["metadata"]["method"] == "password"
    assert envelope["metadata"]["package_hash"]
    assert "/share/" in link


def test_shared_entry_enforces_expiration_bounds_and_expiry(vault_service, unlocked_key_manager):
    entry = vault_service.create_entry(
        {
            "title": "Expire",
            "username": "expire@example.com",
            "password": "StrongPass123!",
            "url": "https://expire.example.com",
            "notes": "note",
            "category": "work",
            "tags": "share",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    importer = VaultImporter(vault_service, unlocked_key_manager)
    sharing = SecureSharingService(exporter, importer=importer)

    with pytest.raises(ValueError):
        sharing.share_entry_with_password(
            entry.id,
            export_password="SharePass123!",
            sharer="alice",
            recipient="bob",
            expires_in_days=31,
        )

    package = sharing.share_entry_with_password(
        entry.id,
        export_password="SharePass123!",
        sharer="alice",
        recipient="bob",
        expires_in_days=1,
    )
    envelope = json.loads(package.decode("utf-8"))
    envelope["metadata"]["expires_at"] = "2000-01-01T00:00:00+00:00"

    with pytest.raises(PermissionError):
        sharing.receive_shared_entry(json.dumps(envelope).encode("utf-8"), import_password="SharePass123!")


def test_export_supports_password_mode_and_gzip_and_field_exclusion(vault_service, unlocked_key_manager):
    entry = vault_service.create_entry(
        {
            "title": "Compressed",
            "username": "gzip@example.com",
            "password": "StrongPass123!",
            "url": "https://gzip.example.com",
            "notes": "remove me",
            "category": "work",
            "tags": "gzip",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    importer = VaultImporter(vault_service, unlocked_key_manager)

    payload = exporter.export_vault(
        fmt="csv",
        entry_ids=[entry.id],
        exclude_fields=["notes"],
        key_bits=128,
        compress=True,
        protection_mode="password",
        export_password="ExportPass123!",
    )
    package = json.loads(payload.decode("utf-8"))
    result = importer.import_package(payload, import_password="ExportPass123!")
    target_id = result.imported_ids[0] if result.imported_ids else result.updated_ids[0]
    imported_entry = vault_service.get_entry(target_id)

    assert package["metadata"]["package_format"] == "cryptosafe.vault-export.encrypted.v1"
    assert package["wrapped_key"]["mode"] == "password"
    assert package["wrapped_key"]["pbkdf2_params"]["iterations"] == 100000
    assert imported_entry.notes == ""
    assert imported_entry.username == "gzip@example.com"


def test_password_manager_json_export_and_audit_logging(test_db, unlocked_key_manager):
    bus = EventBus()
    audit = AuditLogger(test_db, AuditLogSigner(b"test master key material for audit"))
    audit.subscribe(bus)
    from src.core.services.vault_service import VaultService

    vault_service = VaultService(test_db, unlocked_key_manager, event_bus=bus)
    vault_service.create_entry(
        {
            "title": "BW",
            "username": "bw@example.com",
            "password": "StrongPass123!",
            "url": "https://bw.example.com",
            "notes": "note",
            "category": "folder",
            "tags": "tag",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager, event_bus=bus)

    payload = exporter.export_vault(
        fmt="password_manager_json",
        confirmation_password="A_StrongPass123!",
    )
    importer = VaultImporter(vault_service, unlocked_key_manager)
    imported = importer.import_package(payload)
    bus.drain_async(timeout=5)

    with test_db.connection() as conn:
        row = conn.execute(
            "SELECT event_type FROM audit_log WHERE event_type = 'VAULT_DATA_EXPORTED' ORDER BY sequence_number DESC LIMIT 1"
        ).fetchone()

    assert imported.imported_ids or imported.updated_ids
    assert row is not None


def test_export_rejects_missing_master_confirmation(vault_service, unlocked_key_manager):
    vault_service.create_entry(
        {
            "title": "NoConfirm",
            "username": "noconfirm@example.com",
            "password": "StrongPass123!",
            "url": "https://noconfirm.example.com",
            "notes": "note",
            "category": "work",
            "tags": "tag",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)

    with pytest.raises(PermissionError):
        exporter.export_vault(fmt="json")


def test_password_based_sharing_uses_pbkdf2_100000_and_random_salt(vault_service, unlocked_key_manager):
    entry = vault_service.create_entry(
        {
            "title": "PBKDF2",
            "username": "pbkdf2@example.com",
            "password": "StrongPass123!",
            "url": "https://pbkdf2.example.com",
            "notes": "",
            "category": "work",
            "tags": "tag",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)

    payload_a = json.loads(
        exporter.export_vault(
            fmt="json",
            entry_ids=[entry.id],
            protection_mode="password",
            export_password="ExportPass123!",
        ).decode("utf-8")
    )
    payload_b = json.loads(
        exporter.export_vault(
            fmt="json",
            entry_ids=[entry.id],
            protection_mode="password",
            export_password="ExportPass123!",
        ).decode("utf-8")
    )

    assert payload_a["encryption"]["iterations"] == 100000
    assert payload_a["encryption"]["salt"] != payload_b["encryption"]["salt"]
    assert payload_a["encryption"]["algorithm"] == "AES-256-GCM"


def test_public_key_sharing_supports_rsa_oaep_and_sender_public_key(vault_service, unlocked_key_manager):
    entry = vault_service.create_entry(
        {
            "title": "RSA",
            "username": "rsa@example.com",
            "password": "StrongPass123!",
            "url": "https://rsa.example.com",
            "notes": "",
            "category": "work",
            "tags": "tag",
        }
    )
    sender = KeyExchangeService(algorithm="rsa2048")
    recipient = KeyExchangeService(algorithm="rsa2048")
    exporter = VaultExporter(vault_service, unlocked_key_manager, key_exchange=sender)
    importer = VaultImporter(vault_service, unlocked_key_manager, key_exchange=recipient)

    payload = exporter.export_vault(
        fmt="json",
        entry_ids=[entry.id],
        protection_mode="public_key",
        recipient_public_key=recipient.export_public_key(),
    )
    package = json.loads(payload.decode("utf-8"))
    result = importer.import_package(payload)

    assert package["encryption"]["wrapped_key"]
    wrapped_key = json.loads(base64.b64decode(package["encryption"]["wrapped_key"]).decode("utf-8"))
    assert wrapped_key["algorithm"] == "RSA-2048-OAEP+AES-256-GCM"
    assert wrapped_key["sender_public_key"]
    outer_auth = json.loads(base64.b64decode(package["integrity"]["outer_auth"]).decode("utf-8"))
    assert outer_auth["sender_public_key"]
    assert result.imported_ids or result.updated_ids


def test_public_key_sharing_ecies_has_ephemeral_key_and_signature(vault_service, unlocked_key_manager):
    entry = vault_service.create_entry(
        {
            "title": "ECIES",
            "username": "ecies@example.com",
            "password": "StrongPass123!",
            "url": "https://ecies.example.com",
            "notes": "",
            "category": "work",
            "tags": "tag",
        }
    )
    sender = KeyExchangeService(algorithm="p256")
    recipient = KeyExchangeService(algorithm="p256")
    exporter = VaultExporter(vault_service, unlocked_key_manager, key_exchange=sender)

    payload_a = json.loads(
        exporter.export_vault(
            fmt="json",
            entry_ids=[entry.id],
            protection_mode="public_key",
            recipient_public_key=recipient.export_public_key(),
        ).decode("utf-8")
    )
    payload_b = json.loads(
        exporter.export_vault(
            fmt="json",
            entry_ids=[entry.id],
            protection_mode="public_key",
            recipient_public_key=recipient.export_public_key(),
        ).decode("utf-8")
    )

    wrapped_key_a = json.loads(base64.b64decode(payload_a["encryption"]["wrapped_key"]).decode("utf-8"))
    wrapped_key_b = json.loads(base64.b64decode(payload_b["encryption"]["wrapped_key"]).decode("utf-8"))
    outer_auth_a = json.loads(base64.b64decode(payload_a["integrity"]["outer_auth"]).decode("utf-8"))
    assert wrapped_key_a["algorithm"] == "P-256+AES-256-GCM"
    assert wrapped_key_a["ephemeral_public_key"]
    assert wrapped_key_a["ephemeral_public_key"] != wrapped_key_b["ephemeral_public_key"]
    assert outer_auth_a["algorithm"] == "p256-signature"


def test_tamper_evidence_is_verified_before_payload_decryption(vault_service, unlocked_key_manager, monkeypatch):
    entry = vault_service.create_entry(
        {
            "title": "Tamper",
            "username": "tamper@example.com",
            "password": "StrongPass123!",
            "url": "https://tamper.example.com",
            "notes": "",
            "category": "work",
            "tags": "tag",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    importer = VaultImporter(vault_service, unlocked_key_manager)
    payload = json.loads(
        exporter.export_vault(
            fmt="json",
            entry_ids=[entry.id],
            protection_mode="password",
            export_password="ExportPass123!",
        ).decode("utf-8")
    )
    payload["data"] = ("A" if payload["data"][:1] != "A" else "B") + payload["data"][1:]

    original_decrypt = importer._decrypt_document
    calls = {"count": 0}

    def counting_decrypt(*args, **kwargs):
        calls["count"] += 1
        return original_decrypt(*args, **kwargs)

    monkeypatch.setattr(importer, "_decrypt_document", counting_decrypt)

    with pytest.raises(ValueError):
        importer.import_package(json.dumps(payload).encode("utf-8"), import_password="ExportPass123!")

    assert calls["count"] == 0


def test_native_encrypted_json_matches_required_structure(vault_service, unlocked_key_manager):
    vault_service.create_entry(
        {
            "title": "Native",
            "username": "native@example.com",
            "password": "StrongPass123!",
            "url": "https://native.example.com",
            "notes": "note",
            "category": "work",
            "tags": "tag",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    payload = json.loads(
        exporter.export_vault(
            fmt="json",
            protection_mode="password",
            export_password="ExportPass123!",
        ).decode("utf-8")
    )

    assert payload["version"] == "1.0"
    assert payload["cryptosafe_export"] is True
    assert payload["timestamp"].endswith("Z")
    assert payload["encryption"]["algorithm"] == "AES-256-GCM"
    assert payload["encryption"]["key_derivation"] == "PBKDF2-SHA256"
    assert payload["encryption"]["iterations"] == 100000
    assert payload["encryption"]["salt"]
    assert payload["encryption"]["nonce"]
    assert payload["data"]
    assert payload["integrity"]["hash"]
    assert payload["integrity"]["signature"]


def test_csv_export_includes_optional_metadata_header_and_handles_line_breaks(vault_service, unlocked_key_manager):
    vault_service.create_entry(
        {
            "title": "CSV",
            "username": "csv@example.com",
            "password": "StrongPass123!",
            "url": "https://csv.example.com",
            "notes": "line1\nline2,quoted",
            "category": "work",
            "tags": "tag",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    importer = VaultImporter(vault_service, unlocked_key_manager)
    payload = exporter.export_vault(
        fmt="csv",
        encrypt=False,
    )
    text = payload.decode("utf-8")
    result = importer.import_package(payload, mode="dry-run", format_hint="csv")

    assert text.startswith("# cryptosafe_metadata=")
    assert "title,username,password,url,notes,category,tags" in text
    assert result.preview_entries[0]["notes"] == "line1\nline2,quoted"


def test_import_supports_dry_run_without_committing(vault_service, unlocked_key_manager):
    vault_service.create_entry(
        {
            "title": "DryRun",
            "username": "dryrun@example.com",
            "password": "StrongPass123!",
            "url": "https://dryrun.example.com",
            "notes": "original",
            "category": "work",
            "tags": "tag",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    importer = VaultImporter(vault_service, unlocked_key_manager)
    payload = exporter.export_vault(fmt="json", confirmation_password="A_StrongPass123!")
    before = len(vault_service.get_all_entries())

    result = importer.import_package(payload, mode="dry-run")
    after = len(vault_service.get_all_entries())

    assert result.preview_entries
    assert result.mode == "dry-run"
    assert before == after


def test_import_merge_updates_duplicates_and_replace_clears_vault(vault_service, unlocked_key_manager):
    original = vault_service.create_entry(
        {
            "title": "Service",
            "username": "merge@example.com",
            "password": "OldPass123!",
            "url": "https://merge.example.com",
            "notes": "old",
            "category": "work",
            "tags": "old",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    importer = VaultImporter(vault_service, unlocked_key_manager)
    payload = exporter.export_vault(
        fmt="json",
        entry_ids=[original.id],
        confirmation_password="A_StrongPass123!",
    )

    # Update existing in merge mode.
    result = importer.import_package(payload, mode="merge", duplicate_handling="update")
    assert result.updated_ids == [original.id]

    # Replace mode should remove unrelated entries.
    vault_service.create_entry(
        {
            "title": "Second",
            "username": "second@example.com",
            "password": "StrongPass123!",
            "url": "https://second.example.com",
            "notes": "",
            "category": "",
            "tags": "",
        }
    )
    replace_result = importer.import_package(payload, mode="replace")
    entries = vault_service.get_all_entries()

    assert replace_result.imported_ids
    assert len(entries) == 1
    assert entries[0].username == "merge@example.com"


def test_import_supports_bitwarden_json_and_lastpass_csv(vault_service, unlocked_key_manager):
    vault_service.create_entry(
        {
            "title": "Compat",
            "username": "compat@example.com",
            "password": "StrongPass123!",
            "url": "https://compat.example.com",
            "notes": "note",
            "category": "folder",
            "tags": "tag",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    importer = VaultImporter(vault_service, unlocked_key_manager)

    bw_payload = exporter.export_vault(
        fmt="bitwarden_json",
        confirmation_password="A_StrongPass123!",
    )
    lp_payload = exporter.export_vault(
        fmt="lastpass_csv",
        confirmation_password="A_StrongPass123!",
    )

    bw_result = importer.import_package(bw_payload, mode="dry-run")
    lp_result = importer.import_package(lp_payload, mode="dry-run")

    assert bw_result.preview_entries[0]["username"] == "compat@example.com"
    assert lp_result.preview_entries[0]["username"] == "compat@example.com"


def test_import_supports_direct_bitwarden_json_and_lastpass_csv(vault_service, unlocked_key_manager):
    importer = VaultImporter(vault_service, unlocked_key_manager)

    bitwarden_payload = json.dumps(
        {
            "items": [
                {
                    "name": "Direct BW",
                    "login": {
                        "username": "direct-bw@example.com",
                        "password": "StrongPass123!",
                        "uris": [{"uri": "https://bw-direct.example.com"}],
                    },
                    "notes": "bw",
                    "folder": "work",
                    "fields": [{"name": "tags", "value": "tag"}],
                }
            ]
        }
    ).encode("utf-8")
    lastpass_payload = (
        "name,url,username,password,extra,grouping,fav\n"
        "Direct LP,https://lp-direct.example.com,direct-lp@example.com,StrongPass123!,lp,work,tag\n"
    ).encode("utf-8")

    bw_result = importer.import_package(bitwarden_payload, mode="dry-run", format_hint="bitwarden_json")
    lp_result = importer.import_package(lastpass_payload, mode="dry-run", format_hint="lastpass_csv")

    assert bw_result.preview_entries[0]["username"] == "direct-bw@example.com"
    assert lp_result.preview_entries[0]["username"] == "direct-lp@example.com"


def test_query_based_selective_export_uses_vault_service_matches(vault_service, unlocked_key_manager):
    first = vault_service.create_entry(
        {
            "title": "Match Alpha",
            "username": "alpha@example.com",
            "password": "StrongPass123!",
            "url": "https://alpha.example.com",
            "notes": "",
            "category": "work",
            "tags": "team-alpha",
        }
    )
    vault_service.create_entry(
        {
            "title": "Other Beta",
            "username": "beta@example.com",
            "password": "StrongPass123!",
            "url": "https://beta.example.com",
            "notes": "",
            "category": "personal",
            "tags": "team-beta",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    importer = VaultImporter(vault_service, unlocked_key_manager)

    payload = exporter.export_query("alpha", fmt="json", confirmation_password="A_StrongPass123!")
    result = importer.import_package(payload, mode="dry-run")

    assert len(result.preview_entries) == 1
    assert result.preview_entries[0]["title"] == "Match Alpha"


def test_audit_logs_vault_import_and_share_events(test_db, unlocked_key_manager):
    bus = EventBus()
    audit = AuditLogger(test_db, AuditLogSigner(b"test master key material for audit"))
    audit.subscribe(bus)
    bus.publish(VaultDataImported(format="json", entry_count=2, imported_count=1, updated_count=1, mode="merge"))
    bus.publish(EntryShared(entry_id=7, recipient="bob", method="public_key", delivery="qr", permission="editable", expires_in_days=5))
    bus.drain_async(timeout=5)

    with test_db.connection() as conn:
        imported = conn.execute(
            "SELECT event_type FROM audit_log WHERE event_type = 'VAULT_DATA_IMPORTED' ORDER BY sequence_number DESC LIMIT 1"
        ).fetchone()
        shared = conn.execute(
            "SELECT event_type, entry_id FROM audit_log WHERE event_type = 'VAULT_ENTRY_SHARED' ORDER BY sequence_number DESC LIMIT 1"
        ).fetchone()

    assert imported is not None
    assert shared is not None
    assert shared["entry_id"] == 7


def test_import_enforces_size_limit_and_validates_package_before_decrypt(vault_service, unlocked_key_manager):
    importer = VaultImporter(vault_service, unlocked_key_manager, max_file_size_bytes=32)
    with pytest.raises(ValueError):
        importer.import_package(b"x" * 64)

    invalid_package = json.dumps(
        {
            "metadata": {
                "package_format": "cryptosafe.vault-export.encrypted.v1",
                "algorithm": "AES-256-GCM",
            },
            "wrapped_key": {"mode": "master"},
            "nonce": "zzzz",
            "ciphertext": "abcd",
        }
    ).encode("utf-8")

    with pytest.raises(ValueError):
        importer.import_package(invalid_package)


def test_import_timeout_and_script_sanitization(vault_service, unlocked_key_manager, monkeypatch):
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    vault_service.create_entry(
        {
            "title": "Safe",
            "username": "safe@example.com",
            "password": "StrongPass123!",
            "url": "https://safe.example.com",
            "notes": "<script>alert(1)</script>hello",
            "category": "work",
            "tags": "tag",
        }
    )
    payload = exporter.export_vault(fmt="json", confirmation_password="A_StrongPass123!")

    importer = VaultImporter(vault_service, unlocked_key_manager, timeout_seconds=0)
    with pytest.raises(TimeoutError):
        importer.import_package(payload)

    importer = VaultImporter(vault_service, unlocked_key_manager)
    with pytest.raises(ValueError):
        importer.import_package(payload, mode="replace")


def test_export_and_import_wipe_sensitive_buffers(vault_service, unlocked_key_manager, monkeypatch):
    vault_service.create_entry(
        {
            "title": "Wipe",
            "username": "wipe@example.com",
            "password": "StrongPass123!",
            "url": "https://wipe.example.com",
            "notes": "clean",
            "category": "work",
            "tags": "tag",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    importer = VaultImporter(vault_service, unlocked_key_manager)
    export_wipes = {"count": 0}
    import_wipes = {"count": 0}

    original_export_wipe = VaultExporter._wipe_bytes
    original_import_wipe = VaultImporter._wipe_bytes

    def counting_export_wipe(buffer):
        if buffer is not None:
            export_wipes["count"] += 1
        return original_export_wipe(buffer)

    def counting_import_wipe(buffer):
        if buffer is not None:
            import_wipes["count"] += 1
        return original_import_wipe(buffer)

    monkeypatch.setattr(VaultExporter, "_wipe_bytes", staticmethod(counting_export_wipe))
    monkeypatch.setattr(VaultImporter, "_wipe_bytes", staticmethod(counting_import_wipe))

    payload = exporter.export_vault(
        fmt="json",
        protection_mode="password",
        export_password="ExportPass123!",
    )
    importer.import_package(payload, import_password="ExportPass123!", mode="dry-run")

    assert export_wipes["count"] >= 2
    assert import_wipes["count"] >= 2
