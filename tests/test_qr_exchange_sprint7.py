import json
from datetime import datetime, timedelta, timezone

import pytest

from src.core.import_export import KeyExchangeService, QrPayloadService, SecureSharingService, VaultExporter, VaultImporter


def test_qr_image_file_upload_round_trip_for_share_link(tmp_path):
    qr = QrPayloadService(chunk_size=4096)
    bundle = b"https://shares.local/share/test-token"

    chunks = qr.build_chunks("share_link", bundle)
    images = qr.render_qr_images(chunks)
    paths = []
    for index, image in enumerate(images, start=1):
        path = tmp_path / f"pubkey-{index}.png"
        paths.append(str(path))
    qr.save_qr_images(images, paths)

    payload_type, payload = qr.decode_qr_images(paths)

    assert payload_type == "share_link"
    assert payload == bundle


def test_qr_chunking_for_large_payload_and_checksum_validation():
    qr = QrPayloadService(chunk_size=128)
    payload = ("x" * 3000).encode("utf-8")

    chunks = qr.build_chunks("encrypted_entry", payload)
    payload_type, rebuilt = qr.reassemble_chunks(chunks)

    assert len(chunks) > 1
    assert payload_type == "encrypted_entry"
    assert rebuilt == payload

    tampered = [dict(item) for item in chunks]
    tampered[0]["payload"] = tampered[0]["payload"][:-2] + "aa"
    with pytest.raises(ValueError):
        qr.reassemble_chunks(tampered)


def test_qr_expiration_is_enforced():
    qr = QrPayloadService(validity_seconds=60)
    chunks = qr.build_chunks("share_link", b"https://share.local/x")
    chunks[0]["expires_at"] = "2000-01-01T00:00:00+00:00"

    with pytest.raises(PermissionError):
        qr.reassemble_chunks(chunks)


def test_p256_contact_storage_verification_revocation_and_rotation(test_db):
    local = KeyExchangeService.from_database(test_db, algorithm="p256")
    remote = KeyExchangeService(algorithm="p256")
    bundle = remote.export_public_bundle(owner="bob")

    local.store_contact("bob", bundle)
    contacts = local.list_contacts()

    assert contacts["bob"]["verified"] is False
    assert local.verify_contact_fingerprint("bob", bundle["fingerprint"]) is True

    contacts = local.list_contacts()
    assert contacts["bob"]["verified"] is True

    local.revoke_contact("bob")
    contacts = local.list_contacts()
    assert contacts["bob"]["revoked"] is True

    old_fingerprint = local.export_public_bundle(owner="local")["fingerprint"]
    new_bundle = local.rotate_identity("p256")
    assert new_bundle["fingerprint"] != old_fingerprint


def test_shared_entry_qr_preview_and_save_flow(vault_service, unlocked_key_manager):
    entry = vault_service.create_entry(
        {
            "title": "QR Shared",
            "username": "qr@example.com",
            "password": "StrongPass123!",
            "url": "https://qr.example.com",
            "notes": "note",
            "category": "work",
            "tags": "tag",
        }
    )
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    recipient = KeyExchangeService(algorithm="p256")
    importer = VaultImporter(vault_service, unlocked_key_manager, key_exchange=recipient)
    sharing = SecureSharingService(exporter, importer=importer, key_exchange=recipient)
    qr = QrPayloadService()

    shared_package = sharing.share_entry_with_public_key(
        entry.id,
        recipient.export_public_key(),
        sharer="alice",
        recipient="bob",
        expires_in_days=2,
        permission="editable",
    )
    chunks = qr.build_chunks("encrypted_entry", shared_package)
    payload_type, payload = qr.reassemble_chunks(chunks)

    preview = sharing.receive_shared_entry(payload, save_to_vault=False)
    saved = sharing.receive_shared_entry(payload, save_to_vault=True)

    assert payload_type == "encrypted_entry"
    assert preview["metadata"]["permission"] == "editable"
    assert preview["preview_entries"][0]["username"] == "qr@example.com"
    assert saved.imported_ids or saved.updated_ids
