import base64
import json
import time
import tracemalloc

import cv2
import pytest

from src.core.import_export import (
    KeyExchangeService,
    QrPayloadService,
    SecureSharingService,
    VaultExporter,
    VaultImporter,
)


def _make_entry(index: int) -> dict:
    return {
        "title": f"Entry {index}",
        "username": f"user{index}@example.com",
        "password": f"StrongPass{index:04d}!",
        "url": f"https://example.com/{index}",
        "notes": f"note {index}",
        "category": "work" if index % 2 == 0 else "personal",
        "tags": f"tag-{index}",
    }


def test_round_trip_export_import_all_formats_preserves_core_data(vault_service, unlocked_key_manager):
    cases = [
        ("json", {"confirmation_password": "A_StrongPass123!"}),
        ("csv", {"protection_mode": "password", "export_password": "ExportPass123!"}),
        ("bitwarden_json", {"confirmation_password": "A_StrongPass123!"}),
        ("lastpass_csv", {"confirmation_password": "A_StrongPass123!"}),
    ]

    for index, (fmt, export_kwargs) in enumerate(cases, start=1):
        source = vault_service.create_entry(_make_entry(index))
        exporter = VaultExporter(vault_service, unlocked_key_manager)
        importer = VaultImporter(vault_service, unlocked_key_manager)
        payload = exporter.export_vault(fmt=fmt, entry_ids=[source.id], **export_kwargs)
        result = importer.import_package(
            payload,
            import_password=export_kwargs.get("confirmation_password") or export_kwargs.get("export_password"),
            mode="replace",
        )
        imported = vault_service.get_entry(result.imported_ids[0] if result.imported_ids else result.updated_ids[0])
        assert imported.title == source.title
        assert imported.username == source.username
        assert imported.password == source.password
        assert imported.url == source.url


def test_interoperability_import_and_export_for_bitwarden_and_lastpass(vault_service, unlocked_key_manager):
    importer = VaultImporter(vault_service, unlocked_key_manager)
    exporter = VaultExporter(vault_service, unlocked_key_manager)

    bitwarden_payload = json.dumps(
        {
            "items": [
                {
                    "name": "BW Import",
                    "login": {
                        "username": "bw@example.com",
                        "password": "StrongPass123!",
                        "uris": [{"uri": "https://bw.example.com"}],
                    },
                    "notes": "bitwarden",
                    "folder": "work",
                    "fields": [{"name": "tags", "value": "tag"}],
                }
            ]
        }
    ).encode("utf-8")
    lastpass_payload = (
        "name,url,username,password,extra,grouping,fav\n"
        "LP Import,https://lp.example.com,lp@example.com,StrongPass123!,lastpass,work,tag\n"
    ).encode("utf-8")

    bw_result = importer.import_package(bitwarden_payload, mode="merge", format_hint="bitwarden_json")
    lp_result = importer.import_package(lastpass_payload, mode="merge", format_hint="lastpass_csv")
    assert bw_result.imported_ids
    assert lp_result.imported_ids

    bw_export = exporter.export_vault(fmt="bitwarden_json", confirmation_password="A_StrongPass123!")
    lp_export = exporter.export_vault(fmt="lastpass_csv", confirmation_password="A_StrongPass123!")
    bw_preview = importer.import_package(bw_export, mode="dry-run")
    lp_preview = importer.import_package(lp_export, mode="dry-run")

    assert any(item["username"] == "bw@example.com" for item in bw_preview.preview_entries)
    assert any(item["username"] == "lp@example.com" for item in lp_preview.preview_entries)


def test_sharing_security_all_methods_detect_tampering(vault_service, unlocked_key_manager):
    entry = vault_service.create_entry(_make_entry(7))
    exporter = VaultExporter(vault_service, unlocked_key_manager)
    recipient = KeyExchangeService(algorithm="p256")
    importer = VaultImporter(vault_service, unlocked_key_manager, key_exchange=recipient)
    sharing = SecureSharingService(exporter, importer=importer, key_exchange=recipient)

    password_payload = json.loads(
        sharing.share_entry_with_password(
            entry.id,
            export_password="SharePass123!",
            sharer="alice",
            recipient="bob",
            permission="read-only",
        ).decode("utf-8")
    )
    password_payload["package"] = password_payload["package"][:-1] + ("0" if password_payload["package"][-1] != "0" else "1")
    with pytest.raises(Exception):
        sharing.receive_shared_entry(json.dumps(password_payload).encode("utf-8"), import_password="SharePass123!")

    public_payload = json.loads(
        sharing.share_entry_with_public_key(
            entry.id,
            recipient.export_public_key(),
            sharer="alice",
            recipient="bob",
            permission="editable",
        ).decode("utf-8")
    )
    package = json.loads(public_payload["package"])
    package["data"] = ("A" if package["data"][:1] != "A" else "B") + package["data"][1:]
    public_payload["package"] = json.dumps(package)
    with pytest.raises(Exception):
        sharing.receive_shared_entry(json.dumps(public_payload).encode("utf-8"))

    link = sharing.generate_share_link(
        sharing.share_entry_with_password(
            entry.id,
            export_password="SharePass123!",
            sharer="alice",
            recipient="bob",
        ),
        "https://shares.example.com",
        expires_in_days=2,
    )
    token = link.split("/share/", 1)[1]
    padded = token + "=" * (-len(token) % 4)
    envelope = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    tampered_token = base64.urlsafe_b64encode((envelope[:-1] + ("0" if envelope[-1] != "0" else "1")).encode("utf-8")).decode("ascii").rstrip("=")
    tampered_padded = tampered_token + "=" * (-len(tampered_token) % 4)
    with pytest.raises(Exception):
        sharing.receive_shared_entry(base64.urlsafe_b64decode(tampered_padded.encode("ascii")), import_password="SharePass123!")


def test_qr_camera_style_round_trip_for_1kb_payload(tmp_path):
    qr = QrPayloadService(chunk_size=700)
    payload = b"x" * 1024
    chunks = qr.build_chunks("encrypted_entry", payload)
    images = qr.render_qr_images(chunks, box_size=12, border=6)
    paths = []
    for index, image in enumerate(images, start=1):
        path = tmp_path / f"camera-frame-{index}.png"
        paths.append(str(path))
        qr.save_qr_images([image], [str(path)])

    payload_type, rebuilt = qr.decode_qr_images(paths)
    assert payload_type == "encrypted_entry"
    assert rebuilt == payload


def test_import_export_performance_1000_entries_measures_time_and_memory(vault_service, unlocked_key_manager):
    for index in range(1000):
        vault_service.create_entry(_make_entry(index))

    exporter = VaultExporter(vault_service, unlocked_key_manager)
    importer = VaultImporter(vault_service, unlocked_key_manager)

    tracemalloc.start()
    started_at = time.perf_counter()
    payload = exporter.export_vault(fmt="json", confirmation_password="A_StrongPass123!")
    export_elapsed = time.perf_counter() - started_at

    started_at = time.perf_counter()
    preview = importer.import_package(payload, mode="dry-run")
    import_elapsed = time.perf_counter() - started_at
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert len(preview.preview_entries) == 1000
    assert export_elapsed < 5.0
    assert import_elapsed < 10.0
    assert peak < 50 * 1024 * 1024
