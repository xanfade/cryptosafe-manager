from __future__ import annotations

from contextlib import contextmanager

import pytest

from src.core.audit import AuditLogger, AuditLogSigner
from src.core.clipboard.clipboard_service import ClipboardService
from src.core.crypto.authentication import AuthenticationService
from src.core.events import EventBus, PanicModeActivated, SecurityHardeningEvent
from src.core.import_export import VaultExporter, VaultImporter
from src.core.key_manager import KeyManager
from src.core.services.vault_service import VaultService
from src.core.state_manager import StateManager
from src.core.vault.encryption_service import VaultEncryptionService


class FakeClipboardAdapter:
    def __init__(self):
        self.value = ""

    def set_text(self, value: str):
        self.value = value

    def get_text(self) -> str:
        return self.value

    def clear(self):
        self.value = ""


class RecordingGuard:
    def __init__(self):
        self.calls = 0

    @contextmanager
    def scoped_buffer(self, payload, critical: bool = False):
        self.calls += 1
        class _Buf:
            def __init__(self, data):
                self._data = bytes(data)

            def to_bytes(self):
                return self._data
        yield _Buf(payload)


def _login(test_db) -> tuple[KeyManager, AuthenticationService]:
    km = KeyManager(test_db)
    km.initialize_master_password("StrongPass123!")
    auth = AuthenticationService(km, StateManager())
    auth.login("StrongPass123!")
    return km, auth


def test_int1_vault_memory_guard_and_constant_time_search(test_db):
    km, _auth = _login(test_db)
    guard = RecordingGuard()
    crypto = VaultEncryptionService(km, memory_guard=guard)
    payload = {
        "title": "Email",
        "username": "user@example.com",
        "password": "P@ssw0rd!",
        "url": "https://example.com",
        "notes": "alpha beta",
        "category": "work",
    }
    encrypted = crypto.encrypt_entry_payload(payload)
    decrypted = crypto.decrypt_entry_payload(encrypted)
    assert decrypted["title"] == "Email"
    assert guard.calls >= 2

    service = VaultService(test_db, km)
    entry = service.create_entry(payload | {"title": "Github", "notes": "security token"})
    matches = service.find_entries("secur")
    assert any(item.id == entry.id for item in matches)


def test_int2_clipboard_panic_mode_clear():
    bus = EventBus()
    adapter = FakeClipboardAdapter()
    service = ClipboardService(adapter=adapter, event_bus=bus, clear_after_seconds=None)
    service.bind_panic_mode(bus)
    service.copy_text("super-secret")
    assert adapter.get_text() == "super-secret"
    bus.publish(PanicModeActivated(reason="hotkey"))
    assert adapter.get_text() == ""
    assert service.has_active_secret() is False


def test_int3_audit_logs_hardening_events(test_db):
    km, _auth = _login(test_db)
    signer = AuditLogSigner.from_key_manager(km)
    bus = EventBus()
    logger = AuditLogger(test_db, signer)
    logger.subscribe(bus)
    bus.publish(SecurityHardeningEvent(action="profile_apply", profile="enhanced", status="ok"))

    with test_db.connection() as conn:
        row = conn.execute(
            """
            SELECT event_type, source
            FROM audit_log
            WHERE event_type = 'SECURITY_HARDENING_EVENT'
            ORDER BY sequence_number DESC
            LIMIT 1
            """
        ).fetchone()
    assert row is not None
    assert row["source"] == "security"


def test_int4_import_export_panic_interruption(test_db):
    km, _auth = _login(test_db)
    vault_service = VaultService(test_db, km)
    vault_service.create_entry(
        {
            "title": "Entry 1",
            "username": "u1",
            "password": "StrongPass123!",
            "url": "https://example.com",
            "notes": "",
            "category": "general",
            "tags": "",
        }
    )

    exporter = VaultExporter(vault_service, km, panic_checker=lambda: True)
    with pytest.raises(RuntimeError, match="panic mode"):
        exporter.export_vault(fmt="json")

    importer = VaultImporter(vault_service, km, panic_checker=lambda: True)
    with pytest.raises(RuntimeError, match="panic mode"):
        importer.import_package(b"[]", mode="dry-run")
