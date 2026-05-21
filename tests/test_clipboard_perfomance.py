import os
import sqlite3
import tempfile

from src.core.clipboard.clipboard_service import (
    ClipboardService,
    ClipboardDataType,
)


class FakeClipboardAdapter:
    def __init__(self):
        self.value = ""
        self.set_calls = 0
        self.get_calls = 0
        self.clear_calls = 0

    def set_text(self, value: str) -> None:
        self.set_calls += 1
        self.value = value

    def get_text(self) -> str:
        self.get_calls += 1
        return self.value

    def clear(self) -> None:
        self.clear_calls += 1
        self.value = ""


class FakeEventBus:
    def __init__(self):
        self.events = []

    def publish(self, event):
        self.events.append(event)


def make_service():
    adapter = FakeClipboardAdapter()
    event_bus = FakeEventBus()

    service = ClipboardService(
        adapter=adapter,
        event_bus=event_bus,
        clear_after_seconds=None,
        is_unlocked_callback=lambda: True,
    )

    return service, adapter, event_bus


def test_sec1_clipboard_secret_is_not_written_to_database_file():
    service, adapter, event_bus = make_service()

    secret = "SUPER_SECRET_PASSWORD_123456"

    fd, db_path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)

    try:
        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE settings (id INTEGER PRIMARY KEY, setting_key TEXT, setting_value TEXT)"
        )
        conn.execute(
            "INSERT INTO settings(setting_key, setting_value) VALUES (?, ?)",
            ("clipboard.clear_timeout_sec", "30"),
        )
        conn.commit()
        conn.close()

        service.copy_secret(secret, entry_id=1)

        with open(db_path, "rb") as file:
            raw = file.read()

        assert secret.encode("utf-8") not in raw

    finally:
        os.remove(db_path)


def test_sec2_service_does_not_expose_expected_plaintext_value():
    service, adapter, event_bus = make_service()

    secret = "my-private-password"

    service.copy_secret(secret, entry_id=1)

    assert service.get_expected_value() == ""
    assert service._content is not None
    assert service._content.expected_hash != secret


def test_sec3_clipboard_clears_immediately_on_lock():
    service, adapter, event_bus = make_service()

    service.copy_secret("password-to-clear", entry_id=1)

    assert adapter.value == "password-to-clear"

    service.clear_on_lock()

    assert adapter.value == ""
    assert service.has_active_secret() is False


def test_sec4_rejects_empty_clipboard_value():
    service, adapter, event_bus = make_service()

    service.copy_secret("", entry_id=1)

    assert adapter.value == ""
    assert service.has_active_secret() is False


def test_sec4_sanitizes_null_bytes():
    service, adapter, event_bus = make_service()

    service.copy_secret("abc\x00def", entry_id=1)

    assert adapter.value == "abcdef"


def test_sec4_validates_totp_format():
    service, adapter, event_bus = make_service()

    service.copy_totp("123456", entry_id=1)

    assert adapter.value == "123456"

    service.copy_totp("12ab56", entry_id=1)

    assert adapter.value == "123456"


def test_sec4_validates_encrypted_blob_must_be_bytes():
    service, adapter, event_bus = make_service()

    service.copy_secret(
        value="not-bytes",
        entry_id=1,
        data_type=ClipboardDataType.ENCRYPTED_BLOB,
    )

    assert adapter.value == ""
    assert service.has_active_secret() is False