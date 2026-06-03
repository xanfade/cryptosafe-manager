import base64
import json
import threading

from src.core.clipboard.clipboard_monitor import ClipboardMonitor
from src.core.clipboard.clipboard_service import ClipboardDataType, ClipboardService
from src.core.clipboard.clipboard_settings import ClipboardSettings, ClipboardSettingsRepository, normalize_application_id


class DummyAdapter:
    def __init__(self):
        self.value = ""
        self.cleared = False
        self.active_app = ""

    def set_text(self, value):
        self.value = value

    def get_text(self):
        return self.value

    def clear(self):
        self.cleared = True
        self.value = ""

    def active_application_id(self):
        return self.active_app


class DummyEventBus:
    def __init__(self):
        self.events = []

    def publish(self, event):
        self.events.append(event)

    def subscribe(self, *_args, **_kwargs):
        return None


class FakeTimer:
    def __init__(self, interval, callback):
        self.interval = interval
        self.callback = callback
        self.daemon = False
        self.started = False
        self.cancelled = False

    def start(self):
        self.started = True

    def cancel(self):
        self.cancelled = True


def test_clipboard_service_copy_schedule_and_clear(monkeypatch):
    adapter = DummyAdapter()
    bus = DummyEventBus()
    timers = []

    monkeypatch.setattr(
        "src.core.clipboard.clipboard_service.threading.Timer",
        lambda interval, callback: timers.append(FakeTimer(interval, callback)) or timers[-1],
    )

    service = ClipboardService(adapter=adapter, event_bus=bus, clear_after_seconds=10, is_unlocked_callback=lambda: True)
    observed = []
    service.subscribe(observed.append)

    service.copy_text(" secret ", entry_id=7)
    assert adapter.value == "secret"
    assert service.has_active_secret() is True
    assert observed[-1] == "copied"
    assert timers[-1].started is True

    service.schedule_clear()
    assert observed[-1] == "scheduled"

    service.clear()
    assert adapter.cleared is True
    assert service.has_active_secret() is False
    assert observed[-1] == "cleared"


def test_clipboard_service_validates_totp_and_blob():
    adapter = DummyAdapter()
    service = ClipboardService(adapter=adapter, event_bus=DummyEventBus(), clear_after_seconds=None)

    service.copy_totp("123456")
    assert service.get_content_type() == ClipboardDataType.TOTP

    service.copy_encrypted_blob(b"\xAA\xBB")
    assert adapter.value == "aabb"
    assert service.get_content_type() == ClipboardDataType.ENCRYPTED_BLOB


def test_clipboard_service_blocks_and_handles_suspicious_activity(monkeypatch):
    adapter = DummyAdapter()
    service = ClipboardService(adapter=adapter, event_bus=DummyEventBus(), clear_after_seconds=None, is_unlocked_callback=lambda: True)
    events = []
    service.subscribe(events.append)
    service.security_level = "paranoid"

    service.copy_text("value")
    service.report_suspicious_activity("external_change")

    assert service.is_blocked() is True
    assert "suspicious" in events
    assert "copy_blocked" in events


def test_clipboard_settings_normalization_and_repository_roundtrip(test_db, unlocked_key_manager):
    repo = ClipboardSettingsRepository(test_db, unlocked_key_manager)
    settings = ClipboardSettings(
        auto_clear_timeout_sec=1,
        notifications_enabled=False,
        security_level="invalid",
        allowed_applications_whitelist=[" C:\\Program Files\\App\\Tool.EXE ", "", "notes.app"],
    )
    saved = repo.save(settings)
    loaded = repo.get()

    assert saved.auto_clear_timeout_sec == 5
    assert loaded.notifications_enabled is False
    assert loaded.security_level == "advanced"
    assert loaded.allowed_applications_whitelist == ["tool.exe", "notes.app"]


def test_clipboard_settings_repository_falls_back_on_invalid_payload(test_db, unlocked_key_manager):
    repo = ClipboardSettingsRepository(test_db, unlocked_key_manager)
    test_db.set_setting("clipboard.settings", base64.b64encode(b"not-encrypted-json").decode("utf-8"), encrypted=1)

    loaded = repo.get()

    assert loaded.auto_clear_timeout_sec is None
    assert loaded.notifications_enabled is True


def test_normalize_application_id_keeps_executable_name():
    assert normalize_application_id(' "C:\\Program Files\\My App\\App.EXE" ') == "app.exe"
    assert normalize_application_id("/Applications/Notes.app/") == "notes.app"


def test_clipboard_monitor_reports_only_unexpected_external_change(monkeypatch):
    adapter = DummyAdapter()
    adapter.value = "changed"
    adapter.active_app = "blocked.exe"
    service = ClipboardService(adapter=adapter, event_bus=DummyEventBus(), clear_after_seconds=None)
    reported = []
    service.report_suspicious_activity = lambda reason: reported.append(reason)
    service.is_expected_value = lambda value: False
    service.is_application_allowed = lambda app: False
    service.has_active_secret = lambda: True

    monitor = ClipboardMonitor(service, interval=0)
    original_sleep = threading.Event()

    def fake_sleep(_interval):
        monitor._running = False
        original_sleep.set()

    monkeypatch.setattr("src.core.clipboard.clipboard_monitor.time.sleep", fake_sleep)
    monitor._running = True
    monitor._loop()

    assert reported == ["clipboard_changed_outside_application"]
