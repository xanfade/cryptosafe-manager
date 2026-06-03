from src.core.crypto.authentication import AuthenticationService
from src.core.crypto.key_storage import SecureKeyCache
from src.core.events import EventBus, PanicModeActivated
from src.core.key_manager import KeyManager
from src.core.security import ActivityMonitor, MemoryGuard, PanicMode, SecurityHardeningSettings, SecurityProfileManager
from src.core.security.profile_manager import build_profile
from src.core.security.side_channel_protection import constant_time_compare_str
from src.core.settings_repo import SettingsService
from src.core.state_manager import StateManager


def test_hardening_settings_secure_defaults(test_db):
    raw_key = b"x" * 32
    fernet_key = SettingsService.build_fernet_key(raw_key)
    settings = SettingsService(test_db, fernet_key)

    cfg = SecurityHardeningSettings.from_settings(settings)

    assert cfg.enabled is True
    assert cfg.constant_time_compare is True
    assert cfg.memory_locking is True
    assert cfg.memory_auto_wipe is True
    assert cfg.activity_monitor_enabled is True
    assert cfg.auto_lock_timeout_sec == 300
    assert cfg.panic_mode_enabled is True


def test_hardening_settings_backward_compatible_timeout_key(test_db):
    raw_key = b"y" * 32
    fernet_key = SettingsService.build_fernet_key(raw_key)
    settings = SettingsService(test_db, fernet_key)
    settings.set("security.auto_lock_timeout_sec", "120", encrypted=False)

    cfg = SecurityHardeningSettings.from_settings(settings)
    assert cfg.auto_lock_timeout_sec == 120


def test_auth_uses_activity_monitor_for_auto_lock(test_db):
    km = KeyManager(test_db)
    km.initialize_master_password("StrongPass123!")

    state = StateManager()
    monitor = ActivityMonitor(enabled=True, auto_lock_timeout_sec=60)
    auth = AuthenticationService(km, state, activity_monitor=monitor)
    auth.login("StrongPass123!")

    monitor.last_activity_at -= 120
    assert auth.should_auto_lock() is True


def test_panic_mode_triggers_logout_and_callback(test_db):
    km = KeyManager(test_db)
    km.initialize_master_password("StrongPass123!")

    state = StateManager()
    auth = AuthenticationService(km, state, panic_mode=PanicMode(enabled=True))
    auth.login("StrongPass123!")

    marker = {"cleared": False}

    def clear_clipboard():
        marker["cleared"] = True

    assert auth.activate_panic_mode(clear_clipboard_callback=clear_clipboard, reason="hotkey") is True
    assert marker["cleared"] is True
    assert auth.is_unlocked() is False


def test_panic_mode_emits_event_once(test_db):
    km = KeyManager(test_db)
    km.initialize_master_password("StrongPass123!")
    state = StateManager()
    bus = EventBus()
    auth = AuthenticationService(km, state, event_bus=bus, panic_mode=PanicMode(enabled=True))
    auth.login("StrongPass123!")

    events = []
    bus.subscribe(PanicModeActivated, lambda e: events.append(e))
    auth.activate_panic_mode(reason="tray")
    assert len(events) == 1
    assert events[0].reason == "tray"


def test_constant_time_compare_str():
    assert constant_time_compare_str("secure-fp-1", "secure-fp-1") is True
    assert constant_time_compare_str("secure-fp-1", "secure-fp-2") is False


def test_memory_guard_allocate_and_wipe():
    guard = MemoryGuard(enable_locking=False)
    buf = guard.allocate(b"secret", critical=True)
    assert buf.to_bytes() == b"secret"
    guard.wipe(buf, critical=True)


def test_secure_key_cache_uses_guarded_buffers():
    cache = SecureKeyCache(ttl_seconds=60, memory_guard=MemoryGuard(enable_locking=False))
    cache.put(b"\x01" * 32)
    key = cache.get()
    assert key == b"\x01" * 32
    cache.clear()
    assert cache.get() is None


def test_activity_monitor_timeout_bounds_and_profiles():
    monitor = ActivityMonitor(auto_lock_timeout_sec=5, sensitivity="high", device_type="laptop")
    assert monitor.auto_lock_timeout_sec == 60
    assert 60 <= monitor.get_effective_timeout_sec() <= 28800

    monitor.configure(auto_lock_timeout_sec=999999, sensitivity="low", device_type="desktop")
    assert monitor.auto_lock_timeout_sec == 28800
    assert monitor.sensitivity == "low"
    assert monitor.device_type == "desktop"


def test_verify_session_integrity(test_db):
    km = KeyManager(test_db)
    km.initialize_master_password("StrongPass123!")
    auth = AuthenticationService(km, StateManager())
    assert auth.verify_session_integrity() is True
    auth.login("StrongPass123!")
    assert auth.verify_session_integrity() is True
    auth.state.lock()
    assert auth.verify_session_integrity() is False


def test_security_profile_defaults_and_switch(test_db):
    settings = SettingsService(test_db, SettingsService.build_fernet_key(b"z" * 32))
    mgr = SecurityProfileManager(settings)
    assert mgr.get_active_profile() == "standard"

    changes = mgr.preview_profile_change("enhanced")
    assert any(item["key"] == "security.hardening.activity_monitor.auto_lock_timeout_sec" for item in changes)

    result = mgr.apply_profile("enhanced")
    assert result.success is True
    assert settings.get(SecurityProfileManager.ACTIVE_PROFILE_KEY) == "enhanced"


def test_security_profile_migration_rollback_on_failure(test_db):
    settings = SettingsService(test_db, SettingsService.build_fernet_key(b"w" * 32))
    settings.set("security.hardening.activity_monitor.auto_lock_timeout_sec", "123", encrypted=False)

    mgr = SecurityProfileManager(settings)
    original_set_many = settings.set_many

    def _boom(_values, encrypted=False):
        raise RuntimeError("boom")

    settings.set_many = _boom
    result = mgr.apply_profile("paranoid")
    settings.set_many = original_set_many

    assert result.success is False
    assert "rolled back" in result.errors[0].lower()
    assert settings.get("security.hardening.activity_monitor.auto_lock_timeout_sec") == "123"


def test_hardening_validation_blocks_insecure_combination():
    cfg = SecurityHardeningSettings(
        enabled=True,
        constant_time_compare=False,
        normalize_auth_timing=False,
        memory_locking=False,
        memory_auto_wipe=False,
        activity_monitor_enabled=False,
        panic_mode_enabled=False,
    )
    errors, _warnings = cfg.validate()
    assert any("defense in depth" in e.lower() for e in errors)


def test_hardening_validation_disallows_disabling_hardening():
    cfg = SecurityHardeningSettings(enabled=False)
    errors, _warnings = cfg.validate()
    assert any("cannot be disabled" in e.lower() for e in errors)


def test_build_profile_paranoid_validates():
    cfg = build_profile("paranoid")
    errors, _warnings = cfg.validate()
    assert errors == []


def test_profile_manager_fail_secure_uses_paranoid(test_db):
    settings = SettingsService(test_db, SettingsService.build_fernet_key(b"p" * 32))
    mgr = SecurityProfileManager(settings)
    result = mgr.apply_profile("paranoid")
    assert result.success is True
    assert settings.get(SecurityProfileManager.ACTIVE_PROFILE_KEY) == "paranoid"


def test_auto_lock_on_session_integrity_mismatch(test_db):
    km = KeyManager(test_db)
    km.initialize_master_password("StrongPass123!")
    auth = AuthenticationService(km, StateManager())
    auth.login("StrongPass123!")
    auth.state.lock()  # mismatched: cache still present while state says locked
    assert auth.should_auto_lock() is True
