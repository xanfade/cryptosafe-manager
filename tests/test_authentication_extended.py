import time

import pytest

from src.core.crypto.authentication import AuthenticationService, validate_password_strength
from src.core.events import EventBus, LoginFailed, PanicModeActivated
from src.core.security.activity_monitor import ActivityMonitor
from src.core.security.panic_mode import PanicMode
from src.core.state_manager import StateManager


def test_validate_password_strength_rejects_weak_variants():
    weak_passwords = [
        "short1!A",
        "alllowercase123!",
        "ALLUPPERCASE123!",
        "NoDigitsHere!!",
        "NoSpecial12345",
    ]

    for password in weak_passwords:
        with pytest.raises(ValueError):
            validate_password_strength(password)


def test_validate_password_strength_accepts_strong_password():
    validate_password_strength("ValidStrong123!")


def test_authentication_failure_publishes_event_and_increments_attempts(key_manager, monkeypatch):
    events = []
    event_bus = EventBus()
    event_bus.subscribe(LoginFailed, lambda event: events.append(event), async_=False)
    service = AuthenticationService(key_manager, StateManager(), event_bus=event_bus)

    monkeypatch.setattr("src.core.crypto.authentication.time.sleep", lambda _seconds: None)

    with pytest.raises(ValueError):
        service.login("wrong-password")

    assert service.state.session.failed_attempts == 1
    assert len(events) == 1
    assert events[0].delay_seconds == 1


def test_authentication_touch_and_auto_lock_flow(key_manager, auth_service):
    auth_service.login("A_StrongPass123!")
    assert auth_service.is_unlocked() is True

    auth_service.touch()
    assert key_manager.has_cached_key() is True

    auth_service.auto_lock("manual_test")
    assert auth_service.is_unlocked() is False
    assert key_manager.has_cached_key() is False


def test_authentication_focus_and_minimize_hooks_respect_cache_flags(key_manager, auth_service):
    auth_service.login("A_StrongPass123!")
    key_manager.cache.clear_on_focus_loss = False
    key_manager.cache.clear_on_minimize = False

    auth_service.on_app_focus_lost()
    assert auth_service.is_unlocked() is True

    auth_service.on_app_minimized()
    assert auth_service.is_unlocked() is True


def test_authentication_check_auto_lock_uses_activity_monitor(key_manager):
    monitor = ActivityMonitor(enabled=True, auto_lock_timeout_sec=60)
    state = StateManager()
    state.set_inactivity_timeout(None)
    service = AuthenticationService(key_manager, state, activity_monitor=monitor)
    service.login("A_StrongPass123!")

    monitor.last_activity_at = time.time() - 120

    assert service.check_auto_lock() is True
    assert service.is_unlocked() is False


def test_authentication_activate_panic_mode_publishes_event(key_manager):
    bus = EventBus()
    captured = []
    bus.subscribe(PanicModeActivated, lambda event: captured.append(event), async_=False)
    service = AuthenticationService(
        key_manager,
        StateManager(),
        event_bus=bus,
        panic_mode=PanicMode(enabled=True),
    )
    service.login("A_StrongPass123!")

    assert service.activate_panic_mode(reason="unit_test") is True
    assert service.is_unlocked() is False
    assert captured and captured[0].reason == "unit_test"
