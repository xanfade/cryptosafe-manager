from __future__ import annotations

import re
import time

from src.core.crypto.key_derivation import derive_encryption_key, verify_auth_hash
from src.core.events import (
    AppFocusGained,
    AppFocusLost,
    AppMinimized,
    AppRestored,
    AutoLocked,
    EventBus,
    LoginFailed,
    PanicModeActivated,
    UserLoggedIn,
    UserLoggedOut,
)
from src.core.security.activity_monitor import ActivityMonitor
from src.core.security.panic_mode import PanicMode
from src.core.security.side_channel_protection import normalize_timing
from src.core.state_manager import StateManager


COMMON_PASSWORDS = {
    "password123",
    "qwerty",
    "qwerty123",
    "12345678",
    "admin123",
    "letmein",
}


def validate_password_strength(password: str) -> None:
    if len(password) < 12:
        raise ValueError("Минимальная длина пароля — 12 символов")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Нужна хотя бы одна заглавная буква")
    if not re.search(r"[a-z]", password):
        raise ValueError("Нужна хотя бы одна строчная буква")
    if not re.search(r"\d", password):
        raise ValueError("Нужна хотя бы одна цифра")
    if not re.search(r"[^\w\s]", password):
        raise ValueError("Нужен хотя бы один спецсимвол")
    if password.lower() in COMMON_PASSWORDS:
        raise ValueError("Слишком распространённый пароль")


class AuthenticationService:
    def __init__(
        self,
        key_manager,
        state_manager: StateManager,
        event_bus: EventBus | None = None,
        activity_monitor: ActivityMonitor | None = None,
        panic_mode: PanicMode | None = None,
        normalize_auth_timing_enabled: bool = False,
        minimum_auth_delay_sec: float = 0.0,
    ):
        self.key_manager = key_manager
        self.state = state_manager
        self.event_bus = event_bus
        self.activity_monitor = activity_monitor
        self.panic_mode = panic_mode
        self.normalize_auth_timing_enabled = bool(normalize_auth_timing_enabled)
        self.minimum_auth_delay_sec = max(0.0, float(minimum_auth_delay_sec))

    def _delay_for_failures(self) -> int:
        n = self.state.session.failed_attempts
        if n <= 2:
            return 1
        if n <= 4:
            return 5
        return 30

    def login(self, password: str) -> bytes:
        started_at = time.perf_counter()
        bundle = self.key_manager.load_bundle()

        ok = verify_auth_hash(
            password=password,
            salt=bundle["auth_salt"],
            expected_hash=bundle["auth_hash"],
            params=bundle["argon2_params"],
        )

        if not ok:
            self.state.register_failed_attempt()
            delay = self._delay_for_failures()

            if self.event_bus:
                self.event_bus.publish(
                    LoginFailed(
                        user="local",
                        failed_attempts=self.state.session.failed_attempts,
                        delay_seconds=delay,
                    )
                )

            time.sleep(delay)
            if self.normalize_auth_timing_enabled:
                normalize_timing(started_at, self.minimum_auth_delay_sec)
            raise ValueError("Неверный мастер-пароль")

        enc_key = derive_encryption_key(
            password=password,
            salt=bundle["enc_salt"],
            params=bundle["pbkdf2_params"],
        )

        self.key_manager.cache_encryption_key(enc_key)
        self.state.unlock(user="local")
        if self.activity_monitor:
            self.activity_monitor.mark_activity()

        if self.event_bus:
            self.event_bus.publish(UserLoggedIn(user="local"))

        if self.normalize_auth_timing_enabled:
            normalize_timing(started_at, self.minimum_auth_delay_sec)
        return enc_key

    def logout(self) -> None:
        self.key_manager.clear_cache()
        self.state.lock()

        if self.event_bus:
            self.event_bus.publish(UserLoggedOut(user="local"))

    def auto_lock(self, reason: str = "inactivity") -> None:
        self.key_manager.clear_cache()
        self.state.lock()

        if self.event_bus:
            self.event_bus.publish(AutoLocked(reason=reason))
            self.event_bus.publish(UserLoggedOut(user="local"))

    def touch(self) -> None:
        if self.is_unlocked():
            self.state.touch_activity()
            if self.activity_monitor:
                self.activity_monitor.mark_activity()
            self.key_manager.touch_cache()

    def should_auto_lock(self) -> bool:
        if not self.verify_session_integrity():
            return True
        if not self.is_unlocked():
            return False
        if self.activity_monitor and self.activity_monitor.is_inactive():
            return True
        if self.state.is_inactive():
            return True
        return self.key_manager.is_cache_expired()

    def check_auto_lock(self) -> bool:
        if self.should_auto_lock():
            self.auto_lock("inactivity_timeout")
            return True
        return False

    def on_app_focus_lost(self) -> None:
        if self.key_manager.cache.clear_on_focus_loss and self.is_unlocked():
            self.auto_lock("focus_lost")
        else:
            self.key_manager.on_app_focus_lost()

        if self.event_bus:
            self.event_bus.publish(AppFocusLost())

    def on_app_focus_gained(self) -> None:
        self.key_manager.on_app_focus_gained()

        if self.event_bus:
            self.event_bus.publish(AppFocusGained())

    def on_app_minimized(self) -> None:
        if self.key_manager.cache.clear_on_minimize and self.is_unlocked():
            self.auto_lock("app_minimized")
        else:
            self.key_manager.on_app_minimized()

        if self.event_bus:
            self.event_bus.publish(AppMinimized())

    def on_app_restored(self) -> None:
        self.key_manager.on_app_restored()

        if self.event_bus:
            self.event_bus.publish(AppRestored())

    def is_unlocked(self) -> bool:
        return self.state.is_unlocked() and self.key_manager.has_cached_key()

    def verify_session_integrity(self) -> bool:
        state_unlocked = self.state.is_unlocked()
        cache_present = self.key_manager.has_cached_key()
        return state_unlocked == cache_present

    def activate_panic_mode(self, clear_clipboard_callback=None, reason: str = "manual") -> bool:
        if not self.panic_mode:
            return False
        activated = self.panic_mode.activate(
            lock_callback=lambda: self.auto_lock("panic_mode"),
            clear_clipboard_callback=clear_clipboard_callback,
        )
        if activated and self.event_bus:
            self.event_bus.publish(PanicModeActivated(reason=reason))
        return activated
