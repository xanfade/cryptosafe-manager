from __future__ import annotations

import re
import time
from dataclasses import dataclass

from src.core.crypto.key_derivation import (
    derive_encryption_key,
    verify_auth_hash,
)
from src.core.events import (
    AppFocusGained,
    AppFocusLost,
    AppMinimized,
    AppRestored,
    AutoLocked,
    EventBus,
    UserLoggedIn,
    UserLoggedOut,
)

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


@dataclass
class SessionInfo:
    login_time: float | None = None
    last_activity_time: float | None = None
    failed_attempts: int = 0


class AuthenticationService:
    def __init__(self, key_manager, event_bus: EventBus | None = None):
        self.key_manager = key_manager
        self.event_bus = event_bus
        self.session = SessionInfo()

    def _delay_for_failures(self) -> int:
        n = self.session.failed_attempts
        if n <= 2:
            return 1
        if n <= 4:
            return 5
        return 30

    def login(self, password: str) -> bytes:
        bundle = self.key_manager.load_bundle()

        ok = verify_auth_hash(
            password=password,
            salt=bundle["auth_salt"],
            expected_hash=bundle["auth_hash"],
            params=bundle["argon2_params"],
        )

        if not ok:
            self.session.failed_attempts += 1
            time.sleep(self._delay_for_failures())
            raise ValueError("Неверный мастер-пароль")

        enc_key = derive_encryption_key(
            password=password,
            salt=bundle["enc_salt"],
            params=bundle["pbkdf2_params"],
        )

        self.key_manager.cache_encryption_key(enc_key)

        now = time.time()
        self.session.login_time = now
        self.session.last_activity_time = now
        self.session.failed_attempts = 0

        if self.event_bus:
            self.event_bus.publish(UserLoggedIn(user="local"))

        return enc_key

    def logout(self) -> None:
        self.key_manager.clear_cache()
        self.session.login_time = None
        self.session.last_activity_time = None

        if self.event_bus:
            self.event_bus.publish(UserLoggedOut(user="local"))

    def auto_lock(self, reason: str = "inactivity") -> None:
        self.key_manager.clear_cache()
        self.session.login_time = None
        self.session.last_activity_time = None

        if self.event_bus:
            self.event_bus.publish(AutoLocked(reason=reason))
            self.event_bus.publish(UserLoggedOut(user="local"))

    def touch(self) -> None:
        if self.is_unlocked():
            now = time.time()
            self.session.last_activity_time = now
            self.key_manager.touch_cache()

    def should_auto_lock(self) -> bool:
        if not self.is_unlocked():
            return False
        return self.key_manager.is_cache_expired()

    def check_auto_lock(self) -> bool:
        if self.should_auto_lock():
            self.auto_lock("inactivity_timeout")
            return True
        return False

    def on_app_focus_lost(self) -> None:
        # CACHE-2: при потере фокуса приложение считается неактивным
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
        #при сворачивании приложение считается неактивным
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
        return self.key_manager.has_cached_key()