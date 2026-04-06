from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class SessionState:
    unlocked: bool = False
    user: str = "local"
    login_time: Optional[float] = None
    failed_attempts: int = 0


class StateManager:


    def __init__(self):
        self.session = SessionState()

        # Буфер обмена
        self.clipboard_value: Optional[str] = None
        self.clipboard_expires_at: Optional[float] = None

        # Таймер неактивности
        self.last_activity_at: float = time.time()
        self.inactivity_timeout_sec: Optional[int] = None

    # -------- Сессия --------

    def unlock(self, user: str = "local") -> None:
        self.session.unlocked = True
        self.session.user = user
        self.session.login_time = time.time()
        self.session.failed_attempts = 0
        self.touch_activity()

    def lock(self) -> None:
        self.session.unlocked = False
        self.session.login_time = None

    def is_unlocked(self) -> bool:
        return self.session.unlocked

    def register_failed_attempt(self) -> None:
        self.session.failed_attempts += 1

    def reset_failed_attempts(self) -> None:
        self.session.failed_attempts = 0

    # -------- Активность --------

    def touch_activity(self) -> None:
        self.last_activity_at = time.time()

    def set_inactivity_timeout(self, timeout_sec: Optional[int]) -> None:
        if timeout_sec is None:
            self.inactivity_timeout_sec = None
            return

        timeout_sec = int(timeout_sec)
        if timeout_sec <= 0:
            self.inactivity_timeout_sec = None
            return

        self.inactivity_timeout_sec = timeout_sec

    def is_inactive(self) -> bool:
        if self.inactivity_timeout_sec is None:
            return False
        return (time.time() - self.last_activity_at) >= self.inactivity_timeout_sec

    # -------- Буфер обмена --------

    def set_clipboard(self, value: str, timeout_sec: int) -> None:
        self.clipboard_value = value
        self.clipboard_expires_at = time.time() + int(timeout_sec)

    def clear_clipboard(self) -> None:
        self.clipboard_value = None
        self.clipboard_expires_at = None

    def is_clipboard_expired(self) -> bool:
        if self.clipboard_expires_at is None:
            return False
        return time.time() >= self.clipboard_expires_at

    def clear_clipboard_if_expired(self) -> bool:
        if self.is_clipboard_expired():
            self.clear_clipboard()
            return True
        return False