import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class SessionState:
    # Состояние сессии пользователя
    unlocked: bool = False
    user: str = "local"


class StateManager:
    """
    Центральный менеджер состояния (Sprint 1 каркас).
    """

    def __init__(self):
        self.session = SessionState(unlocked=False)

        # Ключ в памяти (в Sprint 2/3 будет формироваться корректно)
        self.master_key: Optional[bytes] = None

        # Буфер обмена (Sprint 4)
        self.clipboard_value: Optional[str] = None
        self.clipboard_expires_at: Optional[float] = None  # unix time

        # Таймер неактивности (Sprint 7)
        self.last_activity_at: float = time.time()
        self.inactivity_timeout_sec: Optional[int] = None  # потом возьмем из settings

    # ---- Сессия ----
    def lock(self):
        self.session.unlocked = False
        self.master_key = None

    def unlock(self, key: bytes, user: str = "local"):
        self.session.unlocked = True
        self.session.user = user
        self.master_key = key
        self.touch_activity()

    def is_unlocked(self) -> bool:
        return self.session.unlocked

    # ---- Активность ----
    def touch_activity(self):
        self.last_activity_at = time.time()

    def is_inactive(self) -> bool:
        if self.inactivity_timeout_sec is None:
            return False
        return (time.time() - self.last_activity_at) >= self.inactivity_timeout_sec

    # ---- Буфер обмена (заглушка) ----
    def set_clipboard(self, value: str, timeout_sec: int):
        self.clipboard_value = value
        self.clipboard_expires_at = time.time() + timeout_sec

    def clear_clipboard_if_expired(self):
        if self.clipboard_expires_at is None:
            return
        if time.time() >= self.clipboard_expires_at:
            self.clipboard_value = None
            self.clipboard_expires_at = None
