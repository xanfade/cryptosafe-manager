from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import threading
from typing import Callable, Optional
from src.core.clipboard.secure_memory import SecureMemoryBuffer
import hashlib

from src.core.events import (
    ClipboardCopied,
    ClipboardCleared,
    ClipboardSuspiciousActivity,
    ClipboardCopyBlocked,
)


class ClipboardDataType(str, Enum):
    TEXT = "text"
    TOTP = "totp"
    ENCRYPTED_BLOB = "encrypted_blob"


@dataclass
class ClipboardContent:
    data_type: ClipboardDataType
    expected_hash: str
    created_at: datetime
    entry_id: int | None = None

    @staticmethod
    def make_hash(value: str) -> str:
        buffer = bytearray(value, "utf-8")

        try:
            return hashlib.sha256(buffer).hexdigest()
        finally:
            for i in range(len(buffer)):
                buffer[i] = 0

    def matches(self, value: str) -> bool:
        return self.expected_hash == self.make_hash(value)

    def clear(self) -> None:
        pass



DEFAULT_CLEAR_SECONDS = 30
MIN_CLEAR_SECONDS = 5
MAX_CLEAR_SECONDS = 300
NEVER_AUTO_CLEAR = None

class ClipboardService:
    def __init__(
            self,
            adapter,
            event_bus,
            clear_after_seconds: int | None = DEFAULT_CLEAR_SECONDS,
            is_unlocked_callback: Callable[[], bool] | None = None,
    ):
        self.adapter = adapter
        self.event_bus = event_bus
        self.clear_after_seconds = self._normalize_timeout(clear_after_seconds)
        self.is_unlocked_callback = is_unlocked_callback

        self._timer: Optional[threading.Timer] = None
        self._observers: list[Callable[[str], None]] = []
        self._content: Optional[ClipboardContent] = None
        self._lock = threading.RLock()
        self._blocked = False
        self._suspicious_detected = False

    def subscribe(self, observer: Callable[[str], None]) -> None:
        self._observers.append(observer)

    def _notify(self, state: str) -> None:
        for observer in self._observers:
            observer(state)

    def _vault_is_unlocked(self) -> bool:
        if self.is_unlocked_callback is None:
            return True

        try:
            return bool(self.is_unlocked_callback())
        except Exception:
            return False

    def copy_secret(
            self,
            value: str | bytes,
            entry_id: int | None = None,
            data_type: ClipboardDataType = ClipboardDataType.TEXT,
    ) -> None:
        if value is None or value == "":
            return

        with self._lock:
            if not self._vault_is_unlocked():
                self.event_bus.publish(
                    ClipboardCopyBlocked(reason="vault_locked")
                )
                self._notify("copy_blocked")
                return

            if self._blocked:
                self.event_bus.publish(
                    ClipboardCopyBlocked(reason="copy_blocked_after_suspicious_activity")
                )
                self._notify("copy_blocked")
                return

            self.clear(publish_event=False)

            clipboard_value = self._to_clipboard_text(value, data_type)

            self.adapter.set_text(clipboard_value)

            self._content = ClipboardContent(
                data_type=data_type,
                expected_hash=ClipboardContent.make_hash(clipboard_value),
                created_at=datetime.now(timezone.utc),
                entry_id=entry_id,
            )

            self.event_bus.publish(
                ClipboardCopied(
                    data_type=data_type.value,
                    entry_id=entry_id,
                )
            )

            self._notify("copied")

            if self.clear_after_seconds is not None:
                self._timer = threading.Timer(
                    self.clear_after_seconds,
                    self.clear,
                )
                self._timer.daemon = True
                self._timer.start()

    def copy_text(self, value: str, entry_id: int | None = None) -> None:
        self.copy_secret(
            value=value,
            entry_id=entry_id,
            data_type=ClipboardDataType.TEXT,
        )

    def copy_totp(self, code: str, entry_id: int | None = None) -> None:
        self.copy_secret(
            value=code,
            entry_id=entry_id,
            data_type=ClipboardDataType.TOTP,
        )

    def copy_encrypted_blob(self, blob: bytes, entry_id: int | None = None) -> None:
        self.copy_secret(
            value=blob,
            entry_id=entry_id,
            data_type=ClipboardDataType.ENCRYPTED_BLOB,
        )

    def _to_clipboard_text(
        self,
        value: str | bytes,
        data_type: ClipboardDataType,
    ) -> str:
        if data_type in (ClipboardDataType.TEXT, ClipboardDataType.TOTP):
            return str(value)

        if data_type == ClipboardDataType.ENCRYPTED_BLOB:
            if isinstance(value, bytes):
                return value.hex()
            return str(value)

        return str(value)

    def _start_timer(self) -> None:
        if self._timer:
            self._timer.cancel()

        self._timer = threading.Timer(
            self.clear_after_seconds,
            self.clear,
        )
        self._timer.daemon = True
        self._timer.start()

    def clear(self, publish_event: bool = True) -> None:
        with self._lock:
            if self._timer:
                self._timer.cancel()
                self._timer = None

            current = self.adapter.get_text()
            if current and self._clipboard_matches_expected(current):
                self.adapter.clear()

            if self._content:
                self._content.clear()
                self._content = None

            if publish_event:
                self.event_bus.publish(ClipboardCleared())

            self._notify("cleared")

    def _clipboard_matches_expected(self, value: str) -> bool:
        if not self._content:
            return False
        return self._content.matches(value)

    def has_active_secret(self) -> bool:
        return self._content is not None

    def get_content_type(self) -> ClipboardDataType | None:
        if not self._content:
            return None

        return self._content.data_type

    def schedule_clear(self) -> None:
        with self._lock:
            if self._timer:
                self._timer.cancel()
                self._timer = None

            if self.clear_after_seconds is None:
                self._notify("never")
                return

            self._timer = threading.Timer(
                self.clear_after_seconds,
                self.clear
            )
            self._timer.daemon = True
            self._timer.start()

            self._notify("scheduled")

    def _normalize_timeout(self, seconds: int | None) -> int | None:
        if seconds is None:
            return None

        seconds = int(seconds)

        if seconds < MIN_CLEAR_SECONDS:
            return MIN_CLEAR_SECONDS

        if seconds > MAX_CLEAR_SECONDS:
            return MAX_CLEAR_SECONDS

        return seconds

    def set_clear_timeout(self, seconds: int | None) -> None:
        with self._lock:
            self.clear_after_seconds = self._normalize_timeout(seconds)

            if self.has_active_secret():
                self.schedule_clear()

    def apply_settings(self, settings) -> None:
        self.set_clear_timeout(settings.auto_clear_timeout_sec)

    def load_timeout_from_settings(self, db) -> None:
        raw_value = db.get_setting("clipboard.clear_timeout_sec", "30")

        if raw_value is None or raw_value == "none":
            self.set_clear_timeout(None)
            return

        try:
            self.set_clear_timeout(int(raw_value))
        except (TypeError, ValueError):
            self.set_clear_timeout(DEFAULT_CLEAR_SECONDS)

    def save_timeout_to_settings(self, db) -> None:
        value = (
            "none"
            if self.clear_after_seconds is None
            else str(self.clear_after_seconds)
        )

        db.set_setting("clipboard.clear_timeout_sec", value, encrypted=1)

    def is_expected_value(self, value: str) -> bool:
        return self._clipboard_matches_expected(value)

    def get_expected_value(self) -> str:
        return ""

    def report_suspicious_activity(self, reason: str) -> None:
        with self._lock:
            self._suspicious_detected = True

            self.event_bus.publish(
                ClipboardSuspiciousActivity(reason=reason)
            )

            self._notify("suspicious")

            # ускоренная очистка: не ждем 30 секунд
            self.clear()

    def block_future_copies(self) -> None:
        with self._lock:
            self._blocked = True
            self._notify("copy_blocked")

    def unblock_future_copies(self) -> None:
        with self._lock:
            self._blocked = False
            self._notify("copy_unblocked")

    def is_blocked(self) -> bool:
        return self._blocked