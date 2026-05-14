import threading
import time
from typing import Callable, Optional

from src.core.events import ClipboardCopied, ClipboardCleared


class ClipboardService:
    def __init__(self, adapter, event_bus, clear_after_seconds: int = 30):
        self.adapter = adapter
        self.event_bus = event_bus
        self.clear_after_seconds = clear_after_seconds

        self._timer: Optional[threading.Timer] = None
        self._observers: list[Callable[[str], None]] = []
        self._last_copied_value: Optional[str] = None
        self._copied_at: Optional[float] = None
        self._lock = threading.RLock()

    def subscribe(self, observer: Callable[[str], None]) -> None:
        self._observers.append(observer)

    def _notify(self, state: str) -> None:
        for observer in self._observers:
            observer(state)

    def copy_secret(self, value: str, entry_id: int) -> None:
        if not value:
            return

        with self._lock:
            self.clear(publish_event=False)

            self.adapter.set_text(value)
            self._last_copied_value = value
            self._copied_at = time.time()

            self._timer = threading.Timer(
                self.clear_after_seconds,
                self.clear
            )
            self._timer.daemon = True
            self._timer.start()

        self.event_bus.publish(ClipboardCopied(entry_id=entry_id))
        self._notify("copied")

    def clear(self, publish_event: bool = True) -> None:
        with self._lock:
            if self._timer:
                self._timer.cancel()
                self._timer = None

            current = self.adapter.get_text()

            if self._last_copied_value and current == self._last_copied_value:
                self.adapter.clear()

            self._last_copied_value = None
            self._copied_at = None

        if publish_event:
            self.event_bus.publish(ClipboardCleared())
            self._notify("cleared")

    def has_active_secret(self) -> bool:
        return self._last_copied_value is not None

    def schedule_clear(self) -> None:
        with self._lock:
            if self._timer:
                self._timer.cancel()

            self._timer = threading.Timer(
                self.clear_after_seconds,
                self.clear
            )
            self._timer.daemon = True
            self._timer.start()

        self._notify("scheduled")