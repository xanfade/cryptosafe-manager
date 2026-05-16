import threading
import time


class ClipboardMonitor:
    def __init__(self, clipboard_service, interval: float = 1.0):
        self.clipboard_service = clipboard_service
        self.interval = interval
        self._running = False
        self._thread = None

    def start(self) -> None:
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        while self._running:
            time.sleep(self.interval)

            if not self.clipboard_service.has_active_secret():
                continue

            current = self.clipboard_service.adapter.get_text()
            expected = self.clipboard_service._expected_clipboard_text()

            if expected and current != expected:
                self.clipboard_service.clear()