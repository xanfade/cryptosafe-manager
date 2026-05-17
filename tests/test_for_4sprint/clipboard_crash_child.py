from __future__ import annotations

import os
import sys


class CrashDuringSetClipboardAdapter:

    def __init__(self, clipboard_file: str):
        self.clipboard_file = clipboard_file

    def set_text(self, value: str) -> None:
        # Имитируем аварийное завершение ДО записи секрета во внешний clipboard.
        os._exit(77)

    def get_text(self) -> str:
        if not os.path.exists(self.clipboard_file):
            return ""

        with open(self.clipboard_file, "r", encoding="utf-8") as file:
            return file.read()

    def clear(self) -> None:
        with open(self.clipboard_file, "w", encoding="utf-8") as file:
            file.write("")


class DummyEventBus:
    def publish(self, event) -> None:
        pass


def main() -> None:
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    from src.core.clipboard.clipboard_service import ClipboardService

    clipboard_file = os.environ["TEST5_CLIPBOARD_FILE"]
    secret = os.environ["TEST5_SECRET"]

    adapter = CrashDuringSetClipboardAdapter(clipboard_file)
    event_bus = DummyEventBus()

    service = ClipboardService(
        adapter=adapter,
        event_bus=event_bus,
        clear_after_seconds=None,
        is_unlocked_callback=lambda: True,
    )

    service.copy_secret(secret, entry_id=1)

    # До этой строки процесс дойти не должен.
    sys.exit(0)


if __name__ == "__main__":
    main()