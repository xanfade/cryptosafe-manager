from __future__ import annotations

import ctypes
import gc
import os
import sys
import time




class DigestOnlyClipboardAdapter:
    def __init__(self):
        self.has_value = False

    def set_text(self, value: str) -> None:
        self.has_value = bool(value)

    def get_text(self) -> str:
        return ""

    def clear(self) -> None:
        self.has_value = False


class DummyEventBus:
    def publish(self, event) -> None:
        pass


def wipe_python_string(value: str) -> None:

    if not value:
        return

    size = ctypes.c_ssize_t()

    ctypes.pythonapi.PyUnicode_AsUTF8AndSize.argtypes = [
        ctypes.py_object,
        ctypes.POINTER(ctypes.c_ssize_t),
    ]
    ctypes.pythonapi.PyUnicode_AsUTF8AndSize.restype = ctypes.c_void_p

    address = ctypes.pythonapi.PyUnicode_AsUTF8AndSize(
        value,
        ctypes.byref(size),
    )

    if address and size.value > 0:
        ctypes.memset(address, 0, size.value)


def wipe_bytearray(value: bytearray) -> None:
    for i in range(len(value)):
        value[i] = 0


def main() -> None:
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    from src.core.clipboard.clipboard_service import ClipboardService

    secret_buffer = bytearray(sys.stdin.buffer.read())
    secret_text = secret_buffer.decode("utf-8")

    adapter = DigestOnlyClipboardAdapter()
    event_bus = DummyEventBus()

    service = ClipboardService(
        adapter=adapter,
        event_bus=event_bus,
        clear_after_seconds=None,
        is_unlocked_callback=lambda: True,
    )

    service.copy_secret(secret_text, entry_id=1)

    wipe_bytearray(secret_buffer)
    wipe_python_string(secret_text)

    del secret_text
    del secret_buffer

    gc.collect()

    print("READY", flush=True)

    time.sleep(10)


if __name__ == "__main__":
    main()

# docker run --rm \
#   --cap-add=SYS_PTRACE \
#   --security-opt seccomp=unconfined \
#   -v "$PWD":/app \
#   -w /app \
#   python:3.12 bash -c "pip install -r requirements.txt && python -m pytest tests/test_for_4sprint/test_clipboard_memory_security.py -q"