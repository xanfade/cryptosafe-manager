from __future__ import annotations

import os
import platform
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from src.core.clipboard.clipboard_service import ClipboardService, ClipboardDataType


class DummyEventBus:
    def __init__(self):
        self.events = []

    def publish(self, event) -> None:
        self.events.append(event)


class TimingClipboardAdapter:
    def __init__(self):
        self.value = ""
        self.cleared_at = None
        self.clear_event = threading.Event()
        self.lock = threading.Lock()

    def set_text(self, value: str) -> None:
        with self.lock:
            self.value = value

    def get_text(self) -> str:
        with self.lock:
            return self.value

    def clear(self) -> None:
        with self.lock:
            self.value = ""
            self.cleared_at = time.perf_counter()
            self.clear_event.set()


class ThreadSafeClipboardAdapter:
    def __init__(self):
        self.value = ""
        self.history = []
        self.lock = threading.Lock()

    def set_text(self, value: str) -> None:
        with self.lock:
            self.value = value
            self.history.append(value)

    def get_text(self) -> str:
        with self.lock:
            return self.value

    def clear(self) -> None:
        with self.lock:
            self.value = ""


def test_test1_auto_clear_timing_within_100ms(monkeypatch):

    import src.core.clipboard.clipboard_service as clipboard_module

    monkeypatch.setattr(clipboard_module, "MIN_CLEAR_SECONDS", 1)
    monkeypatch.setattr(clipboard_module, "MAX_CLEAR_SECONDS", 10)

    adapter = TimingClipboardAdapter()
    event_bus = DummyEventBus()

    configured_timeout = 1

    service = ClipboardService(
        adapter=adapter,
        event_bus=event_bus,
        clear_after_seconds=configured_timeout,
        is_unlocked_callback=lambda: True,
    )

    start = time.perf_counter()
    service.copy_secret("TEST1_SECRET_PASSWORD", entry_id=1)

    cleared = adapter.clear_event.wait(timeout=2)

    assert cleared, "Clipboard was not cleared by auto-clear timer"
    assert adapter.get_text() == ""

    elapsed = adapter.cleared_at - start

    assert abs(elapsed - configured_timeout) <= 0.1, (
        f"Clipboard cleared after {elapsed:.3f}s, "
        f"expected {configured_timeout:.3f}s ±100ms"
    )


def test_test2_platform_environment_is_supported():

    current_platform = sys.platform

    assert current_platform.startswith(("win32", "darwin", "linux")), (
        f"Unsupported platform: {current_platform}"
    )

    assert platform.system() in {"Windows", "Darwin", "Linux"}


def test_test4_multiple_rapid_copy_operations_do_not_leak_previous_values():


    adapter = ThreadSafeClipboardAdapter()
    event_bus = DummyEventBus()

    service = ClipboardService(
        adapter=adapter,
        event_bus=event_bus,
        clear_after_seconds=None,
        is_unlocked_callback=lambda: True,
    )

    secrets = [
        f"TEST4_SECRET_{i:03d}_VALUE"
        for i in range(100)
    ]

    errors = []

    def copy_value(value: str) -> None:
        try:
            service.copy_secret(value, entry_id=1)
        except Exception as exc:
            errors.append(exc)

    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(copy_value, value) for value in secrets]

        for future in as_completed(futures):
            future.result()

    assert not errors, f"Errors during concurrent copy: {errors}"

    current_clipboard_value = adapter.get_text()

    assert current_clipboard_value in secrets
    assert service.has_active_secret()
    assert service.is_expected_value(current_clipboard_value)

    internal_state = repr(service.__dict__)

    for secret in secrets:
        assert secret not in internal_state, (
            f"Secret leaked into ClipboardService internal state: {secret}"
        )

    for secret in secrets:
        if secret != current_clipboard_value:
            assert secret != adapter.get_text(), (
                f"Old secret leaked in clipboard: {secret}"
            )

    service.clear()

    assert adapter.get_text() == ""
    assert not service.has_active_secret()


def test_test5_application_crash_during_clipboard_operation_does_not_leave_secret(tmp_path):

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    child_script = os.path.join(
        project_root,
        "tests",
        "test_for_4sprint",
        "clipboard_crash_child.py",
    )

    clipboard_file = tmp_path / "clipboard.txt"
    secret = "TEST5_CRASH_SECRET_PASSWORD"

    env = os.environ.copy()
    env["PYTHONPATH"] = project_root + os.pathsep + env.get("PYTHONPATH", "")
    env["TEST5_CLIPBOARD_FILE"] = str(clipboard_file)
    env["TEST5_SECRET"] = secret

    process = subprocess.Popen(
        [sys.executable, child_script],
        cwd=project_root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    stdout, stderr = process.communicate(timeout=5)

    assert process.returncode != 0, (
        "Crash child process must terminate abnormally for TEST-5"
    )

    if clipboard_file.exists():
        clipboard_data = clipboard_file.read_text(encoding="utf-8")
    else:
        clipboard_data = ""

    assert secret not in clipboard_data, (
        "Application crash left sensitive plaintext data in clipboard"
    )