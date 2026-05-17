from __future__ import annotations

import os
import secrets
import subprocess
import sys
import time

import pytest


def _read_process_memory_linux(pid: int, needle: bytes) -> bool:

    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"

    with open(maps_path, "r", encoding="utf-8", errors="ignore") as maps_file:
        regions = maps_file.readlines()

    mem_fd = os.open(mem_path, os.O_RDONLY)

    try:
        for region in regions:
            parts = region.split()

            if len(parts) < 2:
                continue

            address_range = parts[0]
            permissions = parts[1]
            path = parts[5] if len(parts) >= 6 else ""

            if "r" not in permissions:
                continue

            # Файловые mmap-регионы пропускаем:
            # библиотеки, .pyc, бинарники и т.д.
            if path.startswith("/"):
                continue

            # Специальные системные регионы часто имеют огромные адреса.
            if path in ("[vdso]", "[vvar]", "[vsyscall]"):
                continue

            start_hex, end_hex = address_range.split("-")
            start = int(start_hex, 16)
            end = int(end_hex, 16)

            if end <= start:
                continue

            # Защита от OverflowError на очень больших адресах.
            if start > sys.maxsize or end > sys.maxsize:
                continue

            region_size = end - start
            chunk_size = 1024 * 1024
            overlap = max(len(needle) - 1, 0)

            offset = 0
            previous = b""

            while offset < region_size:
                to_read = min(chunk_size, region_size - offset)

                try:
                    chunk = os.pread(mem_fd, to_read, start + offset)
                except (OSError, OverflowError):
                    break

                if not chunk:
                    break

                data = previous + chunk

                if needle in data:
                    return True

                previous = data[-overlap:] if overlap else b""
                offset += len(chunk)

    finally:
        os.close(mem_fd)

    return False


@pytest.mark.skipif(sys.platform != "linux", reason="Process memory dump test uses /proc/<pid>/mem")
def test_clipboard_password_not_found_in_plaintext_process_memory():

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    child_script = os.path.join(
        project_root,
        "tests",
        "test_for_4sprint",
        "memory_probe_child.py",
    )

    secret = f"TEST3_SECRET_{secrets.token_hex(32)}".encode("utf-8")

    env = os.environ.copy()
    env["PYTHONPATH"] = project_root + os.pathsep + env.get("PYTHONPATH", "")

    process = subprocess.Popen(
        [sys.executable, child_script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=project_root,
        env=env,
        text=False,
    )

    try:
        assert process.stdin is not None
        process.stdin.write(secret)
        process.stdin.close()

        assert process.stdout is not None

        deadline = time.time() + 5
        ready = False

        while time.time() < deadline:
            line = process.stdout.readline()
            if line.strip() == b"READY":
                ready = True
                break

        if not ready:
            stderr = b""

            if process.stderr is not None:
                stderr = process.stderr.read()

            raise AssertionError(
                f"Memory probe child process did not become ready. STDERR: {stderr.decode('utf-8', errors='replace')}"
            )

        found = _read_process_memory_linux(process.pid, secret)

        assert not found, "Password was found in process memory as plaintext"

    finally:
        process.kill()
        process.wait(timeout=5)