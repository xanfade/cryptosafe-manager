from __future__ import annotations

import secrets
import time

_compare_digest = secrets.compare_digest


def constant_time_compare(left: bytes, right: bytes) -> bool:
    if not isinstance(left, (bytes, bytearray, memoryview)):
        raise TypeError("left must be bytes-like")
    if not isinstance(right, (bytes, bytearray, memoryview)):
        raise TypeError("right must be bytes-like")
    if isinstance(left, bytes) and isinstance(right, bytes):
        return _compare_digest(left, right)
    return _compare_digest(bytes(left), bytes(right))


def constant_time_compare_str(left: str, right: str, encoding: str = "utf-8") -> bool:
    if not isinstance(left, str):
        raise TypeError("left must be str")
    if not isinstance(right, str):
        raise TypeError("right must be str")
    if encoding.lower() == "utf-8":
        return _compare_digest(left, right)
    return constant_time_compare(left.encode(encoding), right.encode(encoding))


def normalize_timing(started_at: float, minimum_delay_sec: float = 0.0) -> None:
    if minimum_delay_sec <= 0:
        return
    elapsed = time.perf_counter() - started_at
    remaining = minimum_delay_sec - elapsed
    if remaining > 0:
        time.sleep(remaining)
