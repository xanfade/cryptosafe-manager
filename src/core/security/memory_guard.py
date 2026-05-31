from __future__ import annotations

import ctypes
import mmap
import os
import secrets
from contextlib import contextmanager
from dataclasses import dataclass

from src.core.crypto.memory import lock_memory, unlock_memory, zeroize


def _secure_memset(buf: memoryview, value: int = 0) -> None:
    if len(buf) == 0:
        return
    raw = (ctypes.c_char * len(buf)).from_buffer(buf)
    ctypes.memset(raw, value, len(buf))


def _zeroize_passes(buf: memoryview, passes: int) -> None:
    if len(buf) == 0:
        return
    for _ in range(max(1, passes) - 1):
        random_block = secrets.token_bytes(len(buf))
        buf[:] = random_block
    _secure_memset(buf, 0)


@dataclass
class SecureBuffer:
    _payload: memoryview
    _locked: bool = False
    _backing: bytearray | None = None
    _mm: mmap.mmap | None = None
    _canary_prefix: bytes | None = None
    _canary_suffix: bytes | None = None
    _prefix_view: memoryview | None = None
    _suffix_view: memoryview | None = None

    def to_bytes(self) -> bytes:
        self.check_canaries()
        return bytes(self._payload)

    def overwrite(self, payload: bytes | bytearray | memoryview) -> None:
        self.check_canaries()
        data = bytes(payload)
        if len(data) > len(self._payload):
            raise ValueError("payload exceeds secure buffer size")
        self._payload[: len(data)] = data
        if len(data) < len(self._payload):
            _secure_memset(self._payload[len(data) :], 0)

    def check_canaries(self) -> None:
        if self._canary_prefix is not None and self._prefix_view is not None:
            if bytes(self._prefix_view) != self._canary_prefix:
                raise RuntimeError("secure buffer prefix canary corrupted")
        if self._canary_suffix is not None and self._suffix_view is not None:
            if bytes(self._suffix_view) != self._canary_suffix:
                raise RuntimeError("secure buffer suffix canary corrupted")

    def wipe(self, passes: int = 1) -> None:
        _zeroize_passes(self._payload, passes)
        if self._prefix_view is not None:
            _secure_memset(self._prefix_view, 0)
        if self._suffix_view is not None:
            _secure_memset(self._suffix_view, 0)

    def unlock(self) -> None:
        if self._locked and self._mm is None and self._backing is not None:
            unlock_memory(self._backing)
            self._locked = False

    def close(self) -> None:
        try:
            self._payload.release()
        except Exception:
            pass
        for view_name in ("_prefix_view", "_suffix_view"):
            view = getattr(self, view_name)
            if view is not None:
                try:
                    view.release()
                except Exception:
                    pass
                setattr(self, view_name, None)

        if self._mm is not None:
            try:
                self._mm.close()
            finally:
                self._mm = None


class MemoryGuard:
    def __init__(
        self,
        enable_locking: bool = True,
        enable_auto_wipe: bool = True,
        multi_pass_wipe_for_critical: bool = True,
    ):
        self.enable_locking = bool(enable_locking)
        self.enable_auto_wipe = bool(enable_auto_wipe)
        self.multi_pass_wipe_for_critical = bool(multi_pass_wipe_for_critical)
        self._page_size = max(4096, mmap.PAGESIZE)

    def allocate(self, payload: bytes | bytearray | memoryview, critical: bool = False) -> SecureBuffer:
        raw = bytes(payload)
        canary_size = 16

        mm = self._allocate_locked_mmap(len(raw), canary_size)
        if mm is not None:
            prefix = secrets.token_bytes(canary_size)
            suffix = secrets.token_bytes(canary_size)
            mm.seek(0)
            mm.write(prefix + raw + suffix)
            whole = memoryview(mm)
            prefix_view = whole[:canary_size]
            payload_view = whole[canary_size : canary_size + len(raw)]
            suffix_view = whole[canary_size + len(raw) : canary_size * 2 + len(raw)]
            return SecureBuffer(
                _payload=payload_view,
                _locked=True,
                _mm=mm,
                _canary_prefix=prefix,
                _canary_suffix=suffix,
                _prefix_view=prefix_view,
                _suffix_view=suffix_view,
            )

        # Fallback heap allocation with canary guards.
        backing = bytearray(canary_size + len(raw) + canary_size)
        prefix = secrets.token_bytes(canary_size)
        suffix = secrets.token_bytes(canary_size)
        backing[:canary_size] = prefix
        backing[canary_size : canary_size + len(raw)] = raw
        backing[canary_size + len(raw) :] = suffix

        payload_view = memoryview(backing)[canary_size : canary_size + len(raw)]
        prefix_view = memoryview(backing)[:canary_size]
        suffix_view = memoryview(backing)[canary_size + len(raw) :]

        locked = False
        if self.enable_locking:
            locked = lock_memory(backing)

        return SecureBuffer(
            _payload=payload_view,
            _locked=locked,
            _backing=backing,
            _mm=None,
            _canary_prefix=prefix,
            _canary_suffix=suffix,
            _prefix_view=prefix_view,
            _suffix_view=suffix_view,
        )

    def wipe(self, secure_buffer: SecureBuffer, critical: bool = False) -> None:
        if self.enable_auto_wipe:
            passes = 3 if (critical and self.multi_pass_wipe_for_critical) else 1
            secure_buffer.wipe(passes=passes)
        secure_buffer.unlock()
        secure_buffer.close()

    @contextmanager
    def scoped_buffer(self, payload: bytes | bytearray | memoryview, critical: bool = False):
        buf = self.allocate(payload, critical=critical)
        try:
            yield buf
        finally:
            self.wipe(buf, critical=critical)

    @staticmethod
    def stack_scrub(*buffers: bytearray) -> None:
        for buf in buffers:
            if isinstance(buf, bytearray):
                zeroize(buf)

    @contextmanager
    def stack_canary(self):
        canary = secrets.token_bytes(16)
        volatile = bytearray(canary)
        try:
            yield volatile
            if bytes(volatile) != canary:
                raise RuntimeError("stack canary corruption detected")
        finally:
            zeroize(volatile)

    def _allocate_locked_mmap(self, payload_len: int, canary_size: int) -> mmap.mmap | None:
        if not self.enable_locking or os.name == "nt":
            return None

        total = payload_len + canary_size * 2
        try:
            flags = mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
            map_locked = getattr(mmap, "MAP_LOCKED", None)
            if map_locked is not None and os.name == "posix":
                flags |= map_locked
            return mmap.mmap(
                -1,
                total,
                flags=flags,
                prot=mmap.PROT_READ | mmap.PROT_WRITE,
            )
        except Exception:
            return None
