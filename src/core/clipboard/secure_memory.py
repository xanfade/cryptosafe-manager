from __future__ import annotations

import ctypes
import mmap
import os
import platform


class SecureMemoryError(RuntimeError):
    pass


class SecureMemoryBuffer:
    def __init__(self, value: str | bytes):
        if isinstance(value, str):
            data = value.encode("utf-8")
        elif isinstance(value, bytes):
            data = value
        else:
            raise TypeError("SecureMemoryBuffer supports only str or bytes")

        self._size = max(len(data), 1)
        self._closed = False
        self._system = platform.system()

        self._ptr = None
        self._mmap = None
        self._locked = False

        if self._system == "Windows":
            self._init_windows(data)
        else:
            self._init_unix(data)

    def _init_windows(self, data: bytes) -> None:
        kernel32 = ctypes.windll.kernel32

        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_READWRITE = 0x04

        kernel32.VirtualAlloc.restype = ctypes.c_void_p
        kernel32.VirtualAlloc.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]

        ptr = kernel32.VirtualAlloc(
            None,
            self._size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )

        if not ptr:
            raise SecureMemoryError("VirtualAlloc failed")

        self._ptr = ptr

        if not kernel32.VirtualLock(ctypes.c_void_p(ptr), ctypes.c_size_t(self._size)):
            self.close()
            raise SecureMemoryError("VirtualLock failed")

        self._locked = True
        ctypes.memmove(ctypes.c_void_p(ptr), data, len(data))

    def _init_unix(self, data: bytes) -> None:
        self._mmap = mmap.mmap(-1, self._size, access=mmap.ACCESS_WRITE)
        self._mmap.write(data)
        self._mmap.seek(0)

        address = ctypes.addressof(ctypes.c_char.from_buffer(self._mmap))

        libc = ctypes.CDLL(None)

        if hasattr(libc, "mlock"):
            result = libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(self._size))
            if result != 0:
                self.close()
                raise SecureMemoryError("mlock failed")

            self._locked = True

        self._ptr = address

    def read_bytes(self) -> bytes:
        if self._closed:
            return b""

        if self._system == "Windows":
            return ctypes.string_at(self._ptr, self._size)

        self._mmap.seek(0)
        return self._mmap.read(self._size)

    def read_text(self) -> str:
        return self.read_bytes().decode("utf-8", errors="replace")

    def zero(self) -> None:
        if self._closed:
            return

        if self._system == "Windows":
            self._zero_windows()
        else:
            self._zero_unix()

    def _zero_windows(self) -> None:
        if not self._ptr:
            return

        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.RtlSecureZeroMemory.argtypes = [
                ctypes.c_void_p,
                ctypes.c_size_t,
            ]
            kernel32.RtlSecureZeroMemory(
                ctypes.c_void_p(self._ptr),
                ctypes.c_size_t(self._size),
            )
        except Exception:
            ctypes.memset(ctypes.c_void_p(self._ptr), 0, self._size)

    def _zero_unix(self) -> None:
        if not self._mmap:
            return

        address = ctypes.addressof(ctypes.c_char.from_buffer(self._mmap))
        ctypes.memset(ctypes.c_void_p(address), 0, self._size)

        self._mmap.seek(0)
        self._mmap.write(b"\x00" * self._size)
        self._mmap.seek(0)

    def close(self) -> None:
        if self._closed:
            return

        self.zero()

        if self._system == "Windows":
            self._close_windows()
        else:
            self._close_unix()

        self._closed = True

    def _close_windows(self) -> None:
        if not self._ptr:
            return

        kernel32 = ctypes.windll.kernel32

        if self._locked:
            kernel32.VirtualUnlock(
                ctypes.c_void_p(self._ptr),
                ctypes.c_size_t(self._size),
            )

        MEM_RELEASE = 0x8000
        kernel32.VirtualFree(
            ctypes.c_void_p(self._ptr),
            0,
            MEM_RELEASE,
        )

        self._ptr = None
        self._locked = False

    def _close_unix(self) -> None:
        if not self._mmap:
            return

        if self._locked and self._ptr:
            libc = ctypes.CDLL(None)

            if hasattr(libc, "munlock"):
                libc.munlock(
                    ctypes.c_void_p(self._ptr),
                    ctypes.c_size_t(self._size),
                )

        self._mmap.close()
        self._mmap = None
        self._ptr = None
        self._locked = False

    def __enter__(self) -> "SecureMemoryBuffer":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass