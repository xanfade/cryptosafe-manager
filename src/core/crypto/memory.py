from __future__ import annotations

import ctypes
import os
import sys


def zeroize(buf: bytearray) -> None:

    if not isinstance(buf, bytearray):
        raise TypeError("zeroize ожидает bytearray")

    length = len(buf)
    if length == 0:
        return

    ptr = (ctypes.c_char * length).from_buffer(buf)
    ctypes.memset(ptr, 0, length)


def lock_memory(buf: bytearray) -> bool:

    if not isinstance(buf, bytearray):
        raise TypeError("lock_memory ожидает bytearray")

    length = len(buf)
    if length == 0:
        return False

    try:
        ptr = ctypes.addressof((ctypes.c_char * length).from_buffer(buf))

        if os.name == "nt":
            kernel32 = ctypes.windll.kernel32
            kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            kernel32.VirtualLock.restype = ctypes.c_int
            return bool(kernel32.VirtualLock(ctypes.c_void_p(ptr), ctypes.c_size_t(length)))

        libc_name = None
        if sys.platform == "darwin":
            libc_name = "libc.dylib"
        else:
            libc_name = "libc.so.6"

        libc = ctypes.CDLL(libc_name)
        libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        libc.mlock.restype = ctypes.c_int
        return libc.mlock(ctypes.c_void_p(ptr), ctypes.c_size_t(length)) == 0

    except Exception:
        return False


def unlock_memory(buf: bytearray) -> bool:

    if not isinstance(buf, bytearray):
        raise TypeError("unlock_memory ожидает bytearray")

    length = len(buf)
    if length == 0:
        return False

    try:
        ptr = ctypes.addressof((ctypes.c_char * length).from_buffer(buf))

        if os.name == "nt":
            kernel32 = ctypes.windll.kernel32
            kernel32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            kernel32.VirtualUnlock.restype = ctypes.c_int
            return bool(kernel32.VirtualUnlock(ctypes.c_void_p(ptr), ctypes.c_size_t(length)))

        libc_name = None
        if sys.platform == "darwin":
            libc_name = "libc.dylib"
        else:
            libc_name = "libc.so.6"

        libc = ctypes.CDLL(libc_name)
        libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        libc.munlock.restype = ctypes.c_int
        return libc.munlock(ctypes.c_void_p(ptr), ctypes.c_size_t(length)) == 0

    except Exception:
        return False