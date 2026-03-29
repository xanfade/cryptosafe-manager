from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional

try:
    import keyring
except Exception:
    keyring = None

from src.core.crypto.memory import lock_memory, unlock_memory, zeroize


@dataclass
class CachedKey:
    value: bytearray
    created_at: float
    last_access_at: float
    memory_locked: bool = False


class SecureKeyCache:

    def __init__(
        self,
        ttl_seconds: int = 3600,
        clear_on_focus_loss: bool = True,
        clear_on_minimize: bool = True,
    ):
        self.ttl_seconds = ttl_seconds
        self.clear_on_focus_loss = clear_on_focus_loss
        self.clear_on_minimize = clear_on_minimize

        self._entry: Optional[CachedKey] = None
        self._lock = threading.RLock()

        self._app_active = True
        self._storage_unlocked = False

    def put(self, key: bytes) -> None:
        with self._lock:
            self.clear()

            now = time.time()
            buf = bytearray(key)
            locked = lock_memory(buf)

            self._entry = CachedKey(
                value=buf,
                created_at=now,
                last_access_at=now,
                memory_locked=locked,
            )
            self._storage_unlocked = True

    def get(self) -> Optional[bytes]:
        with self._lock:
            self._expire_if_needed()

            if not self._app_active:
                return None

            if not self._storage_unlocked:
                return None

            if self._entry is None:
                return None

            self._entry.last_access_at = time.time()
            return bytes(self._entry.value)

    def touch(self) -> None:
        with self._lock:
            if self._entry is not None:
                self._entry.last_access_at = time.time()

    def clear(self) -> None:
        with self._lock:
            if self._entry is not None:
                try:
                    if self._entry.memory_locked:
                        unlock_memory(self._entry.value)
                finally:
                    zeroize(self._entry.value)
                    self._entry = None

            self._storage_unlocked = False

    def has_key(self) -> bool:
        with self._lock:
            self._expire_if_needed()
            return self._entry is not None and self._storage_unlocked and self._app_active

    def mark_storage_locked(self) -> None:
        with self._lock:
            self.clear()

    def mark_storage_unlocked(self) -> None:
        with self._lock:
            self._storage_unlocked = self._entry is not None

    def on_app_focus_lost(self) -> None:
        with self._lock:
            if self.clear_on_focus_loss:
                self.clear()
            else:
                self._app_active = False

    def on_app_focus_gained(self) -> None:
        with self._lock:
            self._app_active = True

    def on_app_minimized(self) -> None:
        with self._lock:
            if self.clear_on_minimize:
                self.clear()
            else:
                self._app_active = False

    def on_app_restored(self) -> None:
        with self._lock:
            self._app_active = True

    def is_expired(self) -> bool:
        with self._lock:
            if self._entry is None:
                return False
            return (time.time() - self._entry.last_access_at) > self.ttl_seconds

    def _expire_if_needed(self) -> None:
        if self._entry is None:
            return

        if (time.time() - self._entry.last_access_at) > self.ttl_seconds:
            self.clear()


class OSKeyringStore:
    def __init__(self, service_name: str = "CryptoSafeManager"):
        self.service_name = service_name

    def is_available(self) -> bool:
        return keyring is not None

    def set_secret(self, name: str, value: str) -> None:
        if keyring is None:
            raise RuntimeError("keyring недоступен")
        keyring.set_password(self.service_name, name, value)

    def get_secret(self, name: str) -> Optional[str]:
        if keyring is None:
            return None
        return keyring.get_password(self.service_name, name)

    def delete_secret(self, name: str) -> None:
        if keyring is None:
            return
        try:
            keyring.delete_password(self.service_name, name)
        except Exception:
            pass