from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

try:
    import keyring
except Exception:
    keyring = None


@dataclass
class CachedKey:
    value: bytearray
    created_at: float
    last_access_at: float


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

    def put(self, key: bytes) -> None:
        now = time.time()
        self._entry = CachedKey(bytearray(key), now, now)

    def get(self) -> Optional[bytes]:
        if self._entry is None:
            return None

        now = time.time()
        if now - self._entry.last_access_at > self.ttl_seconds:
            self.clear()
            return None

        self._entry.last_access_at = now
        return bytes(self._entry.value)

    def has_key(self) -> bool:
        return self.get() is not None

    def touch(self) -> None:
        if self._entry is not None:
            self._entry.last_access_at = time.time()

    def clear(self) -> None:
        if self._entry is not None:
            for i in range(len(self._entry.value)):
                self._entry.value[i] = 0
            self._entry = None

    def is_expired(self) -> bool:
        if self._entry is None:
            return True
        return (time.time() - self._entry.last_access_at) > self.ttl_seconds

    def on_app_focus_lost(self) -> None:
        if self.clear_on_focus_loss:
            self.clear()

    def on_app_focus_gained(self) -> None:
        pass

    def on_app_minimized(self) -> None:
        if self.clear_on_minimize:
            self.clear()

    def on_app_restored(self) -> None:
        pass


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