from __future__ import annotations

import time


class ActivityMonitor:
    MIN_TIMEOUT_SEC = 60
    MAX_TIMEOUT_SEC = 8 * 60 * 60
    DEFAULT_TIMEOUT_SEC = 5 * 60
    SENSITIVITY_FACTORS = {
        "low": 1.5,
        "medium": 1.0,
        "high": 0.7,
    }
    DEVICE_FACTORS = {
        "desktop": 1.0,
        "laptop": 0.8,
    }

    def __init__(
        self,
        enabled: bool = True,
        auto_lock_timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        sensitivity: str = "medium",
        device_type: str = "desktop",
    ):
        self.enabled = bool(enabled)
        self.auto_lock_timeout_sec = self._clamp_timeout(auto_lock_timeout_sec)
        self.sensitivity = self._normalize_sensitivity(sensitivity)
        self.device_type = self._normalize_device_type(device_type)
        self.last_activity_at = time.time()
        self.last_event_type: str | None = None

    def mark_activity(self, event_type: str = "generic") -> None:
        self.last_activity_at = time.time()
        self.last_event_type = event_type

    def configure(
        self,
        enabled: bool | None = None,
        auto_lock_timeout_sec: int | None = None,
        sensitivity: str | None = None,
        device_type: str | None = None,
    ) -> None:
        if enabled is not None:
            self.enabled = bool(enabled)
        if auto_lock_timeout_sec is not None:
            self.auto_lock_timeout_sec = self._clamp_timeout(auto_lock_timeout_sec)
        if sensitivity is not None:
            self.sensitivity = self._normalize_sensitivity(sensitivity)
        if device_type is not None:
            self.device_type = self._normalize_device_type(device_type)

    def is_inactive(self) -> bool:
        if not self.enabled:
            return False
        return (time.time() - self.last_activity_at) >= self.get_effective_timeout_sec()

    def get_effective_timeout_sec(self) -> int:
        base = self.auto_lock_timeout_sec
        sensitivity_factor = self.SENSITIVITY_FACTORS[self.sensitivity]
        device_factor = self.DEVICE_FACTORS[self.device_type]
        effective = int(base * sensitivity_factor * device_factor)
        return self._clamp_timeout(effective)

    @classmethod
    def _clamp_timeout(cls, value: int) -> int:
        return max(cls.MIN_TIMEOUT_SEC, min(cls.MAX_TIMEOUT_SEC, int(value)))

    @classmethod
    def _normalize_sensitivity(cls, value: str) -> str:
        normalized = str(value or "medium").strip().lower()
        return normalized if normalized in cls.SENSITIVITY_FACTORS else "medium"

    @classmethod
    def _normalize_device_type(cls, value: str) -> str:
        normalized = str(value or "desktop").strip().lower()
        return normalized if normalized in cls.DEVICE_FACTORS else "desktop"
