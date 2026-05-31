from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SecurityHardeningSettings:
    enabled: bool = True
    constant_time_compare: bool = True
    normalize_auth_timing: bool = True
    minimum_auth_delay_sec: float = 0.25
    memory_locking: bool = True
    memory_auto_wipe: bool = True
    activity_monitor_enabled: bool = True
    auto_lock_timeout_sec: int = 300
    activity_sensitivity: str = "medium"
    activity_device_type: str = "desktop"
    panic_mode_enabled: bool = True
    panic_lock_on_activate: bool = True
    panic_clear_clipboard_on_activate: bool = True
    panic_close_windows_on_activate: bool = True
    panic_close_app_on_activate: bool = False
    panic_stealth_fake_error: bool = False
    panic_stealth_decoy_command: str = ""
    panic_stealth_redirect_url: str = ""

    @classmethod
    def from_settings(cls, settings_service) -> "SecurityHardeningSettings":
        def _bool(value, default: bool) -> bool:
            if value is None:
                return default
            if isinstance(value, bool):
                return value
            return str(value).strip().lower() in {"1", "true", "yes", "on"}

        def _int(value, default: int) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        def _float(value, default: float) -> float:
            try:
                return float(value)
            except (TypeError, ValueError):
                return default

        timeout = _int(
            settings_service.get("security.hardening.activity_monitor.auto_lock_timeout_sec", None),
            _int(settings_service.get("security.auto_lock_timeout_sec", 300), 300),
        )

        return cls(
            enabled=_bool(settings_service.get("security.hardening.enabled", True), True),
            constant_time_compare=_bool(settings_service.get("security.hardening.constant_time_compare", True), True),
            normalize_auth_timing=_bool(settings_service.get("security.hardening.normalize_auth_timing", True), True),
            minimum_auth_delay_sec=max(
                0.0,
                _float(settings_service.get("security.hardening.minimum_auth_delay_sec", 0.25), 0.25),
            ),
            memory_locking=_bool(settings_service.get("security.hardening.memory_guard.lock_memory", True), True),
            memory_auto_wipe=_bool(settings_service.get("security.hardening.memory_guard.auto_wipe", True), True),
            activity_monitor_enabled=_bool(
                settings_service.get("security.hardening.activity_monitor.enabled", True),
                True,
            ),
            auto_lock_timeout_sec=max(60, min(28800, timeout)),
            activity_sensitivity=str(
                settings_service.get("security.hardening.activity_monitor.sensitivity", "medium")
            ).strip().lower(),
            activity_device_type=str(
                settings_service.get("security.hardening.activity_monitor.device_type", "desktop")
            ).strip().lower(),
            panic_mode_enabled=_bool(settings_service.get("security.hardening.panic_mode.enabled", True), True),
            panic_lock_on_activate=_bool(
                settings_service.get("security.hardening.panic_mode.lock_on_activate", True),
                True,
            ),
            panic_clear_clipboard_on_activate=_bool(
                settings_service.get("security.hardening.panic_mode.clear_clipboard_on_activate", True),
                True,
            ),
            panic_close_windows_on_activate=_bool(
                settings_service.get("security.hardening.panic_mode.close_windows_on_activate", True),
                True,
            ),
            panic_close_app_on_activate=_bool(
                settings_service.get("security.hardening.panic_mode.close_app", False),
                False,
            ),
            panic_stealth_fake_error=_bool(
                settings_service.get("security.hardening.panic_mode.stealth.fake_error", False),
                False,
            ),
            panic_stealth_decoy_command=str(
                settings_service.get("security.hardening.panic_mode.stealth.decoy_command", "") or ""
            ),
            panic_stealth_redirect_url=str(
                settings_service.get("security.hardening.panic_mode.stealth.redirect_url", "") or ""
            ),
        )

    def as_setting_pairs(self) -> dict[str, str]:
        return {
            "security.hardening.enabled": str(self.enabled).lower(),
            "security.hardening.constant_time_compare": str(self.constant_time_compare).lower(),
            "security.hardening.normalize_auth_timing": str(self.normalize_auth_timing).lower(),
            "security.hardening.minimum_auth_delay_sec": str(self.minimum_auth_delay_sec),
            "security.hardening.memory_guard.lock_memory": str(self.memory_locking).lower(),
            "security.hardening.memory_guard.auto_wipe": str(self.memory_auto_wipe).lower(),
            "security.hardening.activity_monitor.enabled": str(self.activity_monitor_enabled).lower(),
            "security.hardening.activity_monitor.auto_lock_timeout_sec": str(self.auto_lock_timeout_sec),
            "security.hardening.activity_monitor.sensitivity": self.activity_sensitivity,
            "security.hardening.activity_monitor.device_type": self.activity_device_type,
            "security.hardening.panic_mode.enabled": str(self.panic_mode_enabled).lower(),
            "security.hardening.panic_mode.lock_on_activate": str(self.panic_lock_on_activate).lower(),
            "security.hardening.panic_mode.clear_clipboard_on_activate": str(
                self.panic_clear_clipboard_on_activate
            ).lower(),
            "security.hardening.panic_mode.close_windows_on_activate": str(
                self.panic_close_windows_on_activate
            ).lower(),
            "security.hardening.panic_mode.close_app": str(self.panic_close_app_on_activate).lower(),
            "security.hardening.panic_mode.stealth.fake_error": str(self.panic_stealth_fake_error).lower(),
            "security.hardening.panic_mode.stealth.decoy_command": self.panic_stealth_decoy_command,
            "security.hardening.panic_mode.stealth.redirect_url": self.panic_stealth_redirect_url,
        }

    def validate(self) -> tuple[list[str], list[str]]:
        errors: list[str] = []
        warnings: list[str] = []

        if not 60 <= int(self.auto_lock_timeout_sec) <= 28800:
            errors.append("Auto-lock timeout must be between 60 and 28800 seconds.")
        if self.activity_sensitivity not in {"low", "medium", "high"}:
            errors.append("Activity sensitivity must be low, medium, or high.")
        if self.activity_device_type not in {"desktop", "laptop"}:
            errors.append("Activity device type must be desktop or laptop.")
        if float(self.minimum_auth_delay_sec) < 0.0:
            errors.append("Minimum authentication delay must be non-negative.")

        if not self.enabled:
            errors.append("Security hardening cannot be disabled in secure mode.")

        enabled_layers = sum(
            1
            for v in (
                self.constant_time_compare,
                self.normalize_auth_timing,
                self.memory_locking,
                self.memory_auto_wipe,
                self.activity_monitor_enabled,
                self.panic_mode_enabled,
            )
            if v
        )
        if enabled_layers < 2:
            errors.append("Defense in depth violation: at least two hardening layers must remain enabled.")

        if self.enabled and self.panic_mode_enabled and not self.panic_lock_on_activate:
            errors.append("Insecure combination: panic mode requires lock-on-activate.")

        defaults = SecurityHardeningSettings()
        if self != defaults:
            warnings.append("Non-default security settings are active.")

        if self.auto_lock_timeout_sec > 1800:
            warnings.append("Long auto-lock timeout may increase exposure risk.")

        return errors, warnings
