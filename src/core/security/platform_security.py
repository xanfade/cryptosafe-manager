from __future__ import annotations

import ctypes
import os
import platform
import sys
from dataclasses import dataclass


@dataclass
class PlatformCapabilities:
    platform_name: str
    # Windows
    credential_guard_api: bool = False
    windows_hello: bool = False  # bonus
    secure_desktop: bool = False
    # macOS
    touch_id: bool = False  # bonus
    keychain_services: bool = False
    gatekeeper_notarization: bool = False
    packaged_app: bool = False
    # Linux
    kernel_keyring: bool = False
    systemd_integration: bool = False
    selinux_or_apparmor: bool = False


class PlatformSecurityManager:
    def __init__(self, strict: bool = True):
        self.strict = bool(strict)
        self.capabilities = self.detect_capabilities()

    @staticmethod
    def detect_capabilities() -> PlatformCapabilities:
        name = platform.system()
        caps = PlatformCapabilities(platform_name=name)

        if name == "Windows":
            caps.credential_guard_api = hasattr(ctypes, "windll")
            caps.secure_desktop = hasattr(ctypes, "windll")
            caps.windows_hello = False
            return caps

        if name == "Darwin":
            caps.keychain_services = True
            caps.packaged_app = bool(getattr(sys, "frozen", False))
            caps.gatekeeper_notarization = bool(os.environ.get("APP_NOTARIZED", "").lower() in {"1", "true", "yes"})
            caps.touch_id = False
            return caps

        if name == "Linux":
            caps.kernel_keyring = os.path.exists("/proc/keys")
            caps.systemd_integration = os.path.exists("/run/systemd/system")
            caps.selinux_or_apparmor = os.path.exists("/sys/fs/selinux") or os.path.exists("/sys/kernel/security/apparmor")
            return caps

        return caps

    def validate(self, capabilities: PlatformCapabilities | None = None) -> tuple[list[str], list[str]]:
        caps = capabilities or self.capabilities
        errors: list[str] = []
        warnings: list[str] = []

        if caps.platform_name == "Windows":
            if not caps.credential_guard_api:
                errors.append("Windows Credential Guard API is unavailable.")
            if not caps.secure_desktop:
                errors.append("Windows Secure Desktop for password entry is unavailable.")
            if not caps.windows_hello:
                warnings.append("Windows Hello integration is unavailable (bonus).")
            return errors, warnings

        if caps.platform_name == "Darwin":
            if not caps.keychain_services:
                errors.append("macOS Keychain Services are unavailable.")
            # Notarization is enforced only for packaged app distributions.
            if caps.packaged_app and not caps.gatekeeper_notarization:
                errors.append("Gatekeeper notarization is not confirmed.")
            if not caps.touch_id:
                warnings.append("Touch ID integration is unavailable (bonus).")
            return errors, warnings

        if caps.platform_name == "Linux":
            if not caps.kernel_keyring:
                errors.append("Linux kernel keyring is unavailable.")
            if not caps.systemd_integration:
                errors.append("systemd integration is unavailable.")
            if not caps.selinux_or_apparmor:
                errors.append("SELinux/AppArmor policy support is unavailable.")
            return errors, warnings

        warnings.append(f"Unknown platform '{caps.platform_name}'; platform-specific hardening cannot be verified.")
        return errors, warnings

    def enforce(self) -> list[str]:
        errors, warnings = self.validate(self.capabilities)
        if self.strict and errors:
            raise RuntimeError("Platform hardening requirements failed: " + "; ".join(errors))
        return warnings
