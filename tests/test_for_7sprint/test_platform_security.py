from __future__ import annotations

import pytest

from src.core.security.platform_security import PlatformCapabilities, PlatformSecurityManager


def test_windows_platform_requirements_pass():
    mgr = PlatformSecurityManager(strict=True)
    caps = PlatformCapabilities(
        platform_name="Windows",
        credential_guard_api=True,
        secure_desktop=True,
        windows_hello=False,
    )
    errors, warnings = mgr.validate(caps)
    assert errors == []
    assert any("bonus" in item.lower() for item in warnings)


def test_macos_platform_requirements_enforced():
    mgr = PlatformSecurityManager(strict=True)
    caps = PlatformCapabilities(
        platform_name="Darwin",
        keychain_services=False,
        gatekeeper_notarization=False,
        packaged_app=True,
        touch_id=False,
    )
    errors, warnings = mgr.validate(caps)
    assert any("keychain" in item.lower() for item in errors)
    assert any("notarization" in item.lower() for item in errors)
    assert any("bonus" in item.lower() for item in warnings)


def test_linux_platform_requirements_enforced():
    mgr = PlatformSecurityManager(strict=True)
    caps = PlatformCapabilities(
        platform_name="Linux",
        kernel_keyring=False,
        systemd_integration=False,
        selinux_or_apparmor=False,
    )
    errors, _warnings = mgr.validate(caps)
    assert len(errors) == 3


def test_enforce_fails_secure_when_strict():
    mgr = PlatformSecurityManager(strict=True)
    mgr.capabilities = PlatformCapabilities(
        platform_name="Linux",
        kernel_keyring=False,
        systemd_integration=False,
        selinux_or_apparmor=False,
    )
    with pytest.raises(RuntimeError, match="Platform hardening requirements failed"):
        mgr.enforce()


def test_enforce_graceful_degradation_when_not_strict():
    mgr = PlatformSecurityManager(strict=False)
    mgr.capabilities = PlatformCapabilities(
        platform_name="Linux",
        kernel_keyring=False,
        systemd_integration=False,
        selinux_or_apparmor=False,
    )
    warnings = mgr.enforce()
    assert isinstance(warnings, list)
