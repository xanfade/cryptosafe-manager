from __future__ import annotations

from dataclasses import dataclass

from .hardening_config import SecurityHardeningSettings
from src.core.events import SecurityHardeningEvent

PROFILE_STANDARD = "standard"
PROFILE_ENHANCED = "enhanced"
PROFILE_PARANOID = "paranoid"
ALL_PROFILES = {PROFILE_STANDARD, PROFILE_ENHANCED, PROFILE_PARANOID}


@dataclass
class ProfileMigrationResult:
    success: bool
    errors: list[str]
    warnings: list[str]
    changed_keys: list[str]


def build_profile(profile: str) -> SecurityHardeningSettings:
    p = (profile or "").strip().lower()
    if p not in ALL_PROFILES:
        raise ValueError(f"Unknown security profile: {profile}")

    if p == PROFILE_STANDARD:
        return SecurityHardeningSettings()

    if p == PROFILE_ENHANCED:
        return SecurityHardeningSettings(
            minimum_auth_delay_sec=0.4,
            auto_lock_timeout_sec=180,
            activity_sensitivity="high",
            panic_stealth_fake_error=True,
        )

    return SecurityHardeningSettings(
        minimum_auth_delay_sec=0.7,
        memory_locking=True,
        memory_auto_wipe=True,
        auto_lock_timeout_sec=60,
        activity_sensitivity="high",
        panic_close_app_on_activate=True,
        panic_stealth_fake_error=True,
    )


class SecurityProfileManager:
    ACTIVE_PROFILE_KEY = "security.profile.active"

    def __init__(self, settings_service, event_bus=None):
        self.settings_service = settings_service
        self.event_bus = event_bus

    def get_active_profile(self) -> str:
        profile = str(self.settings_service.get(self.ACTIVE_PROFILE_KEY, PROFILE_STANDARD) or PROFILE_STANDARD).strip().lower()
        return profile if profile in ALL_PROFILES else PROFILE_STANDARD

    def preview_profile_change(self, target_profile: str) -> list[dict[str, str]]:
        target_cfg = build_profile(target_profile)
        current_cfg = SecurityHardeningSettings.from_settings(self.settings_service)
        current_pairs = current_cfg.as_setting_pairs()
        target_pairs = target_cfg.as_setting_pairs()
        changes = []
        for key in sorted(target_pairs):
            old_value = str(current_pairs.get(key, ""))
            new_value = str(target_pairs[key])
            if old_value != new_value:
                changes.append({"key": key, "from": old_value, "to": new_value})
        if self.get_active_profile() != target_profile:
            changes.append({"key": self.ACTIVE_PROFILE_KEY, "from": self.get_active_profile(), "to": target_profile})
        return changes

    def apply_profile(self, target_profile: str) -> ProfileMigrationResult:
        target_profile = (target_profile or "").strip().lower()
        try:
            target_cfg = build_profile(target_profile)
        except ValueError as exc:
            return ProfileMigrationResult(False, [str(exc)], [], [])

        errors, warnings = target_cfg.validate()
        if errors:
            return ProfileMigrationResult(False, errors, warnings, [])

        pairs = target_cfg.as_setting_pairs()
        pairs[self.ACTIVE_PROFILE_KEY] = target_profile
        changed_keys = sorted(pairs.keys())
        snapshot = self.settings_service.snapshot(changed_keys)

        try:
            self.settings_service.set_many(pairs, encrypted=False)
            applied = SecurityHardeningSettings.from_settings(self.settings_service)
            applied_errors, applied_warnings = applied.validate()
            warnings.extend(applied_warnings)
            if applied_errors:
                raise ValueError("; ".join(applied_errors))
            if self.event_bus:
                self.event_bus.publish(
                    SecurityHardeningEvent(
                        action="profile_apply",
                        profile=target_profile,
                        status="ok",
                    )
                )
            return ProfileMigrationResult(True, [], _deduplicate(warnings), changed_keys)
        except Exception as exc:
            self.settings_service.restore_snapshot(snapshot)
            if self.event_bus:
                self.event_bus.publish(
                    SecurityHardeningEvent(
                        action="profile_apply",
                        profile=target_profile,
                        status="rollback",
                        details=str(exc),
                    )
                )
            return ProfileMigrationResult(False, [f"Profile migration failed and was rolled back: {exc}"], _deduplicate(warnings), [])


def _deduplicate(items: list[str]) -> list[str]:
    out: list[str] = []
    seen = set()
    for item in items:
        if item in seen:
            continue
        out.append(item)
        seen.add(item)
    return out
