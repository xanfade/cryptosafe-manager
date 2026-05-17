from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass, field
from enum import Enum

from src.core.vault.encryption_service import VaultEncryptionService


CLIPBOARD_SETTINGS_KEY = "clipboard.settings"


class ClipboardSecurityLevel(str, Enum):
    BASIC = "basic"
    ADVANCED = "advanced"
    PARANOID = "paranoid"


CLIPBOARD_PRESETS = {
    ClipboardSecurityLevel.BASIC.value: {
        "auto_clear_timeout_sec": 60,
        "notifications_enabled": True,
        "security_level": ClipboardSecurityLevel.BASIC.value,
        "allowed_applications_whitelist": [],
    },
    ClipboardSecurityLevel.ADVANCED.value: {
        "auto_clear_timeout_sec": 30,
        "notifications_enabled": True,
        "security_level": ClipboardSecurityLevel.ADVANCED.value,
        "allowed_applications_whitelist": [],
    },
    ClipboardSecurityLevel.PARANOID.value: {
        "auto_clear_timeout_sec": 5,
        "notifications_enabled": True,
        "security_level": ClipboardSecurityLevel.PARANOID.value,
        "allowed_applications_whitelist": [],
    },
}


@dataclass(slots=True)
class ClipboardSettings:
    auto_clear_timeout_sec: int | None = 30
    notifications_enabled: bool = True
    security_level: str = ClipboardSecurityLevel.ADVANCED.value
    allowed_applications_whitelist: list[str] = field(default_factory=list)

    def normalized(self) -> "ClipboardSettings":
        timeout = self.auto_clear_timeout_sec

        if timeout is not None:
            timeout = int(timeout)

            if timeout < 5:
                timeout = 5

            if timeout > 300:
                timeout = 300

        level = self.security_level
        allowed_levels = {item.value for item in ClipboardSecurityLevel}

        if level not in allowed_levels:
            level = ClipboardSecurityLevel.ADVANCED.value

        return ClipboardSettings(
            auto_clear_timeout_sec=timeout,
            notifications_enabled=bool(self.notifications_enabled),
            security_level=level,
            allowed_applications_whitelist=[
                app.strip()
                for app in self.allowed_applications_whitelist
                if app and app.strip()
            ],
        )


class ClipboardSettingsRepository:
    def __init__(self, db, key_manager):
        self.db = db
        self.crypto = VaultEncryptionService(key_manager)

    def get(self) -> ClipboardSettings:
        raw_value = self.db.get_setting(CLIPBOARD_SETTINGS_KEY)

        if not raw_value:
            return ClipboardSettings()

        try:
            encrypted_payload = base64.b64decode(raw_value.encode("utf-8"))
            decrypted_payload = self.crypto.decrypt(encrypted_payload)
            data = json.loads(decrypted_payload.decode("utf-8"))

            return ClipboardSettings(
                auto_clear_timeout_sec=data.get("auto_clear_timeout_sec", 30),
                notifications_enabled=data.get("notifications_enabled", True),
                security_level=data.get("security_level", "advanced"),
                allowed_applications_whitelist=data.get(
                    "allowed_applications_whitelist",
                    [],
                ),
            ).normalized()

        except Exception:
            return ClipboardSettings()

    def save(self, settings: ClipboardSettings) -> ClipboardSettings:
        settings = settings.normalized()

        plain_payload = json.dumps(
            asdict(settings),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        encrypted_payload = self.crypto.encrypt(plain_payload)
        stored_value = base64.b64encode(encrypted_payload).decode("utf-8")

        self.db.set_setting(
            CLIPBOARD_SETTINGS_KEY,
            stored_value,
            encrypted=1,
        )

        return settings