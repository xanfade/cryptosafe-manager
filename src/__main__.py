import base64
import os
import traceback
import tkinter as tk
from tkinter import messagebox

from src.core.audit import AuditLogger, AuditLogSigner
from src.core.config import ConfigManager
from src.core.events import EventBus
from src.core.key_manager import KeyManager
from src.core.crypto.authentication import AuthenticationService
from src.core.security import (
    ActivityMonitor,
    MemoryGuard,
    PanicMode,
    PlatformSecurityManager,
    SecurityHardeningSettings,
    SecurityProfileManager,
)
from src.core.settings_repo import SettingsService
from src.core.state_manager import StateManager
from src.database.db import Database
from src.gui.login_dialog import LoginDialog
from src.gui.main_window import MainWindow
from src.gui.setup_wizard import SetupWizard


def main():
    cfg = ConfigManager("config.json")
    cfg.load()

    root = tk.Tk()
    root.withdraw()

    if not cfg.get("db_path"):
        wiz = SetupWizard(root)
        root.wait_window(wiz)

        if not getattr(wiz, "result", None):
            root.destroy()
            return

        cfg.set("db_path", wiz.result["db_path"])
        cfg.save()

        db = Database(wiz.result["db_path"])
        db.migrate()

        km = KeyManager(db)
        km.initialize_master_password(wiz.result["master_password"])

    db_path = cfg.get("db_path")
    db = Database(db_path)
    db.migrate()

    event_bus = EventBus()

    key_manager = KeyManager(db)

    state_manager = StateManager()

    settings_key_b64 = cfg.get("settings_secret_key")
    if not settings_key_b64:
        raw_settings_key = os.urandom(32)
        settings_key_b64 = base64.b64encode(raw_settings_key).decode("utf-8")
        cfg.set("settings_secret_key", settings_key_b64)
        cfg.save()
    else:
        raw_settings_key = base64.b64decode(settings_key_b64)

    if len(raw_settings_key) != 32:
        raise ValueError("settings_secret_key должен декодироваться ровно в 32 байта")

    fernet_key = SettingsService.build_fernet_key(raw_settings_key)
    settings_service = SettingsService(db, fernet_key)

    hardening = SecurityHardeningSettings.from_settings(settings_service)
    for key, value in hardening.as_setting_pairs().items():
        if settings_service.get(key) is None:
            settings_service.set(key, value, encrypted=False)
    profile_manager = SecurityProfileManager(settings_service, event_bus=event_bus)
    if settings_service.get(SecurityProfileManager.ACTIVE_PROFILE_KEY) is None:
        settings_service.set(SecurityProfileManager.ACTIVE_PROFILE_KEY, "standard", encrypted=False)

    hardening = SecurityHardeningSettings.from_settings(settings_service)
    errors, _warnings = hardening.validate()
    if errors:
        migration = profile_manager.apply_profile("paranoid")
        if not migration.success:
            raise ValueError(f"Invalid security configuration and failed to recover: {'; '.join(migration.errors)}")
        hardening = SecurityHardeningSettings.from_settings(settings_service)

    if settings_service.get("ui.tray.start_minimized") is None:
        settings_service.set("ui.tray.start_minimized", "false", encrypted=False)
    if settings_service.get("security.platform.strict") is None:
        settings_service.set("security.platform.strict", "true", encrypted=False)

    # Keep the legacy key for backward compatibility with existing deployments.
    if settings_service.get("security.auto_lock_timeout_sec") is None:
        settings_service.set("security.auto_lock_timeout_sec", str(hardening.auto_lock_timeout_sec), encrypted=False)

    strict_platform = str(settings_service.get("security.platform.strict", "true")).strip().lower() in {"1", "true", "yes", "on"}
    platform_security = PlatformSecurityManager(strict=strict_platform)
    platform_warnings = platform_security.enforce()

    state_manager.set_inactivity_timeout(hardening.auto_lock_timeout_sec)
    activity_monitor = ActivityMonitor(
        enabled=hardening.enabled and hardening.activity_monitor_enabled,
        auto_lock_timeout_sec=hardening.auto_lock_timeout_sec,
        sensitivity=hardening.activity_sensitivity,
        device_type=hardening.activity_device_type,
    )
    _memory_guard = MemoryGuard(
        enable_locking=hardening.enabled and hardening.memory_locking,
        enable_auto_wipe=hardening.enabled and hardening.memory_auto_wipe,
    )
    panic_mode = PanicMode(
        enabled=hardening.enabled and hardening.panic_mode_enabled,
        lock_on_activate=hardening.panic_lock_on_activate,
        clear_clipboard_on_activate=hardening.panic_clear_clipboard_on_activate,
        close_windows_on_activate=hardening.panic_close_windows_on_activate,
        close_app_on_activate=hardening.panic_close_app_on_activate,
        stealth_fake_error=hardening.panic_stealth_fake_error,
        stealth_decoy_command=hardening.panic_stealth_decoy_command,
        stealth_redirect_url=hardening.panic_stealth_redirect_url,
    )

    auth_service = AuthenticationService(
        key_manager=key_manager,
        state_manager=state_manager,
        event_bus=event_bus,
        activity_monitor=activity_monitor,
        panic_mode=panic_mode,
        normalize_auth_timing_enabled=hardening.enabled and hardening.normalize_auth_timing,
        minimum_auth_delay_sec=hardening.minimum_auth_delay_sec,
    )
    auth_service.memory_guard = _memory_guard

    if key_manager.is_initialized():
        login = LoginDialog(
            root,
            auth_service,
            secure_entry_mode=(
                platform_security.capabilities.platform_name == "Windows"
                and platform_security.capabilities.secure_desktop
            ),
        )
        root.wait_window(login)

        if not getattr(login, "result", None):
            root.destroy()
            return

    audit_logger = AuditLogger(db, AuditLogSigner.from_key_manager(key_manager))
    audit_logger.subscribe(event_bus)
    verification = audit_logger.verify_integrity()
    if not verification["verified"]:
        audit_logger.handle_verification_result(
            verification,
            source="startup",
            notify_callback=lambda _result: messagebox.showwarning(
                "Audit integrity",
                "Audit log integrity verification failed. Review the audit log immediately.",
                parent=root,
            ),
        )
    audit_logger.log_event(
        "SYSTEM_STARTUP",
        "INFO",
        "application",
        {"message": "Application started", "platform_warnings": platform_warnings},
        user_id="system",
    )

    try:
        if root.winfo_exists():
            root.destroy()
    except tk.TclError:
        pass

    app = MainWindow(
        db=db,
        key_manager=key_manager,
        auth_service=auth_service,
        event_bus=event_bus,
        audit_logger=audit_logger,
        start_minimized_to_tray=str(settings_service.get("ui.tray.start_minimized", "false")).lower() in {"1", "true", "yes", "on"},
    )
    app.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("\n[ERROR] crashed:\n")
        traceback.print_exc()
