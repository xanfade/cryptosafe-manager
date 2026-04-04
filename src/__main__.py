import base64
import os
import traceback
import tkinter as tk

from src.core.audit_logger import AuditLogger
from src.core.config import ConfigManager
from src.core.events import EventBus
from src.core.key_manager import KeyManager
from src.core.crypto.authentication import AuthenticationService
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

    audit_logger = AuditLogger(db)
    audit_logger.subscribe(event_bus)

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

    timeout_raw = settings_service.get("security.auto_lock_timeout_sec", "900")
    try:
        state_manager.set_inactivity_timeout(int(timeout_raw))
    except (TypeError, ValueError):
        state_manager.set_inactivity_timeout(900)

    auth_service = AuthenticationService(
        key_manager=key_manager,
        state_manager=state_manager,
        event_bus=event_bus,
    )

    if key_manager.is_initialized():
        login = LoginDialog(root, auth_service)
        root.wait_window(login)

        if not getattr(login, "result", None):
            root.destroy()
            return

    root.destroy()

    app = MainWindow(
        db=db,
        key_manager=key_manager,
        auth_service=auth_service,
        event_bus=event_bus,
    )
    app.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("\n[ERROR] crashed:\n")
        traceback.print_exc()