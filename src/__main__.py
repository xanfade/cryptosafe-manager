import traceback
import tkinter as tk

from src.core.config import ConfigManager
from src.core.events import EventBus
from src.core.key_manager import KeyManager
from src.core.crypto.authentication import AuthenticationService
from src.gui.setup_wizard import SetupWizard
from src.gui.login_dialog import LoginDialog
from src.gui.main_window import MainWindow
from src.database.db import Database


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
    auth_service = AuthenticationService(key_manager, event_bus=event_bus)

    login = LoginDialog(root, auth_service)
    root.wait_window(login)

    if not login.result:
        root.destroy()
        return

    root.destroy()

    app = MainWindow()
    app.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("\n[ERROR] crashed:\n")
        traceback.print_exc()