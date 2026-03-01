import traceback
import tkinter as tk

from src.core.config import ConfigManager
from src.gui.setup_wizard import SetupWizard
from src.gui.main_window import MainWindow
from src.database.db import Database

def main():

    cfg = ConfigManager("config.json")
    cfg.load()

    # 1) Первый запуск -> мастер
    if not cfg.get("db_path"):

        root = tk.Tk()
        root.withdraw()

        wiz = SetupWizard(root)
        root.wait_window(wiz)


        if not getattr(wiz, "result", None):
            root.destroy()
            return

        cfg.set("db_path", wiz.result["db_path"])
        cfg.set("kdf_iterations", wiz.result["iterations"])
        cfg.save()
        db_path = wiz.result["db_path"]

        cfg.set("db_path", db_path)
        cfg.set("kdf_iterations", wiz.result["iterations"])
        cfg.save()

        # создаём файл БД и таблицы прямо сейчас
        db = Database(db_path)
        db.migrate()


        root.destroy()

    # 2) Запуск главного окна

    app = MainWindow()
    app.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("\n[ERROR] crashed:\n")
        traceback.print_exc()
