from src.core.config import ConfigManager
from src.gui.setup_wizard import SetupWizard
from src.gui.main_window import MainWindow


def main():
    cfg = ConfigManager("config.json")
    cfg.load()

    if not cfg.get("db_path"):
        root = MainWindow()
        root.withdraw()

        wiz = SetupWizard(root)
        root.wait_window(wiz)

        if not wiz.result:
            root.destroy()
            return

        # сохраняем только путь БД и заглушку параметров
        cfg.set("db_path", wiz.result["db_path"])
        cfg.set("kdf_iterations", wiz.result["iterations"])
        cfg.save()

        root.destroy()

    MainWindow().mainloop()


if __name__ == "__main__":
    main()
