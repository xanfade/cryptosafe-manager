from src.gui.main_window import MainWindow
from src.core.events import EventBus
from src.database.db import Database
from src.core.audit_logger import AuditLogger


def main():
    # База (пока просто app.db рядом с проектом)
    db = Database("app.db")
    db.migrate()

    # Шина событий
    bus = EventBus()

    # Заглушка аудита подписывается на события
    audit = AuditLogger(db)
    audit.subscribe(bus)

    # Запуск GUI (позже прокинем bus/db внутрь окна)
    app = MainWindow()
    app.mainloop()


if __name__ == "__main__":
    main()
