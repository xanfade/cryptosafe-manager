import os
from src.database.db import Database


def first_run_init(db_path: str) -> bool:
    # Заглушка первичной настройки: создать БД и мигрировать
    # Возвращает True если все ок
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    db = Database(db_path)
    db.migrate()
    return True
