import pytest
from src.database.db import Database


@pytest.fixture()
def test_db(tmp_path):
    # Фикстура тестовой базы данных на каждый тест (изолированно)
    db_file = tmp_path / "test.db"
    db = Database(str(db_file))
    db.migrate()
    yield db
    db.close_thread_connection()
