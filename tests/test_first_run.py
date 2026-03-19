from src.core.first_run import first_run_init
from src.database.db import Database


def test_first_run_flow_creates_db(tmp_path):
    db_path = tmp_path / "init.db"
    assert first_run_init(str(db_path)) is True

    db = Database(str(db_path))
    with db.connection() as c:
        v = c.execute("PRAGMA user_version;").fetchone()[0]
        assert v == 2
