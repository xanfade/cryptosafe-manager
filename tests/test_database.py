def test_db_schema_exists(test_db):
    # Проверяем user_version и наличие таблиц (подключение + схема)
    with test_db.connection() as c:
        v = c.execute("PRAGMA user_version;").fetchone()[0]
        assert v == 1

        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()}
        assert {"vault_entries", "audit_log", "settings", "key_store"}.issubset(tables)
