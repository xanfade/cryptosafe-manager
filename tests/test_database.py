def test_db_schema_exists(test_db):
    with test_db.connection() as c:
        v = c.execute("PRAGMA user_version;").fetchone()[0]
        assert v == 3

        tables = {
            row[0]
            for row in c.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

        assert "vault_entries" in tables
        assert "audit_log" in tables
        assert "settings" in tables
        assert "key_store" in tables