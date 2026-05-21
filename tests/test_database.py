def test_db_schema_exists(test_db):
    with test_db.connection() as c:
        v = c.execute("PRAGMA user_version;").fetchone()[0]
        assert v == 5

        tables = {
            row[0]
            for row in c.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

        assert "vault_entries" in tables or "vault_entries_new" in tables
        assert "audit_log" in tables
        assert "audit_public_keys" in tables
        assert "audit_log_archive" in tables
        assert "audit_security_log" in tables
        assert "settings" in tables
        assert "key_store" in tables

        audit_columns = {
            row["name"]
            for row in c.execute("PRAGMA table_info(audit_log)").fetchall()
        }
        assert {
            "sequence_number",
            "previous_hash",
            "entry_data",
            "entry_hash",
            "signature",
            "signature_algorithm",
            "event_type",
            "severity",
        }.issubset(audit_columns)
