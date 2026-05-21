def test_db_schema_exists(test_db):
    with test_db.connection() as c:
        v = c.execute("PRAGMA user_version;").fetchone()[0]
        assert v == 6

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
        assert "shared_entries" in tables
        assert "import_export_history" in tables
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

        shared_columns = {
            row["name"]
            for row in c.execute("PRAGMA table_info(shared_entries)").fetchall()
        }
        assert {
            "shared_id",
            "original_entry_id",
            "encryption_method",
            "recipient_info",
            "permissions",
            "shared_at",
            "expires_at",
        }.issubset(shared_columns)

        history_columns = {
            row["name"]
            for row in c.execute("PRAGMA table_info(import_export_history)").fetchall()
        }
        assert {
            "operation_type",
            "format",
            "encryption_used",
            "entry_count",
            "file_size",
            "checksum",
            "verification_status",
        }.issubset(history_columns)
