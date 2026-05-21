import json
import sqlite3
import time

from src.core.audit import AuditLogger, AuditLogSigner, AuditLogVerifier, SignedJsonAuditVerifier
from src.core.audit.audit_exporter import AuditExportManager
from src.core.events import EventBus
from src.database.db import Database


def allow_audit_mutation(conn, allowed: bool) -> None:
    conn.execute(
        "UPDATE audit_write_control SET allow_mutation = ? WHERE id = 1",
        (1 if allowed else 0,),
    )


def test_integrity_1000_entries_detects_database_tampering(test_db):
    audit = AuditLogger(
        test_db,
        AuditLogSigner(b"validation audit key material"),
        config={"max_entries": 0, "max_age_days": 0},
    )
    for index in range(1000):
        audit.log_event("VALIDATION_INTEGRITY", "INFO", "test", {"index": index}, user_id="system")

    with test_db.connection() as conn:
        row = conn.execute(
            "SELECT sequence_number, entry_data FROM audit_log WHERE sequence_number = 500"
        ).fetchone()
        entry = json.loads(bytes(row["entry_data"]).decode("utf-8"))
        entry["details"]["index"] = "tampered"
        allow_audit_mutation(conn, True)
        try:
            conn.execute(
                "UPDATE audit_log SET entry_data = ? WHERE sequence_number = ?",
                (json.dumps(entry, sort_keys=True).encode("utf-8"), row["sequence_number"]),
            )
        finally:
            allow_audit_mutation(conn, False)
        conn.commit()

    result = audit.verify_integrity()

    assert result["verified"] is False
    assert result["invalid_entries"]


def test_performance_10000_events_measures_throughput_and_verification(test_db):
    audit = AuditLogger(
        test_db,
        AuditLogSigner(b"validation audit key material"),
        config={"max_entries": 0, "max_age_days": 0},
    )

    start = time.perf_counter()
    for index in range(10_000):
        audit.log_event("VALIDATION_PERF", "INFO", "perf", {"index": index}, user_id="system")
    logging_elapsed = time.perf_counter() - start

    start = time.perf_counter()
    verification = audit.verify_recent(limit=1000)
    verification_elapsed = time.perf_counter() - start

    assert 10_000 / logging_elapsed > 100
    assert verification["verified"] is True
    assert verification["total_entries"] == 1000
    assert verification_elapsed < 1.0


def test_export_import_signed_json_with_independent_verifier(tmp_path):
    source_db = Database(str(tmp_path / "source.db"))
    imported_db = Database(str(tmp_path / "imported.db"))
    source_db.migrate()
    imported_db.migrate()
    signer = AuditLogSigner(b"validation audit key material")
    try:
        audit = AuditLogger(source_db, signer, config={"max_entries": 0, "max_age_days": 0})
        for index in range(20):
            audit.log_event("VALIDATION_EXPORT", "INFO", "test", {"index": index}, user_id="system")

        with source_db.connection() as conn:
            rows = conn.execute("SELECT * FROM audit_log ORDER BY sequence_number").fetchall()
            public_key = conn.execute(
                "SELECT algorithm, public_key FROM audit_public_keys WHERE key_id = 'current'"
            ).fetchone()

        payload, encrypted = AuditExportManager(source_db).build_export(
            rows,
            "json",
            public_key={"algorithm": public_key["algorithm"], "public_key": public_key["public_key"]},
            encrypt_if_sensitive=False,
        )

        independent = SignedJsonAuditVerifier().verify_export(payload)
        imported_count = AuditExportManager(imported_db).import_signed_json(payload)
        imported_result = AuditLogVerifier(imported_db, signer).verify_range().to_dict()

        assert encrypted is False
        assert independent["verified"] is True
        assert imported_count == len(rows)
        assert imported_result["verified"] is True
    finally:
        source_db.close()
        imported_db.close()


def test_failure_recovery_database_corruption_reports_options(test_db):
    audit = AuditLogger(test_db, AuditLogSigner(b"validation audit key material"))
    audit.log_event("VALIDATION_RECOVERY", "INFO", "test", {"ok": True}, user_id="system")

    with test_db.connection() as conn:
        conn.execute("DROP TABLE audit_log")
        conn.commit()

    result = audit.verify_integrity()

    assert result["verified"] is False
    assert result["errors"]
    assert "restore_from_backup" in result["recovery_options"]


def test_security_attempts_are_logged_and_sql_injection_is_blocked(test_db):
    audit = AuditLogger(test_db, AuditLogSigner(b"validation audit key material"))
    malicious_event_type = "AUTH_LOGIN_FAILURE'; DROP TABLE audit_log; --"
    audit.log_security_attempt(
        "sql_injection",
        "audit_viewer",
        {"input": malicious_event_type, "blocked": True},
        user_id="local",
    )
    audit.log_security_attempt(
        "privilege_escalation",
        "access_control",
        {"requested_role": "admin", "blocked": True},
        user_id="local",
    )

    with test_db.connection() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE event_type = ?",
            ("SECURITY_ATTEMPT_BLOCKED",),
        ).fetchall()
        table_exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'audit_log'"
        ).fetchone()
        secure_count = conn.execute(
            "SELECT COUNT(*) AS count FROM audit_security_log WHERE event_type = 'SECURITY_ATTEMPT_BLOCKED'"
        ).fetchone()["count"]

    assert table_exists is not None
    assert len(rows) == 2
    assert secure_count == 2


def test_audit_log_is_append_only_without_bypass(test_db):
    audit = AuditLogger(test_db, AuditLogSigner(b"validation audit key material"))
    audit.log_event("APPEND_ONLY", "INFO", "test", {"ok": True}, user_id="system")

    with test_db.connection() as conn:
        row = conn.execute(
            "SELECT sequence_number, entry_data FROM audit_log WHERE event_type = 'APPEND_ONLY'"
        ).fetchone()
        try:
            conn.execute(
                "UPDATE audit_log SET entry_data = ? WHERE sequence_number = ?",
                (row["entry_data"], row["sequence_number"]),
            )
        except sqlite3.DatabaseError as exc:
            assert "append-only" in str(exc)
        else:
            raise AssertionError("audit_log update should be blocked")

        try:
            conn.execute(
                "DELETE FROM audit_log WHERE sequence_number = ?",
                (row["sequence_number"],),
            )
        except sqlite3.DatabaseError as exc:
            assert "append-only" in str(exc)
        else:
            raise AssertionError("audit_log delete should be blocked")


def test_forward_security_uses_distinct_entry_public_keys(test_db):
    audit = AuditLogger(
        test_db,
        AuditLogSigner(b"validation audit key material"),
        config={"max_entries": 0, "max_age_days": 0},
    )
    for index in range(4):
        audit.log_event("FORWARD_SECURE", "INFO", "test", {"index": index}, user_id="system")

    with test_db.connection() as conn:
        key_rows = conn.execute(
            """
            SELECT sequence_number, public_key
            FROM audit_entry_keys
            ORDER BY sequence_number
            """
        ).fetchall()
        export_rows = conn.execute("SELECT * FROM audit_log ORDER BY sequence_number").fetchall()
        public_key = conn.execute(
            "SELECT algorithm, public_key FROM audit_public_keys WHERE key_id = 'current'"
        ).fetchone()

    public_keys = [row["public_key"] for row in key_rows]
    payload, _encrypted = AuditExportManager(test_db).build_export(
        export_rows,
        "json",
        public_key={"algorithm": public_key["algorithm"], "public_key": public_key["public_key"]},
        encrypt_if_sensitive=False,
    )
    verified = SignedJsonAuditVerifier().verify_export(payload)

    assert len(key_rows) == len(export_rows)
    assert len(set(public_keys)) > 1
    assert verified["verified"] is True


def test_disable_logging_attempt_is_logged_and_blocked(test_db):
    audit = AuditLogger(test_db, AuditLogSigner(b"validation audit key material"))

    try:
        audit.request_disable_logging("settings", "user_requested_disable")
    except PermissionError:
        pass
    else:
        raise AssertionError("disable logging should be blocked")

    with test_db.connection() as conn:
        row = conn.execute(
            """
            SELECT event_type, entry_data
            FROM audit_log
            WHERE event_type = 'SECURITY_ATTEMPT_BLOCKED'
            ORDER BY sequence_number DESC
            LIMIT 1
            """
        ).fetchone()

    entry = json.loads(bytes(row["entry_data"]).decode("utf-8"))
    details = entry["details"]

    assert row["event_type"] == "SECURITY_ATTEMPT_BLOCKED"
    assert details["attempt_type"] == "disable_logging"


def test_import_signed_json_publishes_audit_import_event(tmp_path):
    source_db = Database(str(tmp_path / "source_import.db"))
    target_db = Database(str(tmp_path / "target_import.db"))
    source_db.migrate()
    target_db.migrate()
    signer = AuditLogSigner(b"validation audit key material")
    try:
        source_audit = AuditLogger(source_db, signer, config={"max_entries": 0, "max_age_days": 0})
        source_audit.log_event("IMPORT_SOURCE", "INFO", "test", {"ok": True}, user_id="system")

        with source_db.connection() as conn:
            rows = conn.execute("SELECT * FROM audit_log ORDER BY sequence_number").fetchall()
            public_key = conn.execute(
                "SELECT algorithm, public_key FROM audit_public_keys WHERE key_id = 'current'"
            ).fetchone()

        payload, _encrypted = AuditExportManager(source_db).build_export(
            rows,
            "json",
            public_key={"algorithm": public_key["algorithm"], "public_key": public_key["public_key"]},
            encrypt_if_sensitive=False,
        )

        bus = EventBus()
        target_audit = AuditLogger(target_db, AuditLogSigner(b"validation audit key material"))
        target_audit.subscribe(bus)
        imported = AuditExportManager(target_db, event_bus=bus).import_signed_json(payload)
        bus.drain_async(timeout=5)

        with target_db.connection() as conn:
            row = conn.execute(
                "SELECT event_type FROM audit_log WHERE event_type = 'AUDIT_LOG_IMPORTED' ORDER BY sequence_number DESC LIMIT 1"
            ).fetchone()

        assert imported > 0
        assert row is not None
    finally:
        source_db.close()
        target_db.close()
