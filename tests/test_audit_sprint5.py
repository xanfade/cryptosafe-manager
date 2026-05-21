import json
import os
import time
import tracemalloc

from src.core.audit import AuditLogger, AuditLogSigner
from src.core.audit.audit_exporter import AuditExportManager
from src.core.events import EntryCreated, LoginFailed
from src.core.audit.log_formatters import row_to_cef, rows_to_csv, rows_to_signed_json
from src.core.events import (
    AppShutdown,
    AuditDataImported,
    ClipboardAutoCleared,
    ConfigurationChanged,
    EntryListViewed,
    EntryRead,
    EventBus,
    PanicModeActivated,
    PasswordChanged,
    TotpAccessed,
    VaultSearchPerformed,
    VaultUnlocked,
)


def allow_audit_mutation(conn, allowed: bool) -> None:
    conn.execute(
        "UPDATE audit_write_control SET allow_mutation = ? WHERE id = 1",
        (1 if allowed else 0,),
    )


def test_audit_log_detects_tampering(test_db):
    signer = AuditLogSigner(b"test master key material for audit")
    audit = AuditLogger(test_db, signer)

    for index in range(10):
        audit.log_event(
            "VAULT_ENTRY_CREATED",
            "INFO",
            "test",
            {"entry": index, "password": "must not leak"},
            entry_id=index,
        )

    with test_db.connection() as conn:
        row = conn.execute(
            "SELECT sequence_number, entry_data FROM audit_log WHERE sequence_number = 5"
        ).fetchone()
        data = json.loads(bytes(row["entry_data"]).decode("utf-8"))
        data["details"]["entry"] = 999
        allow_audit_mutation(conn, True)
        try:
            conn.execute(
                "UPDATE audit_log SET entry_data = ? WHERE sequence_number = ?",
                (json.dumps(data, sort_keys=True).encode("utf-8"), row["sequence_number"]),
            )
        finally:
            allow_audit_mutation(conn, False)
        conn.commit()

    result = audit.verify_integrity()

    assert result["verified"] is False
    assert result["invalid_entries"]


def test_audit_log_redacts_sensitive_details(test_db):
    audit = AuditLogger(test_db, AuditLogSigner(b"test master key material for audit"))

    audit.log_event(
        "CONFIG_CHANGED",
        "INFO",
        "test",
        {"password": "secret", "nested": {"api_key": "abc", "safe": "ok"}},
    )

    with test_db.connection() as conn:
        row = conn.execute(
            "SELECT entry_data FROM audit_log WHERE event_type = 'CONFIG_CHANGED'"
        ).fetchone()

    entry = json.loads(bytes(row["entry_data"]).decode("utf-8"))
    assert entry["details"]["password"] == "[REDACTED]"
    assert entry["details"]["nested"]["api_key"] == "[REDACTED]"
    assert entry["details"]["nested"]["safe"] == "ok"


def test_audit_export_formats_include_signatures(test_db):
    audit = AuditLogger(test_db, AuditLogSigner(b"test master key material for audit"))
    audit.log_event("SYSTEM_STARTUP", "INFO", "test", {"ok": True}, user_id="system")

    with test_db.connection() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY sequence_number").fetchall()
        key = conn.execute("SELECT algorithm, public_key FROM audit_public_keys").fetchone()

    signed_json = json.loads(
        rows_to_signed_json(
            rows,
            {"algorithm": key["algorithm"], "public_key": key["public_key"]},
            exporter="local",
            date_range={"from": "2026-01-01", "to": "2026-01-31"},
        )
    )
    csv_data = rows_to_csv(rows)

    assert signed_json["public_key"]["algorithm"] == "Ed25519"
    assert signed_json["metadata"]["exporter"] == "local"
    assert signed_json["metadata"]["range"]["from"] == "2026-01-01"
    assert signed_json["metadata"]["standard"] == "CEF-like structured audit"
    assert signed_json["entries"][0]["signature"]
    assert "sequence_number,timestamp,event_type" in csv_data


def test_audit_cef_formatter_produces_cef_like_record(test_db):
    audit = AuditLogger(test_db, AuditLogSigner(b"test master key material for audit"))
    audit.log_event("SYSTEM_STARTUP", "INFO", "test", {"ok": True}, user_id="system")

    with test_db.connection() as conn:
        row = conn.execute("SELECT * FROM audit_log ORDER BY sequence_number DESC LIMIT 1").fetchone()

    cef_line = row_to_cef(row)

    assert cef_line.startswith("CEF:0|CryptoSafe|Manager|5|SYSTEM_STARTUP|SYSTEM_STARTUP|3|")
    assert "rt=" in cef_line
    assert "cn1=" in cef_line
    assert "msg=" in cef_line


def test_audit_signing_key_can_be_cleared_from_cache():
    signer = AuditLogSigner(b"test master key material for audit")
    signature = signer.sign(b"entry")

    assert signer.verify(b"entry", signature) is True

    signer.clear()

    try:
        signer.sign(b"entry")
    except RuntimeError as exc:
        assert "not cached" in str(exc)
    else:
        raise AssertionError("cleared audit signing key should not be usable")


def test_audit_event_categories_are_logged_via_event_bus(test_db):
    bus = EventBus()
    audit = AuditLogger(test_db, AuditLogSigner(b"test master key material for audit"))
    audit.subscribe(bus)

    bus.publish(EntryRead(entry_id=7))
    bus.publish(EntryListViewed(count=3))
    bus.publish(PasswordChanged(user="local"))
    bus.publish(VaultUnlocked(user="local"))
    bus.publish(VaultSearchPerformed(query_hash="deadbeefcafebabe", result_count=3))
    bus.publish(AppShutdown(reason="test"))
    bus.publish(ClipboardAutoCleared())
    bus.publish(ConfigurationChanged(setting_key="clipboard", source="settings"))
    bus.publish(AuditDataImported(format="signed_json", entry_count=5))
    bus.publish(PanicModeActivated(reason="test"))
    bus.publish(TotpAccessed(entry_id=7, operation="copy"))
    bus.drain_async(timeout=5)

    with test_db.connection() as conn:
        event_types = {
            row["event_type"]
            for row in conn.execute("SELECT event_type FROM audit_log").fetchall()
        }

    assert "VAULT_ENTRY_READ" in event_types
    assert "VAULT_ENTRY_LIST_VIEWED" in event_types
    assert "AUTH_PASSWORD_CHANGED" in event_types
    assert "SYSTEM_UNLOCK" in event_types
    assert "VAULT_SEARCH_PERFORMED" in event_types
    assert "SYSTEM_SHUTDOWN" in event_types
    assert "CLIPBOARD_AUTO_CLEAR" in event_types
    assert "CONFIG_CHANGED" in event_types
    assert "AUDIT_LOG_IMPORTED" in event_types
    assert "SECURITY_PANIC_MODE" in event_types
    assert "TOTP_ACCESSED" in event_types


def test_audit_entry_has_required_structured_fields_and_hashes_personal_data(test_db):
    audit = AuditLogger(test_db, AuditLogSigner(b"test master key material for audit"))
    audit.log_event(
        "VAULT_ENTRY_UPDATED",
        "INFO",
        "test",
        {"username": "person@example.com", "password": "secret"},
        entry_id=42,
    )

    with test_db.connection() as conn:
        row = conn.execute(
            "SELECT entry_data FROM audit_log WHERE event_type = 'VAULT_ENTRY_UPDATED'"
        ).fetchone()

    entry = json.loads(bytes(row["entry_data"]).decode("utf-8"))

    assert set(
        [
            "timestamp",
            "event_type",
            "severity",
            "user_id",
            "source",
            "details",
            "entry_id",
        ]
    ).issubset(entry)
    assert entry["timestamp"].endswith("+00:00")
    assert entry["details"]["password"] == "[REDACTED]"
    assert entry["details"]["username"].startswith("[HASH:")
    assert "person@example.com" not in json.dumps(entry, ensure_ascii=False)


def test_audit_entries_can_be_reconstructed_in_chronological_order(test_db):
    audit = AuditLogger(test_db, AuditLogSigner(b"test master key material for audit"))
    for index in range(3):
        audit.log_event("CHRONO_TEST", "INFO", "test", {"index": index}, user_id="system")

    with test_db.connection() as conn:
        rows = conn.execute(
            "SELECT sequence_number, timestamp FROM audit_log WHERE event_type = 'CHRONO_TEST' ORDER BY sequence_number"
        ).fetchall()

    sequences = [int(row["sequence_number"]) for row in rows]
    timestamps = [row["timestamp"] for row in rows]

    assert sequences == sorted(sequences)
    assert timestamps == sorted(timestamps)


def test_audit_log_rotation_archives_old_entries(test_db):
    with test_db.connection() as conn:
        conn.execute(
            """
            INSERT INTO settings(setting_key, setting_value, encrypted)
            VALUES ('audit.rotation.max_entries', '3', 0)
            ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value
            """
        )
        conn.commit()

    audit = AuditLogger(test_db, AuditLogSigner(b"test master key material for audit"))
    for index in range(5):
        audit.log_event("SYSTEM_TEST", "INFO", "test", {"index": index}, user_id="system")

    with test_db.connection() as conn:
        live_count = conn.execute("SELECT COUNT(*) AS count FROM audit_log").fetchone()["count"]
        archive = conn.execute(
            "SELECT entry_count, reason, archive_data FROM audit_log_archive ORDER BY archive_id LIMIT 1"
        ).fetchone()

    payload = json.loads(bytes(archive["archive_data"]).decode("utf-8"))

    assert live_count == 3
    assert archive["entry_count"] > 0
    assert archive["reason"] == "max_entries"
    assert payload["format"] == "cryptosafe.audit.archive.v1"
    assert payload["entries"][0]["signature"]


def test_audit_tampering_detection_writes_separate_security_log(test_db):
    audit = AuditLogger(test_db, AuditLogSigner(b"test master key material for audit"))
    audit.log_event("SYSTEM_TEST", "INFO", "test", {"ok": True}, user_id="system")

    with test_db.connection() as conn:
        row = conn.execute(
            "SELECT sequence_number, entry_data FROM audit_log WHERE event_type = 'SYSTEM_TEST'"
        ).fetchone()
        data = json.loads(bytes(row["entry_data"]).decode("utf-8"))
        data["details"]["ok"] = False
        allow_audit_mutation(conn, True)
        try:
            conn.execute(
                "UPDATE audit_log SET entry_data = ? WHERE sequence_number = ?",
                (json.dumps(data, sort_keys=True).encode("utf-8"), row["sequence_number"]),
            )
        finally:
            allow_audit_mutation(conn, False)
        conn.commit()

    result = audit.verify_integrity()
    audit.handle_verification_result(result, source="test")

    with test_db.connection() as conn:
        secure_row = conn.execute(
            "SELECT event_type, severity, details FROM audit_security_log ORDER BY id DESC LIMIT 1"
        ).fetchone()

    details = json.loads(secure_row["details"])
    assert secure_row["event_type"] == "AUDIT_TAMPERING_DETECTED"
    assert secure_row["severity"] == "CRITICAL"
    assert details["source"] == "test"
    assert details["invalid_entries"]


def test_audit_recent_verification_uses_configured_recent_limit(test_db):
    audit = AuditLogger(test_db, AuditLogSigner(b"test master key material for audit"))
    for index in range(5):
        audit.log_event("SYSTEM_TEST", "INFO", "test", {"index": index}, user_id="system")

    result = audit.verify_recent(limit=2)

    assert result["total_entries"] == 2
    assert result["verified"] is True


class DummyExportKeyManager:
    def derive_key(self, purpose: str, length: int = 32) -> bytes:
        assert purpose == "audit-export-encryption"
        return b"x" * length


def test_audit_export_manager_encrypts_sensitive_payload(test_db):
    audit = AuditLogger(test_db, AuditLogSigner(b"test master key material for audit"))
    audit.log_event("SYSTEM_TEST", "INFO", "test", {"ok": True}, user_id="system")

    with test_db.connection() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY sequence_number").fetchall()

    manager = AuditExportManager(test_db, key_manager=DummyExportKeyManager())
    payload, encrypted = manager.build_export(
        rows,
        "json",
        public_key={"algorithm": "Ed25519", "public_key": "abc"},
        encrypt_if_sensitive=False,
    )

    assert encrypted is False
    assert json.loads(payload.decode("utf-8"))["metadata"]["format"] == "cryptosafe.audit.signed-json.v1"

    sensitive_payload, encrypted = manager.build_export(
        rows,
        "json",
        public_key={"algorithm": "Ed25519", "public_key": "abc"},
        encrypt_if_sensitive=True,
    )

    assert encrypted is False
    assert b"encrypted-export" not in sensitive_payload


def test_scheduled_export_and_retention_cleanup(test_db, tmp_path):
    audit = AuditLogger(test_db, AuditLogSigner(b"test master key material for audit"))
    audit.log_event("SYSTEM_TEST", "INFO", "test", {"ok": True}, user_id="system")

    manager = AuditExportManager(test_db, output_dir=tmp_path)
    path = manager.run_scheduled_export_if_due("daily")

    assert path is not None
    assert path.exists()

    old_path = tmp_path / "audit-old.json"
    old_path.write_text("old", encoding="utf-8")
    old_time = time.time() - 10 * 24 * 60 * 60
    os.utime(old_path, (old_time, old_time))

    removed = manager.cleanup_old_exports(retention_days=1)

    assert removed == 1
    assert not old_path.exists()


def test_audit_non_critical_events_are_subscribed_async(test_db):
    bus = EventBus()
    audit = AuditLogger(test_db, AuditLogSigner(b"test master key material for audit"))

    audit.subscribe(bus)

    assert EntryCreated in bus._async
    assert LoginFailed in bus._sync


def test_audit_logging_average_under_10ms(test_db):
    audit = AuditLogger(
        test_db,
        AuditLogSigner(b"test master key material for audit"),
        config={"max_entries": 0, "max_age_days": 0},
    )

    start = time.perf_counter()
    for index in range(300):
        audit.log_event("PERF_TEST", "INFO", "perf", {"index": index}, user_id="system")
    elapsed = time.perf_counter() - start

    assert (elapsed / 300) < 0.010


def test_audit_verify_1000_entries_under_1s(test_db):
    audit = AuditLogger(
        test_db,
        AuditLogSigner(b"test master key material for audit"),
        config={"max_entries": 0, "max_age_days": 0},
    )
    for index in range(1000):
        audit.log_event("PERF_VERIFY", "INFO", "perf", {"index": index}, user_id="system")

    start = time.perf_counter()
    result = audit.verify_recent(limit=1000)
    elapsed = time.perf_counter() - start

    assert result["verified"] is True
    assert result["total_entries"] == 1000
    assert elapsed < 1.0


def test_audit_query_10000_entries_under_500ms_and_page_memory_under_50mb(test_db):
    audit = AuditLogger(
        test_db,
        AuditLogSigner(b"test master key material for audit"),
        config={"max_entries": 0, "max_age_days": 0},
    )
    for index in range(10_000):
        audit.log_event("PERF_QUERY", "INFO", "perf", {"index": index}, user_id="system")

    tracemalloc.start()
    start = time.perf_counter()
    with test_db.connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM audit_log
            WHERE event_type = ?
            ORDER BY sequence_number DESC
            LIMIT 50
            """,
            ("PERF_QUERY",),
        ).fetchall()
    elapsed = time.perf_counter() - start
    current_bytes, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert len(rows) == 50
    assert elapsed < 0.5
    assert peak_bytes / (1024 * 1024) < 50
