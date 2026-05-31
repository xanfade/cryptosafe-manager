from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import asdict, is_dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any

from src.core.events import (
    AuditDataImported,
    AppFocusGained,
    AppFocusLost,
    AppMinimized,
    AppRestored,
    AppShutdown,
    AutoLocked,
    ClipboardAutoCleared,
    ClipboardCleared,
    ClipboardCopied,
    ClipboardCopyBlocked,
    ClipboardImageScanned,
    ClipboardSuspiciousActivity,
    ConfigurationChanged,
    EntryCreated,
    EntryDeleted,
    EntryShared,
    EntryListViewed,
    EntryRead,
    EntryUpdated,
    LoginFailed,
    PanicModeActivated,
    SecurityHardeningEvent,
    PasswordChanged,
    TotpAccessed,
    UserLoggedIn,
    UserLoggedOut,
    VaultDataImported,
    VaultDataExported,
    VaultSearchPerformed,
    VaultUnlocked,
)
from src.database.db import Database
from src.core.security.memory_guard import MemoryGuard


class AuditSeverity(StrEnum):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


SENSITIVE_KEYS = {
    "password",
    "passphrase",
    "secret",
    "token",
    "key",
    "private_key",
    "encryption_key",
    "master_password",
}

PERSONAL_KEYS = {
    "email",
    "username",
    "login",
    "title",
    "url",
    "notes",
    "name",
    "query",
    "search",
}


class AuditLogger:
    def __init__(self, db: Database, signer, config: dict[str, Any] | None = None):
        self.db = db
        self.signer = signer
        self.config = config or {}
        self.memory_guard = MemoryGuard(enable_locking=True, enable_auto_wipe=True)
        self._lock = threading.Lock()
        self._ensure_archive_schema()
        self._ensure_security_log_schema()
        self._ensure_append_only_schema()
        self._ensure_public_key()
        self._init_log_structure()

    def subscribe(self, bus) -> None:
        subscriptions = {
            EntryCreated: self.on_entry_created,
            EntryRead: self.on_entry_read,
            EntryListViewed: self.on_entry_list_viewed,
            VaultSearchPerformed: self.on_vault_search_performed,
            EntryUpdated: self.on_entry_updated,
            EntryDeleted: self.on_entry_deleted,
            UserLoggedIn: self.on_login,
            UserLoggedOut: self.on_logout,
            PasswordChanged: self.on_password_changed,
            LoginFailed: self.on_login_failed,
            AutoLocked: self.on_auto_locked,
            VaultUnlocked: self.on_vault_unlocked,
            AppShutdown: self.on_shutdown,
            AppFocusLost: self.on_focus_lost,
            AppFocusGained: self.on_focus_gained,
            AppMinimized: self.on_minimized,
            AppRestored: self.on_restored,
            ClipboardCopied: self.on_clipboard_copied,
            ClipboardCleared: self.on_clipboard_cleared,
            ClipboardAutoCleared: self.on_clipboard_auto_cleared,
            ClipboardImageScanned: self.on_clipboard_image_scanned,
            ClipboardSuspiciousActivity: self.on_clipboard_suspicious_activity,
            ClipboardCopyBlocked: self.on_clipboard_copy_blocked,
            ConfigurationChanged: self.on_configuration_changed,
            VaultDataExported: self.on_vault_data_exported,
            VaultDataImported: self.on_vault_data_imported,
            EntryShared: self.on_entry_shared,
            AuditDataImported: self.on_audit_data_imported,
            PanicModeActivated: self.on_panic_mode_activated,
            SecurityHardeningEvent: self.on_security_hardening_event,
            TotpAccessed: self.on_totp_accessed,
        }
        critical_events = {
            LoginFailed,
            PasswordChanged,
            EntryDeleted,
            AutoLocked,
            AppShutdown,
            ClipboardSuspiciousActivity,
            ClipboardCopyBlocked,
            ConfigurationChanged,
        }
        for event_type, handler in subscriptions.items():
            bus.subscribe(event_type, handler, async_=event_type not in critical_events)

    def log_event(
        self,
        event_type: str,
        severity: str | AuditSeverity,
        source: str,
        details: dict[str, Any] | None = None,
        user_id: str = "local",
        entry_id: int | None = None,
    ) -> int:
        with self._lock:
            with self.db.connection() as conn:
                previous = conn.execute(
                    """
                    SELECT sequence_number, entry_hash
                    FROM audit_log
                    ORDER BY sequence_number DESC
                    LIMIT 1
                    """
                ).fetchone()
                sequence = 0 if previous is None else int(previous["sequence_number"]) + 1
                previous_hash = "0" * 64 if previous is None else previous["entry_hash"]

                entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "event_type": event_type,
                    "severity": str(severity),
                    "user_id": user_id,
                    "source": source,
                    "details": self._sanitize(details or {}),
                    "entry_id": entry_id,
                    "sequence_number": sequence,
                    "previous_hash": previous_hash,
                }
                entry_json = self._canonical_json(entry)
                with self.memory_guard.scoped_buffer(entry_json, critical=True) as protected_json:
                    json_bytes = protected_json.to_bytes()
                    entry_hash = hashlib.sha256(json_bytes).hexdigest()
                    signature = self.signer.sign(json_bytes).hex()
                public_key = self.signer.public_key_record()

                conn.execute(
                    """
                    INSERT INTO audit_log(
                        sequence_number, previous_hash, entry_data, entry_hash,
                        signature, signature_algorithm, timestamp, event_type,
                        severity, user_id, source, entry_id
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sequence,
                        previous_hash,
                        json_bytes,
                        entry_hash,
                        signature,
                        self.signer.algorithm,
                        entry["timestamp"],
                        event_type,
                        str(severity),
                        user_id,
                        source,
                        entry_id,
                    ),
                )
                conn.execute(
                    """
                    INSERT OR REPLACE INTO audit_entry_keys(
                        sequence_number, algorithm, public_key, created_at
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        sequence,
                        public_key.algorithm,
                        public_key.public_key_hex,
                        entry["timestamp"],
                    ),
                )
                if hasattr(self.signer, "ratchet"):
                    self.signer.ratchet()
                    self._ensure_public_key(conn=conn)
                self._rotate_if_needed(conn)
                conn.commit()
                return sequence

    def verify_integrity(self, start_seq: int = 0, end_seq: int | None = None) -> dict[str, Any]:
        from src.core.audit.log_verifier import AuditLogVerifier

        return AuditLogVerifier(self.db, self.signer).verify_range(start_seq, end_seq).to_dict()

    def verify_recent(self, limit: int | None = None) -> dict[str, Any]:
        limit = limit or self._get_setting_int("audit.verification.recent_entries", 1000)
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT MAX(sequence_number) AS max_seq FROM audit_log"
            ).fetchone()
        max_seq = row["max_seq"] if row else None
        if max_seq is None:
            return self.verify_integrity()
        start_seq = max(0, int(max_seq) - int(limit) + 1)
        return self.verify_integrity(start_seq=start_seq)

    def handle_verification_result(
        self,
        result: dict[str, Any],
        source: str = "audit_verifier",
        notify_callback=None,
        lock_callback=None,
    ) -> None:
        if result.get("verified", False):
            return

        details = {
            "source": source,
            "invalid_entries": result.get("invalid_entries", []),
            "chain_breaks": result.get("chain_breaks", []),
            "total_entries": result.get("total_entries", 0),
            "valid_entries": result.get("valid_entries", 0),
        }
        self._write_security_log("AUDIT_TAMPERING_DETECTED", "CRITICAL", details)
        self.log_event(
            "SECURITY_AUDIT_TAMPERING_DETECTED",
            AuditSeverity.CRITICAL,
            "audit_logger",
            details,
            user_id="system",
        )

        if notify_callback:
            notify_callback(result)
        if lock_callback:
            lock_callback()

    def log_security_attempt(
        self,
        attempt_type: str,
        source: str,
        details: dict[str, Any] | None = None,
        user_id: str = "local",
    ) -> None:
        payload = {"attempt_type": attempt_type, **(details or {})}
        self._write_security_log("SECURITY_ATTEMPT_BLOCKED", "WARN", payload)
        self.log_event(
            "SECURITY_ATTEMPT_BLOCKED",
            AuditSeverity.WARN,
            source,
            payload,
            user_id=user_id,
        )

    def request_disable_logging(
        self,
        source: str,
        reason: str,
        user_id: str = "local",
    ) -> None:
        self.log_security_attempt(
            "disable_logging",
            source,
            {"reason": reason, "blocked": True},
            user_id=user_id,
        )
        raise PermissionError("audit logging cannot be disabled")

    def request_modify_log(
        self,
        source: str,
        target: str,
        user_id: str = "local",
    ) -> None:
        self.log_security_attempt(
            "modify_logging",
            source,
            {"target": target, "blocked": True},
            user_id=user_id,
        )
        raise PermissionError("audit log is append-only")

    def _get_setting_int(self, key: str, default: int) -> int:
        with self.db.connection() as conn:
            return self._setting_int(conn, key, default)

    def _ensure_public_key(self, conn=None) -> None:
        record = self.signer.public_key_record()
        def write(target_conn):
            target_conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_entry_keys (
                    sequence_number INTEGER PRIMARY KEY,
                    algorithm TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            target_conn.execute(
                """
                INSERT INTO audit_public_keys(key_id, algorithm, public_key, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(key_id) DO UPDATE SET
                    algorithm = excluded.algorithm,
                    public_key = excluded.public_key
                """,
                (
                    "current",
                    record.algorithm,
                    record.public_key_hex,
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                ),
            )

        if conn is None:
            with self.db.connection() as local_conn:
                write(local_conn)
                local_conn.commit()
        else:
            write(conn)

    def _ensure_archive_schema(self) -> None:
        with self.db.connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log_archive (
                    archive_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archived_at TEXT NOT NULL,
                    first_sequence INTEGER NOT NULL,
                    last_sequence INTEGER NOT NULL,
                    entry_count INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    archive_data BLOB NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_archive_time_v5 ON audit_log_archive(archived_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_archive_range_v5 ON audit_log_archive(first_sequence, last_sequence)"
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO settings (setting_key, setting_value, encrypted)
                VALUES
                    ('audit.rotation.max_entries', '10000', 0),
                    ('audit.rotation.max_age_days', '365', 0),
                    ('audit.export.schedule', 'disabled', 0),
                    ('audit.export.retention_days', '90', 0)
                """
            )
            conn.commit()

    def _ensure_security_log_schema(self) -> None:
        with self.db.connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_security_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    details TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_security_time_v5 ON audit_security_log(timestamp)"
            )
            conn.commit()

    def _ensure_append_only_schema(self) -> None:
        with self.db.connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_write_control (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    allow_mutation INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                "INSERT OR IGNORE INTO audit_write_control(id, allow_mutation) VALUES (1, 0)"
            )
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS audit_log_no_update
                BEFORE UPDATE ON audit_log
                WHEN (SELECT allow_mutation FROM audit_write_control WHERE id = 1) = 0
                BEGIN
                    SELECT RAISE(ABORT, 'audit_log is append-only');
                END;
                """
            )
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
                BEFORE DELETE ON audit_log
                WHEN (SELECT allow_mutation FROM audit_write_control WHERE id = 1) = 0
                BEGIN
                    SELECT RAISE(ABORT, 'audit_log is append-only');
                END;
                """
            )
            conn.commit()

    def _write_security_log(self, event_type: str, severity: str, details: dict[str, Any]) -> None:
        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_security_log(timestamp, event_type, severity, details)
                VALUES (?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    event_type,
                    severity,
                    json.dumps(details, sort_keys=True, ensure_ascii=False, default=str),
                ),
            )
            conn.commit()

    def _init_log_structure(self) -> None:
        with self.db.connection() as conn:
            count = conn.execute("SELECT COUNT(*) AS count FROM audit_log").fetchone()["count"]
        if count == 0:
            self.log_event(
                "SYSTEM_GENESIS",
                AuditSeverity.INFO,
                "audit_logger",
                {"message": "Audit log initialized"},
                user_id="system",
            )

    def _rotate_if_needed(self, conn) -> None:
        max_entries = self._setting_int(conn, "audit.rotation.max_entries", 10_000)
        max_age_days = self._setting_int(conn, "audit.rotation.max_age_days", 365)

        if max_entries > 0:
            count = conn.execute("SELECT COUNT(*) AS count FROM audit_log").fetchone()["count"]
            overflow = int(count) - max_entries
            if overflow > 0:
                rows = conn.execute(
                    """
                    SELECT *
                    FROM audit_log
                    ORDER BY sequence_number
                    LIMIT ?
                    """,
                    (overflow,),
                ).fetchall()
                self._archive_rows(conn, rows, "max_entries")

        if max_age_days > 0:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat(timespec="seconds")
            rows = conn.execute(
                """
                SELECT *
                FROM audit_log
                WHERE timestamp < ?
                ORDER BY sequence_number
                """,
                (cutoff,),
            ).fetchall()
            self._archive_rows(conn, rows, "max_age")

    def _setting_int(self, conn, key: str, default: int) -> int:
        config_key = key.removeprefix("audit.rotation.")
        if config_key in self.config:
            try:
                return int(self.config[config_key])
            except (TypeError, ValueError):
                return default

        row = conn.execute(
            "SELECT setting_value FROM settings WHERE setting_key = ?",
            (key,),
        ).fetchone()
        if row is None:
            return default
        try:
            return int(row["setting_value"])
        except (TypeError, ValueError):
            return default

    def _archive_rows(self, conn, rows, reason: str) -> None:
        if not rows:
            return

        sequences = [int(row["sequence_number"]) for row in rows]
        archive_entries = []
        for row in rows:
            archive_entries.append(
                {
                    "sequence_number": row["sequence_number"],
                    "previous_hash": row["previous_hash"],
                    "entry_data": bytes(row["entry_data"]).decode("utf-8"),
                    "entry_hash": row["entry_hash"],
                    "signature": row["signature"],
                    "signature_algorithm": row["signature_algorithm"],
                    "timestamp": row["timestamp"],
                    "event_type": row["event_type"],
                    "severity": row["severity"],
                    "user_id": row["user_id"],
                    "source": row["source"],
                    "entry_id": row["entry_id"],
                }
            )

        payload = json.dumps(
            {
                "format": "cryptosafe.audit.archive.v1",
                "reason": reason,
                "entries": archive_entries,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        conn.execute(
            """
            INSERT INTO audit_log_archive(
                archived_at, first_sequence, last_sequence, entry_count, reason, archive_data
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                min(sequences),
                max(sequences),
                len(sequences),
                reason,
                payload,
            ),
        )
        conn.execute("UPDATE audit_write_control SET allow_mutation = 1 WHERE id = 1")
        try:
            conn.executemany(
                "DELETE FROM audit_log WHERE sequence_number = ?",
                [(sequence,) for sequence in sequences],
            )
        finally:
            conn.execute("UPDATE audit_write_control SET allow_mutation = 0 WHERE id = 1")

    def _event_dict(self, event: Any) -> dict[str, Any]:
        if is_dataclass(event):
            return asdict(event)
        if hasattr(event, "__dict__"):
            return dict(event.__dict__)
        return {"value": str(event)}

    def _sanitize(self, value: Any) -> Any:
        if isinstance(value, dict):
            clean = {}
            for key, item in value.items():
                if self._is_sensitive_key(str(key)):
                    clean[key] = "[REDACTED]"
                elif self._is_personal_key(str(key)):
                    clean[key] = self._hash_placeholder(item)
                else:
                    clean[key] = self._sanitize(item)
            return clean
        if isinstance(value, list):
            return [self._sanitize(item) for item in value]
        if isinstance(value, tuple):
            return [self._sanitize(item) for item in value]
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc).isoformat(timespec="seconds")
        return value

    def _is_sensitive_key(self, key: str) -> bool:
        normalized = re.sub(r"[^a-z0-9_]", "_", key.lower())
        return any(part in SENSITIVE_KEYS for part in normalized.split("_"))

    def _is_personal_key(self, key: str) -> bool:
        normalized = re.sub(r"[^a-z0-9_]", "_", key.lower())
        return any(part in PERSONAL_KEYS for part in normalized.split("_"))

    def _hash_placeholder(self, value: Any) -> str:
        raw = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
        return f"[HASH:{hashlib.sha256(raw).hexdigest()[:16]}]"

    def _canonical_json(self, entry: dict[str, Any]) -> bytes:
        return json.dumps(
            entry,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")

    def on_entry_created(self, e: EntryCreated):
        self.log_event("VAULT_ENTRY_CREATED", AuditSeverity.INFO, "vault", self._event_dict(e), entry_id=e.entry_id)

    def on_entry_read(self, e: EntryRead):
        self.log_event("VAULT_ENTRY_READ", AuditSeverity.INFO, "vault", self._event_dict(e), entry_id=e.entry_id)

    def on_entry_list_viewed(self, e: EntryListViewed):
        self.log_event("VAULT_ENTRY_LIST_VIEWED", AuditSeverity.INFO, "vault", self._event_dict(e))

    def on_vault_search_performed(self, e: VaultSearchPerformed):
        self.log_event("VAULT_SEARCH_PERFORMED", AuditSeverity.INFO, "vault", self._event_dict(e))

    def on_entry_updated(self, e: EntryUpdated):
        self.log_event("VAULT_ENTRY_UPDATED", AuditSeverity.INFO, "vault", self._event_dict(e), entry_id=e.entry_id)

    def on_entry_deleted(self, e: EntryDeleted):
        self.log_event("VAULT_ENTRY_DELETED", AuditSeverity.WARN, "vault", self._event_dict(e), entry_id=e.entry_id)

    def on_login(self, e: UserLoggedIn):
        self.log_event("AUTH_LOGIN_SUCCESS", AuditSeverity.INFO, "auth", self._event_dict(e), user_id=e.user)

    def on_logout(self, e: UserLoggedOut):
        self.log_event("AUTH_LOGOUT", AuditSeverity.INFO, "auth", self._event_dict(e), user_id=e.user)

    def on_password_changed(self, e: PasswordChanged):
        self.log_event("AUTH_PASSWORD_CHANGED", AuditSeverity.WARN, "auth", self._event_dict(e), user_id=e.user)

    def on_login_failed(self, e: LoginFailed):
        self.log_event("AUTH_LOGIN_FAILURE", AuditSeverity.WARN, "auth", self._event_dict(e), user_id=e.user)

    def on_auto_locked(self, e: AutoLocked):
        self.log_event("SYSTEM_LOCK", AuditSeverity.INFO, "auth", self._event_dict(e))

    def on_vault_unlocked(self, e: VaultUnlocked):
        self.log_event("SYSTEM_UNLOCK", AuditSeverity.INFO, "auth", self._event_dict(e), user_id=e.user)

    def on_shutdown(self, e: AppShutdown):
        self.log_event("SYSTEM_SHUTDOWN", AuditSeverity.INFO, "application", self._event_dict(e), user_id="system")

    def on_focus_lost(self, e: AppFocusLost):
        self.log_event("SYSTEM_FOCUS_LOST", AuditSeverity.INFO, "system", self._event_dict(e))

    def on_focus_gained(self, e: AppFocusGained):
        self.log_event("SYSTEM_FOCUS_GAINED", AuditSeverity.INFO, "system", self._event_dict(e))

    def on_minimized(self, e: AppMinimized):
        self.log_event("SYSTEM_MINIMIZED", AuditSeverity.INFO, "system", self._event_dict(e))

    def on_restored(self, e: AppRestored):
        self.log_event("SYSTEM_RESTORED", AuditSeverity.INFO, "system", self._event_dict(e))

    def on_clipboard_copied(self, e: ClipboardCopied):
        self.log_event("CLIPBOARD_COPY", AuditSeverity.INFO, "clipboard", self._event_dict(e), entry_id=e.entry_id)

    def on_clipboard_cleared(self, e: ClipboardCleared):
        self.log_event("CLIPBOARD_CLEAR", AuditSeverity.INFO, "clipboard", self._event_dict(e))

    def on_clipboard_auto_cleared(self, e: ClipboardAutoCleared):
        self.log_event("CLIPBOARD_AUTO_CLEAR", AuditSeverity.INFO, "clipboard", self._event_dict(e))

    def on_clipboard_image_scanned(self, e: ClipboardImageScanned):
        self.log_event("CLIPBOARD_IMAGE_SCANNED", AuditSeverity.INFO, "clipboard", self._event_dict(e))

    def on_clipboard_suspicious_activity(self, e: ClipboardSuspiciousActivity):
        self.log_event("SECURITY_CLIPBOARD_SUSPICIOUS", AuditSeverity.WARN, "clipboard", self._event_dict(e), entry_id=e.entry_id)

    def on_clipboard_copy_blocked(self, e: ClipboardCopyBlocked):
        self.log_event("SECURITY_CLIPBOARD_BLOCKED", AuditSeverity.WARN, "clipboard", self._event_dict(e), entry_id=e.entry_id)

    def on_configuration_changed(self, e: ConfigurationChanged):
        self.log_event("CONFIG_CHANGED", AuditSeverity.INFO, e.source, self._event_dict(e))

    def on_vault_data_exported(self, e: VaultDataExported):
        self.log_event("VAULT_DATA_EXPORTED", AuditSeverity.INFO, "import_export", self._event_dict(e), user_id="system")

    def on_vault_data_imported(self, e: VaultDataImported):
        self.log_event("VAULT_DATA_IMPORTED", AuditSeverity.INFO, "import_export", self._event_dict(e), user_id="system")

    def on_entry_shared(self, e: EntryShared):
        self.log_event("VAULT_ENTRY_SHARED", AuditSeverity.INFO, "sharing_service", self._event_dict(e), entry_id=e.entry_id, user_id="system")

    def on_audit_data_imported(self, e: AuditDataImported):
        self.log_event("AUDIT_LOG_IMPORTED", AuditSeverity.INFO, "audit_import", self._event_dict(e), user_id="system")

    def on_panic_mode_activated(self, e: PanicModeActivated):
        self.log_event("SECURITY_PANIC_MODE", AuditSeverity.CRITICAL, "panic_mode", self._event_dict(e), user_id="system")

    def on_totp_accessed(self, e: TotpAccessed):
        self.log_event("TOTP_ACCESSED", AuditSeverity.INFO, "totp", self._event_dict(e), entry_id=e.entry_id)

    def on_security_hardening_event(self, e: SecurityHardeningEvent):
        severity = AuditSeverity.WARN if e.status != "ok" else AuditSeverity.INFO
        self.log_event("SECURITY_HARDENING_EVENT", severity, "security", self._event_dict(e), user_id="system")
