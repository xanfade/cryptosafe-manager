from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.core.audit.log_formatters import (
    encrypt_export_payload,
    export_contains_sensitive_data,
    rows_to_csv,
    rows_to_pdf_report,
    rows_to_signed_json,
)
from src.database.db import Database


class AuditExportManager:
    def __init__(self, db: Database, key_manager=None, output_dir: str | Path = "audit_exports", event_bus=None):
        self.db = db
        self.key_manager = key_manager
        self.output_dir = Path(output_dir)
        self.event_bus = event_bus

    def query_rows(self, date_from: str | None = None, date_to: str | None = None):
        where = []
        params: list[Any] = []
        if date_from:
            where.append("timestamp >= ?")
            params.append(date_from)
        if date_to:
            where.append("timestamp <= ?")
            params.append(date_to)

        sql = "SELECT * FROM audit_log"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY sequence_number"

        with self.db.connection() as conn:
            return conn.execute(sql, params).fetchall()

    def build_export(
        self,
        rows,
        kind: str,
        public_key: dict[str, str] | None = None,
        exporter: str = "local",
        date_range: dict[str, str | None] | None = None,
        encrypt_if_sensitive: bool = True,
    ) -> tuple[bytes, bool]:
        if kind == "json":
            rows = self._with_entry_public_keys(rows)
            payload = rows_to_signed_json(rows, public_key, exporter=exporter, date_range=date_range).encode("utf-8")
        elif kind == "csv":
            payload = rows_to_csv(rows).encode("utf-8")
        elif kind == "pdf":
            payload = rows_to_pdf_report(rows)
        else:
            raise ValueError(f"unsupported audit export format: {kind}")

        if encrypt_if_sensitive and export_contains_sensitive_data(payload):
            if self.key_manager is None:
                raise RuntimeError("key manager is required to encrypt sensitive audit exports")
            payload = encrypt_export_payload(payload, self.key_manager.derive_key("audit-export-encryption", 32))
            return payload, True

        return payload, False

    def _with_entry_public_keys(self, rows):
        sequences = [int(row["sequence_number"]) for row in rows]
        if not sequences:
            return rows

        placeholders = ",".join("?" for _ in sequences)
        with self.db.connection() as conn:
            key_rows = conn.execute(
                f"""
                SELECT sequence_number, public_key
                FROM audit_entry_keys
                WHERE sequence_number IN ({placeholders})
                """,
                sequences,
            ).fetchall()
        keys = {int(row["sequence_number"]): row["public_key"] for row in key_rows}
        enriched = []
        for row in rows:
            data = {key: row[key] for key in row.keys()}
            data["public_key"] = keys.get(int(row["sequence_number"]))
            enriched.append(data)
        return enriched

    def import_signed_json(self, payload: str | bytes) -> int:
        from src.core.events import AuditDataImported

        document = json.loads(payload.decode("utf-8") if isinstance(payload, bytes) else payload)
        entries = document.get("entries", [])
        with self.db.connection() as conn:
            conn.execute("UPDATE audit_write_control SET allow_mutation = 1 WHERE id = 1")
            try:
                conn.execute("DELETE FROM audit_log")
                for item in entries:
                    entry = json.loads(item["entry_data"])
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
                            item["sequence_number"],
                            item["previous_hash"],
                            item["entry_data"].encode("utf-8"),
                            item["entry_hash"],
                            item["signature"],
                            item["signature_algorithm"],
                            entry["timestamp"],
                            entry["event_type"],
                            entry["severity"],
                            entry["user_id"],
                            entry["source"],
                            entry.get("entry_id"),
                        ),
                    )
                    if item.get("public_key"):
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO audit_entry_keys(
                                sequence_number, algorithm, public_key, created_at
                            )
                            VALUES (?, ?, ?, ?)
                            """,
                            (
                                item["sequence_number"],
                                item["signature_algorithm"],
                                item["public_key"],
                                entry["timestamp"],
                            ),
                        )
            finally:
                conn.execute("UPDATE audit_write_control SET allow_mutation = 0 WHERE id = 1")
            conn.commit()
        if self.event_bus is not None:
            self.event_bus.publish(
                AuditDataImported(
                    format=str(document.get("metadata", {}).get("format", "signed_json")),
                    entry_count=len(entries),
                )
            )
        return len(entries)

    def run_scheduled_export_if_due(self, frequency: str | None = None) -> Path | None:
        frequency = frequency or self._setting("audit.export.schedule", "disabled")
        if frequency == "disabled":
            return None

        now = datetime.now(timezone.utc)
        last_raw = self._setting("audit.export.last_run", "")
        if last_raw:
            try:
                last_run = datetime.fromisoformat(last_raw)
            except ValueError:
                last_run = None
            if last_run is not None and now - last_run < self._frequency_delta(frequency):
                return None

        self.output_dir.mkdir(parents=True, exist_ok=True)
        rows = self.query_rows()
        filename = f"audit-{now.strftime('%Y%m%d-%H%M%S')}.json"
        path = self.output_dir / filename

        public_key = self._public_key()
        payload, encrypted = self.build_export(
            rows,
            "json",
            public_key,
            exporter="scheduled",
            date_range={"from": None, "to": None},
        )
        path = path.with_suffix(".json.enc" if encrypted else ".json")
        path.write_bytes(payload)
        self._set_setting("audit.export.last_run", now.isoformat(timespec="seconds"))
        self.cleanup_old_exports()
        return path

    def cleanup_old_exports(self, retention_days: int | None = None) -> int:
        retention_days = retention_days or int(self._setting("audit.export.retention_days", "90"))
        if not self.output_dir.exists():
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        removed = 0
        for path in self.output_dir.glob("audit-*"):
            modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            if modified < cutoff:
                path.unlink()
                removed += 1
        return removed

    def _public_key(self) -> dict[str, str]:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT algorithm, public_key FROM audit_public_keys WHERE key_id = 'current'"
            ).fetchone()
        if row is None:
            return {}
        return {"algorithm": row["algorithm"], "public_key": row["public_key"]}

    def _setting(self, key: str, default: str) -> str:
        with self.db.connection() as conn:
            row = conn.execute("SELECT setting_value FROM settings WHERE setting_key = ?", (key,)).fetchone()
            return default if row is None else str(row["setting_value"])

    def _set_setting(self, key: str, value: str) -> None:
        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO settings(setting_key, setting_value, encrypted)
                VALUES (?, ?, 0)
                ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value
                """,
                (key, value),
            )
            conn.commit()

    @staticmethod
    def _frequency_delta(frequency: str) -> timedelta:
        if frequency == "daily":
            return timedelta(days=1)
        if frequency == "weekly":
            return timedelta(days=7)
        if frequency == "monthly":
            return timedelta(days=30)
        raise ValueError(f"unsupported export schedule: {frequency}")
