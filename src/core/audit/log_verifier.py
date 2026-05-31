from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.core.security.side_channel_protection import constant_time_compare_str
from src.database.db import Database


@dataclass
class VerificationIssue:
    sequence_number: int
    reason: str
    expected: str | None = None
    actual: str | None = None


@dataclass
class VerificationResult:
    total_entries: int = 0
    valid_entries: int = 0
    verified: bool = True
    invalid_entries: list[VerificationIssue] = field(default_factory=list)
    chain_breaks: list[VerificationIssue] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    recovery_options: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_entries": self.total_entries,
            "valid_entries": self.valid_entries,
            "verified": self.verified,
            "invalid_entries": [issue.__dict__ for issue in self.invalid_entries],
            "chain_breaks": [issue.__dict__ for issue in self.chain_breaks],
            "errors": self.errors,
            "recovery_options": self.recovery_options,
        }


class AuditLogVerifier:
    def __init__(self, db: Database, signer):
        self.db = db
        self.signer = signer

    def verify_range(self, start_seq: int = 0, end_seq: int | None = None) -> VerificationResult:
        query = """
            SELECT
                audit_log.sequence_number,
                audit_log.previous_hash,
                audit_log.entry_data,
                audit_log.entry_hash,
                audit_log.signature,
                audit_entry_keys.algorithm AS key_algorithm,
                audit_entry_keys.public_key AS entry_public_key
            FROM audit_log
            LEFT JOIN audit_entry_keys
                ON audit_entry_keys.sequence_number = audit_log.sequence_number
            WHERE audit_log.sequence_number >= ?
        """
        params: list[Any] = [start_seq]
        if end_seq is not None:
            query += " AND audit_log.sequence_number <= ?"
            params.append(end_seq)
        query += " ORDER BY audit_log.sequence_number"

        try:
            with self.db.connection() as conn:
                rows = conn.execute(query, params).fetchall()
        except sqlite3.DatabaseError as exc:
            return VerificationResult(
                verified=False,
                errors=[f"Database verification failed: {exc}"],
                recovery_options=[
                    "restore_from_backup",
                    "inspect_audit_log_archive",
                    "export_remaining_security_log",
                    "reinitialize_audit_log_after_user_confirmation",
                ],
            )

        result = VerificationResult(total_entries=len(rows))
        previous_hash = None
        for row in rows:
            seq = int(row["sequence_number"])
            entry_data = bytes(row["entry_data"])
            stored_hash = row["entry_hash"]
            previous_hash_field = row["previous_hash"]

            computed_hash = hashlib.sha256(entry_data).hexdigest()
            entry_valid = True

            if not constant_time_compare_str(computed_hash, stored_hash):
                result.invalid_entries.append(
                    VerificationIssue(seq, "Hash mismatch", stored_hash, computed_hash)
                )
                result.verified = False
                entry_valid = False

            if not self._verify_signature(row, entry_data):
                result.invalid_entries.append(VerificationIssue(seq, "Invalid signature"))
                result.verified = False
                entry_valid = False

            if previous_hash is not None and not constant_time_compare_str(previous_hash_field, previous_hash):
                result.chain_breaks.append(
                    VerificationIssue(seq, "Hash chain break", previous_hash, previous_hash_field)
                )
                result.verified = False
                entry_valid = False

            if entry_valid:
                result.valid_entries += 1
            previous_hash = stored_hash

        return result

    def _verify_signature(self, row, entry_data: bytes) -> bool:
        signature = bytes.fromhex(row["signature"])
        if row["key_algorithm"] == "Ed25519" and row["entry_public_key"]:
            try:
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(
                    bytes.fromhex(row["entry_public_key"])
                )
                public_key.verify(signature, entry_data)
                return True
            except InvalidSignature:
                return False
        return self.signer.verify(entry_data, signature)


class SignedJsonAuditVerifier:
    """Independent verifier for signed JSON audit exports."""

    def verify_export(self, payload: str | bytes) -> dict[str, Any]:
        document = json.loads(payload.decode("utf-8") if isinstance(payload, bytes) else payload)
        public_key_record = document.get("public_key", {})
        algorithm = public_key_record.get("algorithm")
        if algorithm != "Ed25519":
            return {
                "verified": False,
                "errors": [f"unsupported export public key algorithm: {algorithm}"],
            }

        public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(public_key_record["public_key"])
        )

        previous_hash = None
        invalid_entries = []
        chain_breaks = []
        valid_entries = 0

        for item in document.get("entries", []):
            sequence = int(item["sequence_number"])
            entry_data = item["entry_data"].encode("utf-8")
            item_public_key = item.get("public_key") or public_key_record["public_key"]
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(item_public_key))
            entry_hash = item["entry_hash"]
            computed_hash = hashlib.sha256(entry_data).hexdigest()
            entry_valid = True

            if not constant_time_compare_str(computed_hash, entry_hash):
                invalid_entries.append({"sequence_number": sequence, "reason": "Hash mismatch"})
                entry_valid = False

            try:
                public_key.verify(bytes.fromhex(item["signature"]), entry_data)
            except InvalidSignature:
                invalid_entries.append({"sequence_number": sequence, "reason": "Invalid signature"})
                entry_valid = False

            if previous_hash is not None and not constant_time_compare_str(item["previous_hash"], previous_hash):
                chain_breaks.append(
                    {
                        "sequence_number": sequence,
                        "reason": "Hash chain break",
                        "expected": previous_hash,
                        "actual": item["previous_hash"],
                    }
                )
                entry_valid = False

            if entry_valid:
                valid_entries += 1
            previous_hash = entry_hash

        verified = not invalid_entries and not chain_breaks
        return {
            "verified": verified,
            "total_entries": len(document.get("entries", [])),
            "valid_entries": valid_entries,
            "invalid_entries": invalid_entries,
            "chain_breaks": chain_breaks,
            "metadata": document.get("metadata", {}),
        }
