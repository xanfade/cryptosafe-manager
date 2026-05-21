from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timezone
from typing import Any, Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _cef_escape(value: Any) -> str:
    text = str(value)
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "")
    )


def row_to_cef(
    row: Any,
    device_vendor: str = "CryptoSafe",
    device_product: str = "Manager",
    device_version: str = "5",
) -> str:
    severity_map = {"INFO": "3", "WARN": "5", "ERROR": "8", "CRITICAL": "10"}
    details = bytes(row["entry_data"]).decode("utf-8")
    extension = {
        "rt": row["timestamp"],
        "suser": row["user_id"],
        "cs1Label": "source",
        "cs1": row["source"],
        "cs2Label": "entry_id",
        "cs2": "" if row["entry_id"] is None else row["entry_id"],
        "cn1Label": "sequence_number",
        "cn1": row["sequence_number"],
        "cs3Label": "entry_hash",
        "cs3": row["entry_hash"],
        "msg": details,
    }
    extension_text = " ".join(
        f"{key}={_cef_escape(value)}"
        for key, value in extension.items()
    )
    return (
        f"CEF:0|{_cef_escape(device_vendor)}|{_cef_escape(device_product)}|"
        f"{_cef_escape(device_version)}|{_cef_escape(row['event_type'])}|"
        f"{_cef_escape(row['event_type'])}|{severity_map.get(str(row['severity']), '3')}|"
        f"{extension_text}"
    )


def rows_to_signed_json(
    rows: Iterable[Any],
    public_key: dict[str, str] | None = None,
    exporter: str = "local",
    date_range: dict[str, str | None] | None = None,
) -> str:
    entries = []
    for row in rows:
        entries.append(
            {
                "sequence_number": row["sequence_number"],
                "previous_hash": row["previous_hash"],
                "entry_hash": row["entry_hash"],
                "entry_data": bytes(row["entry_data"]).decode("utf-8"),
                "signature": row["signature"],
                "signature_algorithm": row["signature_algorithm"],
                "public_key": row["public_key"] if "public_key" in row.keys() else None,
            }
        )
    payload = {
        "metadata": {
            "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "exporter": exporter,
            "range": date_range or {"from": None, "to": None},
            "format": "cryptosafe.audit.signed-json.v1",
            "standard": "CEF-like structured audit",
            "entry_count": len(entries),
        },
        "public_key": public_key or {},
        "entries": entries,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def rows_to_csv(rows: Iterable[Any]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "sequence_number",
            "timestamp",
            "event_type",
            "severity",
            "user_id",
            "source",
            "entry_id",
            "entry_hash",
        ],
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({name: row[name] for name in writer.fieldnames})
    return output.getvalue()


def rows_to_pdf_report(rows: Iterable[Any]) -> bytes:
    rows = list(rows)
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    for row in rows:
        severity_counts[row["severity"]] = severity_counts.get(row["severity"], 0) + 1
        event_counts[row["event_type"]] = event_counts.get(row["event_type"], 0) + 1

    lines = [
        "CryptoSafe Audit Report",
        f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"Entries: {len(rows)}",
        f"Severity summary: {severity_counts}",
        f"Top events: {dict(sorted(event_counts.items(), key=lambda item: item[1], reverse=True)[:10])}",
        "",
    ]
    for row in rows:
        lines.append(
            f"{row['sequence_number']} {row['timestamp']} "
            f"{row['severity']} {row['event_type']} source={row['source']}"
        )
    text = "\n".join(lines)
    # Minimal PDF-compatible text payload for dependency-free export.
    stream = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    body = f"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >> endobj
4 0 obj << /Length {len(stream) + 47} >> stream
BT /F1 10 Tf 40 760 Td ({stream}) Tj ET
endstream endobj
trailer << /Root 1 0 R >>
%%EOF
"""
    return body.encode("latin-1", errors="replace")


def export_contains_sensitive_data(payload: bytes) -> bool:
    lower = payload.lower()
    markers = [
        b'"password"',
        b'"secret"',
        b'"token"',
        b'"private_key"',
        b'"master_password"',
        b'"encryption_key"',
    ]
    return any(marker in lower for marker in markers) and b"[redacted]" not in lower


def encrypt_export_payload(payload: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, payload, None)
    package = {
        "metadata": {
            "format": "cryptosafe.audit.encrypted-export.v1",
            "algorithm": "AES-256-GCM",
            "encrypted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }
    return json.dumps(package, indent=2).encode("utf-8")
