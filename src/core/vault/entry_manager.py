from __future__ import annotations

from datetime import datetime, timezone

from src.core.validators import clean_text, clean_url, validate_required
from src.core.vault.encryption_service import VaultEncryptionService


class EntryManager:
    def __init__(self, db, key_manager, event_bus=None, audit_logger=None):
        self.db = db
        self.key_manager = key_manager
        self.crypto = VaultEncryptionService(key_manager)
        self.event_bus = event_bus
        self.audit_logger = audit_logger

    def create_entry(
            self,
            title: str,
            username: str,
            password: str,
            url: str = "",
            notes: str = "",
            tags: str = "",
    ) -> int:
        title = clean_text(title, 120)
        username = clean_text(username, 120)
        url = clean_url(url, 500)
        notes = clean_text(notes, 2000)
        tags = clean_text(tags, 300)

        validate_required("title", title)
        validate_required("password", password)

        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        encrypted_blob = self.crypto.encrypt_entry(
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
            created_at=now,
        )

        with self.db.connection() as conn:
            cursor = conn.execute("""
                INSERT INTO vault_entries (
                    encrypted_blob,
                    tags,
                    updated_at
                ) VALUES (?, ?, ?)
            """, (
                encrypted_blob,
                tags,
                now,
            ))
            entry_id = cursor.lastrowid
            conn.commit()

        if self.event_bus:
            self.event_bus.publish("EntryAdded", {"entry_id": entry_id, "title": title})

        return entry_id

    def get_all_entries(self) -> list[dict]:
        with self.db.connection() as conn:
            rows = conn.execute("""
                SELECT id, encrypted_blob, tags, updated_at
                FROM vault_entries
                ORDER BY id DESC
            """).fetchall()

        result = []
        for row in rows:
            payload = self.crypto.decrypt_entry(row["encrypted_blob"])
            result.append({
                "id": row["id"],
                "title": payload["title"],
                "username": payload["username"],
                "password": payload["password"],
                "url": payload["url"],
                "notes": payload["notes"],
                "created_at": payload["created_at"],
                "updated_at": row["updated_at"] or "",
                "tags": row["tags"] or "",
                "version": payload["version"],
            })

        return result

    def update_entry(
            self,
            entry_id: int,
            title: str,
            username: str,
            password: str,
            url: str = "",
            notes: str = "",
            tags: str = "",
    ) -> None:
        title = clean_text(title, 120)
        username = clean_text(username, 120)
        url = clean_url(url, 500)
        notes = clean_text(notes, 2000)
        tags = clean_text(tags, 300)

        validate_required("title", title)
        validate_required("password", password)

        with self.db.connection() as conn:
            existing = conn.execute("""
                SELECT encrypted_blob
                FROM vault_entries
                WHERE id = ?
            """, (entry_id,)).fetchone()

            if existing is None:
                raise ValueError("Запись не найдена.")

        old_payload = self.crypto.decrypt_entry(existing["encrypted_blob"])
        updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

        encrypted_blob = self.crypto.encrypt_entry(
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
            created_at=old_payload["created_at"],
        )

        with self.db.connection() as conn:
            conn.execute("""
                UPDATE vault_entries
                SET encrypted_blob = ?, tags = ?, updated_at = ?
                WHERE id = ?
            """, (
                encrypted_blob,
                tags,
                updated_at,
                entry_id,
            ))
            conn.commit()

        if self.event_bus:
            self.event_bus.publish("EntryUpdated", {"entry_id": entry_id, "title": title})

    def delete_entry(self, entry_id: int) -> None:
        with self.db.connection() as conn:
            conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
            conn.commit()

        if self.event_bus:
            self.event_bus.publish("EntryDeleted", {"entry_id": entry_id})