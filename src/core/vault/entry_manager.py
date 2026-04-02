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

        encrypted_password = self.crypto.encrypt(password.encode("utf-8"))
        encrypted_notes = self.crypto.encrypt(notes.encode("utf-8")) if notes else None

        now = datetime.now(timezone.utc).isoformat(timespec="seconds")

        with self.db.connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO vault_entries (
                    title, username, encrypted_password, url, notes, created_at, updated_at, tags
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (title, username, encrypted_password, url, encrypted_notes, now, now, tags),
            )
            entry_id = cursor.lastrowid
            conn.commit()

        if self.event_bus:
            self.event_bus.publish("EntryAdded", {"entry_id": entry_id, "title": title})

        return entry_id

    def get_all_entries(self) -> list[dict]:
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, title, username, encrypted_password, url, notes, created_at, updated_at, tags
                FROM vault_entries
                ORDER BY id DESC
                """
            ).fetchall()

        result = []
        for row in rows:
            decrypted_password = self.crypto.decrypt(row["encrypted_password"]).decode("utf-8")
            decrypted_notes = (
                self.crypto.decrypt(row["notes"]).decode("utf-8")
                if row["notes"] else ""
            )

            result.append({
                "id": row["id"],
                "title": row["title"] or "",
                "username": row["username"] or "",
                "password": decrypted_password,
                "url": row["url"] or "",
                "notes": decrypted_notes,
                "created_at": row["created_at"] or "",
                "updated_at": row["updated_at"] or "",
                "tags": row["tags"] or "",
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

        encrypted_password = self.crypto.encrypt(password.encode("utf-8"))
        encrypted_notes = self.crypto.encrypt(notes.encode("utf-8")) if notes else None
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")

        with self.db.connection() as conn:
            conn.execute(
                """
                UPDATE vault_entries
                SET title = ?, username = ?, encrypted_password = ?, url = ?, notes = ?, updated_at = ?, tags = ?
                WHERE id = ?
                """,
                (title, username, encrypted_password, url, encrypted_notes, now, tags, entry_id),
            )
            conn.commit()

        if self.event_bus:
            self.event_bus.publish("EntryUpdated", {"entry_id": entry_id, "title": title})

    def delete_entry(self, entry_id: int) -> None:
        with self.db.connection() as conn:
            conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
            conn.commit()

        if self.event_bus:
            self.event_bus.publish("EntryDeleted", {"entry_id": entry_id})