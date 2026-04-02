from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.core.validators import clean_text, clean_url, validate_required
from src.core.vault.encryption_service import VaultEncryptionService


class EntryManager:
    def __init__(self, db, key_manager, event_bus=None):
        self.db = db
        self.key_manager = key_manager
        self.event_bus = event_bus
        self.crypto = VaultEncryptionService(key_manager)

    @staticmethod
    def _utc_now_iso() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    @staticmethod
    def _normalize_tags(tags: Optional[str]) -> str:
        return clean_text(tags or "")

    def _build_payload(
        self,
        title: str,
        username: str,
        password: str,
        url: str,
        notes: str,
        category: str,
    ) -> Dict[str, Any]:
        title = clean_text(title)
        username = clean_text(username)
        password = password or ""
        url = clean_url(url or "")
        notes = clean_text(notes or "")
        category = clean_text(category or "Без категории")

        validate_required(title, "Название")
        validate_required(username, "Имя пользователя")
        validate_required(password, "Пароль")

        return {
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
            "category": category,
            "version": VaultEncryptionService.PAYLOAD_VERSION,
        }

    def create_entry(
        self,
        title: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
        tags: str = "",
        category: str = "",
    ) -> int:
        created_at = self._utc_now_iso()
        updated_at = created_at
        tags = self._normalize_tags(tags)

        payload = self._build_payload(
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
            category=category,
        )

        encrypted_data = self.crypto.encrypt_entry_payload(payload)

        with self.db.connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO vault_entries (encrypted_data, created_at, updated_at, tags)
                VALUES (?, ?, ?, ?)
                """,
                (encrypted_data, created_at, updated_at, tags),
            )
            entry_id = cursor.lastrowid
            conn.commit()

        if self.event_bus:
            self.event_bus.publish(
                "EntryAdded",
                {
                    "entry_id": entry_id,
                    "title": payload["title"],
                    "updated_at": updated_at,
                },
            )

        return entry_id

    def get_entry_by_id(self, entry_id: int) -> Optional[Dict[str, Any]]:
        with self.db.connection() as conn:
            row = conn.execute(
                """
                SELECT id, encrypted_data, created_at, updated_at, tags
                FROM vault_entries
                WHERE id = ?
                """,
                (entry_id,),
            ).fetchone()

        if not row:
            return None

        payload = self.crypto.decrypt_entry_payload(row["encrypted_data"])

        return {
            "id": row["id"],
            "title": payload["title"],
            "username": payload["username"],
            "password": payload["password"],
            "url": payload["url"],
            "notes": payload["notes"],
            "category": payload["category"],
            "version": payload["version"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "tags": row["tags"] or "",
        }

    def get_all_entries(self) -> List[Dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, encrypted_data, created_at, updated_at, tags
                FROM vault_entries
                ORDER BY id DESC
                """
            ).fetchall()

        result: List[Dict[str, Any]] = []

        for row in rows:
            payload = self.crypto.decrypt_entry_payload(row["encrypted_data"])
            result.append(
                {
                    "id": row["id"],
                    "title": payload["title"],
                    "username": payload["username"],
                    "password": payload["password"],
                    "url": payload["url"],
                    "notes": payload["notes"],
                    "category": payload["category"],
                    "version": payload["version"],
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                    "tags": row["tags"] or "",
                }
            )

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
        category: str = "",
    ) -> bool:
        existing = self.get_entry_by_id(entry_id)
        if not existing:
            return False

        updated_at = self._utc_now_iso()
        tags = self._normalize_tags(tags)

        payload = self._build_payload(
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
            category=category,
        )

        encrypted_data = self.crypto.encrypt_entry_payload(payload)

        with self.db.connection() as conn:
            conn.execute(
                """
                UPDATE vault_entries
                SET encrypted_data = ?, updated_at = ?, tags = ?
                WHERE id = ?
                """,
                (encrypted_data, updated_at, tags, entry_id),
            )
            conn.commit()

        if self.event_bus:
            self.event_bus.publish(
                "EntryUpdated",
                {
                    "entry_id": entry_id,
                    "title": payload["title"],
                    "updated_at": updated_at,
                },
            )

        return True

    def delete_entry(self, entry_id: int) -> bool:
        existing = self.get_entry_by_id(entry_id)
        if not existing:
            return False

        with self.db.connection() as conn:
            cursor = conn.execute(
                "DELETE FROM vault_entries WHERE id = ?",
                (entry_id,),
            )
            conn.commit()

        deleted = cursor.rowcount > 0

        if deleted and self.event_bus:
            self.event_bus.publish(
                "EntryDeleted",
                {
                    "entry_id": entry_id,
                    "title": existing["title"],
                },
            )

        return deleted