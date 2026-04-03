from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.core.events import EntryAdded, EntryDeleted, EntryUpdated
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
    def _normalize_tags(tags: str | None) -> str:
        return clean_text(tags or "")

    @staticmethod
    def _has_is_deleted_column(conn) -> bool:
        rows = conn.execute("PRAGMA table_info(vault_entries)").fetchall()
        column_names = {row["name"] for row in rows}
        return "is_deleted" in column_names

    def _build_payload_from_dict(
            self,
            data_dict: dict[str, Any],
            created_at: str,
    ) -> tuple[dict[str, Any], str]:
        title = clean_text(data_dict.get("title", ""))
        username = clean_text(data_dict.get("username", ""))
        password = data_dict.get("password", "") or ""
        url = clean_url(data_dict.get("url", "") or "")
        notes = clean_text(data_dict.get("notes", "") or "")
        tags = self._normalize_tags(data_dict.get("tags", ""))

        validate_required(title, "Название")
        validate_required(username, "Имя пользователя")
        validate_required(password, "Пароль")

        payload = {
            "version": VaultEncryptionService.PAYLOAD_VERSION,
            "created_at": created_at,
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
        }
        return payload, tags

    def create_entry(self, data_dict: dict[str, Any]) -> dict[str, Any]:
        created_at = self._utc_now_iso()
        updated_at = created_at

        payload, tags = self._build_payload_from_dict(data_dict, created_at)
        encrypted_data = self.crypto.encrypt_entry_payload(payload)

        with self.db.connection() as conn:
            try:
                cursor = conn.execute(
                    """
                    INSERT INTO vault_entries (encrypted_data, created_at, updated_at, tags)
                    VALUES (?, ?, ?, ?)
                    """,
                    (encrypted_data, created_at, updated_at, tags),
                )
                entry_id = cursor.lastrowid
                conn.commit()
            except Exception:
                conn.rollback()
                raise

        if self.event_bus:
            self.event_bus.publish(EntryAdded(entry_id=entry_id))

        entry = self.get_entry(entry_id)
        if entry is None:
            raise RuntimeError("Не удалось получить созданную запись")

        return entry

    def get_entry(self, entry_id: int) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            has_soft_delete = self._has_is_deleted_column(conn)

            if has_soft_delete:
                row = conn.execute(
                    """
                    SELECT id, encrypted_data, created_at, updated_at, tags
                    FROM vault_entries
                    WHERE id = ? AND is_deleted = 0
                    """,
                    (entry_id,),
                ).fetchone()
            else:
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
            "title": payload.get("title", ""),
            "username": payload.get("username", ""),
            "password": payload.get("password", ""),
            "url": payload.get("url", ""),
            "notes": payload.get("notes", ""),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "tags": row["tags"] or "",
        }

    def get_all_entries(self) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            has_soft_delete = self._has_is_deleted_column(conn)

            if has_soft_delete:
                rows = conn.execute(
                    """
                    SELECT id, encrypted_data, created_at, updated_at, tags
                    FROM vault_entries
                    WHERE is_deleted = 0
                    ORDER BY id DESC
                    """
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, encrypted_data, created_at, updated_at, tags
                    FROM vault_entries
                    ORDER BY id DESC
                    """
                ).fetchall()

        entries: list[dict[str, Any]] = []

        for row in rows:
            payload = self.crypto.decrypt_entry_payload(row["encrypted_data"])
            entries.append(
                {
                    "id": row["id"],
                    "title": payload.get("title", ""),
                    "username": payload.get("username", ""),
                    "password": payload.get("password", ""),
                    "url": payload.get("url", ""),
                    "notes": payload.get("notes", ""),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                    "tags": row["tags"] or "",
                }
            )

        return entries

    def update_entry(self, entry_id: int, data_dict: dict[str, Any]) -> dict[str, Any]:
        existing = self.get_entry(entry_id)
        if existing is None:
            raise ValueError("Запись не найдена")

        updated_at = self._utc_now_iso()
        payload, tags = self._build_payload_from_dict(data_dict, existing["created_at"])
        encrypted_data = self.crypto.encrypt_entry_payload(payload)

        with self.db.connection() as conn:
            try:
                cursor = conn.execute(
                    """
                    UPDATE vault_entries
                    SET encrypted_data = ?, updated_at = ?, tags = ?
                    WHERE id = ?
                    """,
                    (encrypted_data, updated_at, tags, entry_id),
                )
                if cursor.rowcount == 0:
                    raise ValueError("Запись не найдена")
                conn.commit()
            except Exception:
                conn.rollback()
                raise

        if self.event_bus:
            self.event_bus.publish(EntryUpdated(entry_id=entry_id))

        entry = self.get_entry(entry_id)
        if entry is None:
            raise RuntimeError("Не удалось получить обновлённую запись")

        return entry

    def delete_entry(self, entry_id: int, soft_delete: bool = True) -> None:
        existing = self.get_entry(entry_id)
        if existing is None:
            raise ValueError("Запись не найдена")

        with self.db.connection() as conn:
            try:
                has_soft_delete = self._has_is_deleted_column(conn)

                if soft_delete and has_soft_delete:
                    cursor = conn.execute(
                        """
                        UPDATE vault_entries
                        SET is_deleted = 1, updated_at = ?
                        WHERE id = ?
                        """,
                        (self._utc_now_iso(), entry_id),
                    )
                else:
                    cursor = conn.execute(
                        "DELETE FROM vault_entries WHERE id = ?",
                        (entry_id,),
                    )

                if cursor.rowcount == 0:
                    raise ValueError("Запись не найдена")

                conn.commit()
            except Exception:
                conn.rollback()
                raise

        if self.event_bus:
            self.event_bus.publish(EntryDeleted(entry_id=entry_id))