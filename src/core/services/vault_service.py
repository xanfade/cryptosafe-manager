from __future__ import annotations

from datetime import datetime

from src.core.crypto.placeholder import AES256Placeholder
from src.database.db import Database
from src.core.validators import clean_text, clean_url, validate_required


class VaultService:
    def __init__(self, db: Database, key_manager):
        self.db = db
        self.key_manager = key_manager
        self.crypto = AES256Placeholder(key_manager)

    def add_entry(
        self,
        title: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
        tags: str = "",
    ):
        title = clean_text(title, 120)
        username = clean_text(username, 120)
        url = clean_url(url, 500)
        notes = clean_text(notes, 2000)
        tags = clean_text(tags, 300)

        validate_required("title", title)
        validate_required("password", password)

        enc_password = self.crypto.encrypt(password.encode("utf-8"))
        enc_notes = self.crypto.encrypt(notes.encode("utf-8")) if notes else None

        now = datetime.utcnow().isoformat(timespec="seconds")

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO vault_entries(
                    title, username, encrypted_password, url, notes,
                    created_at, updated_at, tags
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (title, username, enc_password, url, enc_notes, now, now, tags),
            )
            conn.commit()

    def update_entry(
            self,
            entry_id: int,
            title: str,
            username: str,
            password: str,
            url: str = "",
            notes: str = "",
            tags: str = "",
    ):
        title = clean_text(title, 120)
        username = clean_text(username, 120)
        url = clean_url(url, 500)
        notes = clean_text(notes, 2000)
        tags = clean_text(tags, 300)

        validate_required("title", title)
        validate_required("password", password)

        enc_password = self.crypto.encrypt(password.encode("utf-8"))
        enc_notes = self.crypto.encrypt(notes.encode("utf-8")) if notes else None

        now = datetime.utcnow().isoformat(timespec="seconds")

        with self.db.connection() as conn:
            conn.execute(
                """
                UPDATE vault_entries
                SET title = ?, username = ?, encrypted_password = ?, url = ?, notes = ?,
                    updated_at = ?, tags = ?
                WHERE id = ?
                """,
                (title, username, enc_password, url, enc_notes, now, tags, entry_id),
            )
            conn.commit()

    def list_entries(self):
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, title, username, encrypted_password, url, notes,
                       created_at, updated_at, tags
                FROM vault_entries
                ORDER BY id DESC
                """
            ).fetchall()

        result = []
        for row in rows:
            decrypted_password = self.crypto.decrypt(row[3]).decode("utf-8")
            decrypted_notes = self.crypto.decrypt(row[5]).decode("utf-8") if row[5] else ""

            result.append(
                {
                    "id": row[0],
                    "title": row[1],
                    "username": row[2],
                    "password": decrypted_password,
                    "url": row[4],
                    "notes": decrypted_notes,
                    "created_at": row[6],
                    "updated_at": row[7],
                    "tags": row[8],
                }
            )

        return result

    def delete_entry(self, entry_id: int):
        with self.db.connection() as conn:
            conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
            conn.commit()