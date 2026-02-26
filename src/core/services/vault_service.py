from datetime import datetime
from src.core.crypto.placeholder import AES256Placeholder
from src.database.db import Database


class VaultService:
    def __init__(self, db: Database):
        self.db = db
        self.crypto = AES256Placeholder()

    def add_entry(self, title: str, username: str, password: str, url: str = "", notes: str = "", tags: str = "", key: bytes | None = None):
        # SEC-1: ключ не хранится в коде, а должен быть передан снаружи
        if not key:
            raise ValueError("Ключ шифрования не задан (приложение должно быть разблокировано)")
        enc_password = self.crypto.encrypt(password.encode("utf-8"), key)
        enc_notes = self.crypto.encrypt(notes.encode("utf-8"), key) if notes else None

        now = datetime.utcnow().isoformat(timespec="seconds")

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO vault_entries(title, username, encrypted_password, url, notes, created_at, updated_at, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (title, username, enc_password, url, enc_notes, now, now, tags),
            )
            conn.commit()

