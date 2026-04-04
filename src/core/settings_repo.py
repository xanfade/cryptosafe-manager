from __future__ import annotations

import base64
from cryptography.fernet import Fernet, InvalidToken


class SettingsService:


    def __init__(self, db, secret_key: bytes):
        self.db = db
        self.fernet = Fernet(secret_key)

    @staticmethod
    def build_fernet_key(raw_key: bytes) -> bytes:
        if len(raw_key) != 32:
            raise ValueError("Секретный ключ настроек должен быть длиной 32 байта")
        return base64.urlsafe_b64encode(raw_key)

    def get(self, key: str, default=None):
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT setting_value, encrypted FROM settings WHERE setting_key = ?",
                (key,),
            ).fetchone()

        if row is None:
            return default

        value = row["setting_value"]
        encrypted = int(row["encrypted"] or 0)

        if not encrypted:
            return value

        try:
            decrypted = self.fernet.decrypt(value.encode("utf-8"))
            return decrypted.decode("utf-8")
        except (InvalidToken, UnicodeDecodeError):
            raise ValueError(f"Не удалось расшифровать настройку: {key}")

    def set(self, key: str, value: str, encrypted: bool = False):
        stored_value = value
        encrypted_flag = 1 if encrypted else 0

        if encrypted:
            token = self.fernet.encrypt(str(value).encode("utf-8"))
            stored_value = token.decode("utf-8")

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO settings(setting_key, setting_value, encrypted)
                VALUES (?, ?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET
                    setting_value = excluded.setting_value,
                    encrypted = excluded.encrypted
                """,
                (key, stored_value, encrypted_flag),
            )
            conn.commit()