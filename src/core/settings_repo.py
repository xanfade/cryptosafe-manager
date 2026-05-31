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

    def get_many(self, keys: list[str]) -> dict[str, str | None]:
        if not keys:
            return {}
        placeholders = ",".join("?" for _ in keys)
        with self.db.connection() as conn:
            rows = conn.execute(
                f"SELECT setting_key, setting_value, encrypted FROM settings WHERE setting_key IN ({placeholders})",
                tuple(keys),
            ).fetchall()
        by_key = {str(row["setting_key"]): row for row in rows}
        result: dict[str, str | None] = {}
        for key in keys:
            row = by_key.get(key)
            if row is None:
                result[key] = None
                continue
            encrypted = int(row["encrypted"] or 0)
            value = row["setting_value"]
            if not encrypted:
                result[key] = value
                continue
            try:
                decrypted = self.fernet.decrypt(value.encode("utf-8"))
                result[key] = decrypted.decode("utf-8")
            except (InvalidToken, UnicodeDecodeError):
                raise ValueError(f"Не удалось расшифровать настройку: {key}")
        return result

    def set_many(self, values: dict[str, str], encrypted: bool = False):
        if not values:
            return
        encrypted_flag = 1 if encrypted else 0
        rows = []
        for key, value in values.items():
            stored_value = str(value)
            if encrypted:
                stored_value = self.fernet.encrypt(stored_value.encode("utf-8")).decode("utf-8")
            rows.append((key, stored_value, encrypted_flag))
        with self.db.connection() as conn:
            conn.executemany(
                """
                INSERT INTO settings(setting_key, setting_value, encrypted)
                VALUES (?, ?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET
                    setting_value = excluded.setting_value,
                    encrypted = excluded.encrypted
                """,
                rows,
            )
            conn.commit()

    def snapshot(self, keys: list[str]) -> dict[str, str | None]:
        return self.get_many(keys)

    def restore_snapshot(self, snapshot: dict[str, str | None]):
        if not snapshot:
            return
        with self.db.connection() as conn:
            for key, value in snapshot.items():
                if value is None:
                    conn.execute("DELETE FROM settings WHERE setting_key = ?", (key,))
                else:
                    conn.execute(
                        """
                        INSERT INTO settings(setting_key, setting_value, encrypted)
                        VALUES (?, ?, 0)
                        ON CONFLICT(setting_key) DO UPDATE SET
                            setting_value = excluded.setting_value,
                            encrypted = excluded.encrypted
                        """,
                        (key, str(value)),
                    )
            conn.commit()
