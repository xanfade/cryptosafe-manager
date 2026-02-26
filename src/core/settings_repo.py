from src.core.crypto.placeholder import AES256Placeholder
from src.database.db import Database


class SettingsRepository:
    """
    CFG-2: Все настройки в таблице settings.
    - encrypted=0 -> хранится как обычный текст
    - encrypted=1 -> значение шифруется (Sprint 1 XOR-заглушка)
    """

    def __init__(self, db: Database, key: bytes):
        self.db = db
        self.key = key
        self.crypto = AES256Placeholder()

    def set(self, setting_key: str, value: str, encrypted: bool = False):
        if encrypted:
            enc = self.crypto.encrypt(value.encode("utf-8"), self.key)
            store_value = enc.hex()  # храним как hex-строку (удобно в TEXT)
            enc_flag = 1
        else:
            store_value = value
            enc_flag = 0

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO settings(setting_key, setting_value, encrypted)
                VALUES (?, ?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET
                  setting_value=excluded.setting_value,
                  encrypted=excluded.encrypted
                """,
                (setting_key, store_value, enc_flag),
            )
            conn.commit()

    def get(self, setting_key: str, default: str | None = None) -> str | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT setting_value, encrypted FROM settings WHERE setting_key=?",
                (setting_key,),
            ).fetchone()

        if row is None:
            return default

        value, enc_flag = row
        if enc_flag == 1 and value is not None:
            raw = bytes.fromhex(value)
            dec = self.crypto.decrypt(raw, self.key)
            return dec.decode("utf-8")

        return value
