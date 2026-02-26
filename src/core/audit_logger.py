from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import json

from src.core.events import EntryAdded, EntryUpdated, EntryDeleted, UserLoggedIn, UserLoggedOut
from src.database.db import Database


class AuditLogger:
    """
    Заглушка журнала аудита
    """

    def __init__(self, db: Database):
        self.db = db

    def subscribe(self, bus):
        # Подписки на события (EVT-2)
        bus.subscribe(EntryAdded, self.on_entry_added)
        bus.subscribe(EntryUpdated, self.on_entry_updated)
        bus.subscribe(EntryDeleted, self.on_entry_deleted)
        bus.subscribe(UserLoggedIn, self.on_login)
        bus.subscribe(UserLoggedOut, self.on_logout)

    def _write(self, action: str, entry_id: int | None, details: dict):
        # Пишем в audit_log простую запись
        ts = datetime.utcnow().isoformat(timespec="seconds")
        details_json = json.dumps(details, ensure_ascii=False)

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_log(action, timestamp, entry_id, details, signature)
                VALUES (?, ?, ?, ?, ?)
                """,
                (action, ts, entry_id, details_json, None),
            )
            conn.commit()

    def on_entry_added(self, e: EntryAdded):
        self._write("EntryAdded", e.entry_id, asdict(e))

    def on_entry_updated(self, e: EntryUpdated):
        self._write("EntryUpdated", e.entry_id, asdict(e))

    def on_entry_deleted(self, e: EntryDeleted):
        self._write("EntryDeleted", e.entry_id, asdict(e))

    def on_login(self, e: UserLoggedIn):
        self._write("UserLoggedIn", None, asdict(e))

    def on_logout(self, e: UserLoggedOut):
        self._write("UserLoggedOut", None, asdict(e))
