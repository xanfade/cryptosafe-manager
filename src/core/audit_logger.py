from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import json

from src.core.events import (
    EntryCreated,
    EntryUpdated,
    EntryDeleted,
    UserLoggedIn,
    UserLoggedOut,
    LoginFailed,
    AutoLocked,
)
from src.database.db import Database


class AuditLogger:
    def __init__(self, db: Database):
        self.db = db

    def subscribe(self, bus):
        bus.subscribe(EntryCreated, self.on_entry_created)
        bus.subscribe(EntryUpdated, self.on_entry_updated)
        bus.subscribe(EntryDeleted, self.on_entry_deleted)
        bus.subscribe(UserLoggedIn, self.on_login)
        bus.subscribe(UserLoggedOut, self.on_logout)
        bus.subscribe(LoginFailed, self.on_login_failed)
        bus.subscribe(AutoLocked, self.on_auto_locked)

    def _write(self, action: str, entry_id: int | None, details: dict):
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

    def on_entry_created(self, e: EntryCreated):
        self._write("EntryCreated", e.entry_id, asdict(e))

    def on_entry_updated(self, e: EntryUpdated):
        self._write("EntryUpdated", e.entry_id, asdict(e))

    def on_entry_deleted(self, e: EntryDeleted):
        self._write("EntryDeleted", e.entry_id, asdict(e))

    def on_login(self, e: UserLoggedIn):
        self._write("UserLoggedIn", None, asdict(e))

    def on_logout(self, e: UserLoggedOut):
        self._write("UserLoggedOut", None, asdict(e))

    def on_login_failed(self, e: LoginFailed):
        self._write("LoginFailed", None, asdict(e))

    def on_auto_locked(self, e: AutoLocked):
        self._write("AutoLocked", None, asdict(e))