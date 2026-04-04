from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import json

from src.core.events import (
    AppFocusGained,
    AppFocusLost,
    AppMinimized,
    AppRestored,
    AutoLocked,
    EntryAdded,
    EntryDeleted,
    EntryUpdated,
    LoginFailed,
    UserLoggedIn,
    UserLoggedOut,
)
from src.database.db import Database


class AuditLogger:
    """
    Журнал аудита.
    """

    def __init__(self, db: Database):
        self.db = db

    def subscribe(self, bus):
        bus.subscribe(EntryAdded, self.on_entry_added)
        bus.subscribe(EntryUpdated, self.on_entry_updated)
        bus.subscribe(EntryDeleted, self.on_entry_deleted)

        bus.subscribe(UserLoggedIn, self.on_login)
        bus.subscribe(UserLoggedOut, self.on_logout)
        bus.subscribe(LoginFailed, self.on_login_failed)

        bus.subscribe(AutoLocked, self.on_auto_locked)
        bus.subscribe(AppFocusLost, self.on_focus_lost)
        bus.subscribe(AppFocusGained, self.on_focus_gained)
        bus.subscribe(AppMinimized, self.on_app_minimized)
        bus.subscribe(AppRestored, self.on_app_restored)

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

    def on_login_failed(self, e: LoginFailed):
        self._write("LoginFailed", None, asdict(e))

    def on_auto_locked(self, e: AutoLocked):
        self._write("AutoLocked", None, asdict(e))

    def on_focus_lost(self, e: AppFocusLost):
        self._write("AppFocusLost", None, asdict(e))

    def on_focus_gained(self, e: AppFocusGained):
        self._write("AppFocusGained", None, asdict(e))

    def on_app_minimized(self, e: AppMinimized):
        self._write("AppMinimized", None, asdict(e))

    def on_app_restored(self, e: AppRestored):
        self._write("AppRestored", None, asdict(e))