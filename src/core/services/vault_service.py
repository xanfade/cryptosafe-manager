from __future__ import annotations

import shlex
from typing import Any

from src.core.events import EntryListViewed, EntryRead
from src.core.vault.entry_manager import EntryManager


class VaultService:
    def __init__(self, db, key_manager, event_bus=None):
        self.event_bus = event_bus
        self.manager = EntryManager(
            db=db,
            key_manager=key_manager,
            event_bus=event_bus,
        )

    def add_entry(self, data_dict: dict[str, Any]):
        return self.manager.create_entry(data_dict)

    def create_entry(self, data_dict: dict[str, Any]):
        return self.manager.create_entry(data_dict)

    def get_entry(self, entry_id: int):
        entry = self.manager.get_entry(entry_id)
        if entry is not None and self.event_bus:
            self.event_bus.publish(EntryRead(entry_id=entry_id))
        return entry

    def get_all_entries(self):
        entries = self.manager.get_all_entries()
        if self.event_bus:
            self.event_bus.publish(EntryListViewed(count=len(entries)))
        return entries

    def list_entries(self):
        return self.manager.get_all_entries()

    def update_entry(self, entry_id: int, data_dict: dict[str, Any]):
        return self.manager.update_entry(entry_id, data_dict)

    def delete_entry(self, entry_id: int, soft_delete: bool = True):
        return self.manager.delete_entry(entry_id, soft_delete=soft_delete)

    def clear_entries(self):
        for entry in self.manager.get_all_entries():
            self.manager.delete_entry(entry.id, soft_delete=False)

    def find_entries(self, query: str):
        tokens = self._parse_query(query)
        if not tokens:
            return self.get_all_entries()
        rows = []
        for entry in self.manager.get_all_entries():
            haystack = " ".join(
                str(getattr(entry, field, "") or "").lower()
                for field in ("title", "username", "url", "notes", "category", "tags")
            )
            if all(token in haystack for token in tokens):
                rows.append(entry)
        return rows

    @staticmethod
    def _parse_query(query: str) -> list[str]:
        try:
            parts = shlex.split(query or "")
        except ValueError:
            parts = (query or "").split()
        return [part.strip().lower() for part in parts if part.strip()]
