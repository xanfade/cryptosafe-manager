from __future__ import annotations

from typing import Any

from src.core.vault.entry_manager import EntryManager


class VaultService:
    def __init__(self, db, key_manager, event_bus=None):
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
        return self.manager.get_entry(entry_id)

    def get_all_entries(self):
        return self.manager.get_all_entries()

    def list_entries(self):
        return self.manager.get_all_entries()

    def update_entry(self, entry_id: int, data_dict: dict[str, Any]):
        return self.manager.update_entry(entry_id, data_dict)

    def delete_entry(self, entry_id: int, soft_delete: bool = True):
        return self.manager.delete_entry(entry_id, soft_delete=soft_delete)