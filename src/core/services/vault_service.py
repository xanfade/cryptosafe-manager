from __future__ import annotations
from src.core.vault.entry_manager import EntryManager


class VaultService:
    def __init__(self, db, key_manager):
        self.manager = EntryManager(db, key_manager)

    def add_entry(self, *args, **kwargs):
        return self.manager.create_entry(*args, **kwargs)

    def list_entries(self):
        return self.manager.get_all_entries()

    def update_entry(self, *args, **kwargs):
        return self.manager.update_entry(*args, **kwargs)

    def delete_entry(self, *args, **kwargs):
        return self.manager.delete_entry(*args, **kwargs)