from __future__ import annotations

import tkinter as tk
from datetime import datetime
from tkinter import Menu, ttk
from typing import Any, Callable, Iterable
from urllib.parse import urlparse


class SecureTable(ttk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.rows_by_id: dict[str, Any] = {}
        self.item_to_entry_id: dict[str, str] = {}
        self.passwords_visible = False
        self.sort_state: dict[str, bool] = {}
        self.clipboard_entry_id: str | None = None

        self._on_edit: Callable[[str], None] | None = None
        self._on_delete: Callable[[list[str]], None] | None = None
        self._on_copy_username: Callable[[str], None] | None = None
        self._on_copy_password: Callable[[str], None] | None = None
        self._on_open_url: Callable[[str], None] | None = None
        self._on_selection_changed: Callable[[], None] | None = None
        self._on_copy_all: Callable[[str], None] | None = None

        self.columns = ("title", "username", "password", "domain", "updated_at")
        self.tree = ttk.Treeview(self, columns=self.columns, show="headings", selectmode="extended", height=18)

        headings = {
            "title": ("Название", 220, 160, "w", True),
            "username": ("Логин", 180, 140, "w", True),
            "password": ("Пароль", 160, 120, "center", False),
            "domain": ("Домен", 180, 140, "w", True),
            "updated_at": ("Изменено", 150, 120, "center", False),
        }
        for column, (label, width, minwidth, anchor, stretch) in headings.items():
            self.tree.heading(column, text=label, command=lambda c=column: self.sort_by(c))
            self.tree.column(column, width=width, minwidth=minwidth, anchor=anchor, stretch=stretch)

        y_scroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview, style="Vertical.TScrollbar")
        x_scroll = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview, style="Horizontal.TScrollbar")
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.menu = Menu(self, tearoff=0)
        self.menu.add_command(label="Редактировать", command=self._handle_edit)
        self.menu.add_command(label="Удалить", command=self._handle_delete)
        self.menu.add_separator()
        self.menu.add_command(label="Копировать логин", command=self._handle_copy_username)
        self.menu.add_command(label="Копировать пароль", command=self._handle_copy_password)
        self.menu.add_command(label="Копировать всё", command=self._handle_copy_all)
        self.menu.add_separator()
        self.menu.add_command(label="Открыть URL", command=self._handle_open_url)

        self.tree.bind("<Button-3>", self._show_context_menu, add="+")
        self.tree.bind("<Control-Button-1>", self._show_context_menu, add="+")
        self.tree.bind("<<TreeviewSelect>>", self._on_select, add="+")

    def bind_actions(
        self,
        on_edit=None,
        on_delete=None,
        on_copy_username=None,
        on_copy_password=None,
        on_open_url=None,
        on_selection_changed=None,
        on_copy_all=None,
    ) -> None:
        self._on_edit = on_edit
        self._on_delete = on_delete
        self._on_copy_username = on_copy_username
        self._on_copy_password = on_copy_password
        self._on_open_url = on_open_url
        self._on_selection_changed = on_selection_changed
        self._on_copy_all = on_copy_all

    def clear(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.rows_by_id.clear()
        self.item_to_entry_id.clear()

    def set_rows(self, rows: Iterable[Any]) -> None:
        selected_ids = set(self.get_selected_ids())
        self.clear()
        for row in rows:
            entry_id = str(getattr(row, "id"))
            self.rows_by_id[entry_id] = row
            item_id = self.tree.insert("", "end", values=self._build_values(row))
            self.item_to_entry_id[item_id] = entry_id
        self._restore_selection(selected_ids)

    def refresh_row(self, entry_id: str) -> None:
        for item_id, mapped_id in self.item_to_entry_id.items():
            if mapped_id == entry_id and entry_id in self.rows_by_id:
                self.tree.item(item_id, values=self._build_values(self.rows_by_id[entry_id]))
                return

    def get_selected_ids(self) -> list[str]:
        return [self.item_to_entry_id[item] for item in self.tree.selection() if item in self.item_to_entry_id]

    def get_first_selected_id(self) -> str | None:
        selected = self.get_selected_ids()
        return selected[0] if selected else None

    def toggle_password_visibility(self) -> None:
        self.set_passwords_visible(not self.passwords_visible)

    def set_passwords_visible(self, visible: bool) -> None:
        self.passwords_visible = bool(visible)
        for item_id, entry_id in self.item_to_entry_id.items():
            row = self.rows_by_id.get(entry_id)
            if row is not None:
                self.tree.item(item_id, values=self._build_values(row))

    def sort_by(self, column: str) -> None:
        reverse = self.sort_state.get(column, False)
        self.sort_state[column] = not reverse
        rows = list(self.rows_by_id.values())
        rows.sort(key=lambda row: self._sort_key(row, column), reverse=reverse)
        self.set_rows(rows)

    def _sort_key(self, row: Any, column: str):
        if column == "title":
            return (getattr(row, "title", "") or "").lower()
        if column == "username":
            return (getattr(row, "username", "") or "").lower()
        if column == "password":
            return (getattr(row, "password", "") or "").lower()
        if column == "domain":
            return self._extract_domain(getattr(row, "url", "") or "").lower()
        if column == "updated_at":
            return self._safe_datetime(getattr(row, "updated_at", None))
        return ""

    def _build_values(self, row: Any) -> tuple[str, str, str, str, str]:
        entry_id = str(getattr(row, "id"))
        title = getattr(row, "title", "") or ""
        if entry_id == self.clipboard_entry_id:
            title = "[буфер] " + title
        username = self._mask_username(getattr(row, "username", "") or "")
        password = self._format_password(row)
        domain = self._extract_domain(getattr(row, "url", "") or "")
        updated_at = self._format_updated_at(getattr(row, "updated_at", None))
        return title, username, password, domain, updated_at

    def _format_password(self, row: Any) -> str:
        raw_password = getattr(row, "password", "") or ""
        if self.passwords_visible:
            return raw_password
        return "*" * max(8, len(raw_password)) if raw_password else ""

    @staticmethod
    def _mask_username(username: str) -> str:
        if not username or len(username) <= 4:
            return username
        return username[:4] + "*" * (len(username) - 4)

    @staticmethod
    def _extract_domain(url: str) -> str:
        if not url:
            return ""
        candidate = url.strip()
        if "://" not in candidate:
            candidate = "https://" + candidate
        try:
            parsed = urlparse(candidate)
            domain = parsed.netloc.lower().strip()
            return domain[4:] if domain.startswith("www.") else domain
        except Exception:
            return url

    @staticmethod
    def _format_updated_at(value: Any) -> str:
        dt = SecureTable._safe_datetime(value)
        return "" if dt == datetime.min else dt.strftime("%d.%m.%Y %H:%M")

    @staticmethod
    def _safe_datetime(value: Any) -> datetime:
        if isinstance(value, datetime):
            return value
        if not value:
            return datetime.min
        text = str(value).strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                pass
        return datetime.min

    def _restore_selection(self, selected_ids: set[str]) -> None:
        items = [item_id for item_id, entry_id in self.item_to_entry_id.items() if entry_id in selected_ids]
        if items:
            self.tree.selection_set(items)

    def _show_context_menu(self, event) -> None:
        item_id = self.tree.identify_row(event.y)
        if not item_id:
            return
        if item_id not in self.tree.selection():
            self.tree.selection_set(item_id)
        selected_count = len(self.get_selected_ids())
        states = {
            "Редактировать": selected_count == 1,
            "Копировать логин": selected_count == 1,
            "Копировать пароль": selected_count == 1,
            "Копировать всё": selected_count == 1,
            "Открыть URL": selected_count == 1,
            "Удалить": selected_count >= 1,
        }
        for label, enabled in states.items():
            self.menu.entryconfigure(label, state="normal" if enabled else "disabled")
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def _on_select(self, _event=None) -> None:
        if self._on_selection_changed:
            self._on_selection_changed()

    def _handle_edit(self) -> None:
        entry_id = self.get_first_selected_id()
        if entry_id and self._on_edit:
            self._on_edit(entry_id)

    def _handle_delete(self) -> None:
        selected_ids = self.get_selected_ids()
        if selected_ids and self._on_delete:
            self._on_delete(selected_ids)

    def _handle_copy_username(self) -> None:
        entry_id = self.get_first_selected_id()
        if entry_id and self._on_copy_username:
            self._on_copy_username(entry_id)

    def _handle_copy_password(self) -> None:
        entry_id = self.get_first_selected_id()
        if entry_id and self._on_copy_password:
            self._on_copy_password(entry_id)

    def _handle_copy_all(self) -> None:
        entry_id = self.get_first_selected_id()
        if entry_id and self._on_copy_all:
            self._on_copy_all(entry_id)

    def _handle_open_url(self) -> None:
        entry_id = self.get_first_selected_id()
        if entry_id and self._on_open_url:
            self._on_open_url(entry_id)

    def set_clipboard_entry(self, entry_id: int | None) -> None:
        self.clipboard_entry_id = str(entry_id) if entry_id is not None else None
        for item_id, mapped_id in self.item_to_entry_id.items():
            row = self.rows_by_id.get(mapped_id)
            if row is not None:
                self.tree.item(item_id, values=self._build_values(row))
