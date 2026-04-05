from __future__ import annotations

import tkinter as tk
from tkinter import ttk, Menu
from urllib.parse import urlparse
from datetime import datetime
from typing import Callable, Iterable, Any


class SecureTable(ttk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)

        self.rows_by_id: dict[str, Any] = {}
        self.item_to_entry_id: dict[str, str] = {}
        self.password_visibility: dict[str, bool] = {}
        self.passwords_visible: bool = False
        self.sort_state: dict[str, bool] = {}

        self._on_edit: Callable[[str], None] | None = None
        self._on_delete: Callable[[list[str]], None] | None = None
        self._on_copy_username: Callable[[str], None] | None = None
        self._on_copy_password: Callable[[str], None] | None = None
        self._on_open_url: Callable[[str], None] | None = None
        self._on_selection_changed: Callable[[], None] | None = None

        self.columns = ("title", "username", "password", "domain", "updated_at", "action")

        self.tree = ttk.Treeview(
            self,
            columns=self.columns,
            show="headings",
            selectmode="extended",
            height=18
        )

        self.tree.heading("title", text="Заголовок", command=lambda: self.sort_by("title"))
        self.tree.heading("username", text="Имя пользователя", command=lambda: self.sort_by("username"))
        self.tree.heading("password", text="Пароль", command=lambda: self.sort_by("password"))
        self.tree.heading("domain", text="Домен", command=lambda: self.sort_by("domain"))
        self.tree.heading("updated_at", text="Изменено", command=lambda: self.sort_by("updated_at"))
        self.tree.heading("action", text="👁")

        self.tree.column("title", width=220, minwidth=160, anchor="w", stretch=True)
        self.tree.column("username", width=180, minwidth=140, anchor="w", stretch=True)
        self.tree.column("password", width=160, minwidth=120, anchor="center", stretch=False)
        self.tree.column("domain", width=180, minwidth=140, anchor="w", stretch=True)
        self.tree.column("updated_at", width=150, minwidth=120, anchor="center", stretch=False)
        self.tree.column("action", width=48, minwidth=48, anchor="center", stretch=False)

        y_scroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        x_scroll = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
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
        self.menu.add_separator()
        self.menu.add_command(label="Открыть URL", command=self._handle_open_url)

        self.tree.bind("<Button-1>", self._on_left_click, add="+")
        self.tree.bind("<Button-3>", self._show_context_menu, add="+")
        self.tree.bind("<Control-Button-1>", self._show_context_menu, add="+")
        self.tree.bind("<<TreeviewSelect>>", self._on_select, add="+")

    def bind_actions(
        self,
        on_edit: Callable[[str], None] | None = None,
        on_delete: Callable[[list[str]], None] | None = None,
        on_copy_username: Callable[[str], None] | None = None,
        on_copy_password: Callable[[str], None] | None = None,
        on_open_url: Callable[[str], None] | None = None,
        on_selection_changed: Callable[[], None] | None = None,
    ) -> None:
        self._on_edit = on_edit
        self._on_delete = on_delete
        self._on_copy_username = on_copy_username
        self._on_copy_password = on_copy_password
        self._on_open_url = on_open_url
        self._on_selection_changed = on_selection_changed

    def clear(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.rows_by_id.clear()
        self.item_to_entry_id.clear()
        self.password_visibility.clear()

    def set_rows(self, rows: Iterable[Any]) -> None:
        selected_ids = set(self.get_selected_ids())
        self.clear()

        for row in rows:
            entry_id = str(getattr(row, "id"))
            self.rows_by_id[entry_id] = row
            self.password_visibility.setdefault(entry_id, False)

            item_id = self.tree.insert(
                "",
                "end",
                values=self._build_values(row)
            )
            self.item_to_entry_id[item_id] = entry_id

        self._restore_selection(selected_ids)

    def refresh_row(self, entry_id: str) -> None:
        for item_id, mapped_id in self.item_to_entry_id.items():
            if mapped_id == entry_id and entry_id in self.rows_by_id:
                row = self.rows_by_id[entry_id]
                self.tree.item(item_id, values=self._build_values(row))
                return

    def get_selected_ids(self) -> list[str]:
        result: list[str] = []
        for item_id in self.tree.selection():
            entry_id = self.item_to_entry_id.get(item_id)
            if entry_id:
                result.append(entry_id)
        return result

    def get_first_selected_id(self) -> str | None:
        selected = self.get_selected_ids()
        return selected[0] if selected else None

    def toggle_password_visibility(self) -> None:
        self.passwords_visible = not self.passwords_visible
        for item_id, entry_id in self.item_to_entry_id.items():
            row = self.rows_by_id.get(entry_id)
            if row is not None:
                self.tree.item(item_id, values=self._build_values(row))

    def set_passwords_visible(self, visible: bool) -> None:
        self.passwords_visible = visible
        for item_id, entry_id in self.item_to_entry_id.items():
            row = self.rows_by_id.get(entry_id)
            if row is not None:
                self.tree.item(item_id, values=self._build_values(row))

    def sort_by(self, column: str) -> None:
        reverse = self.sort_state.get(column, False)
        self.sort_state[column] = not reverse

        rows = list(self.rows_by_id.values())

        def sort_key(row: Any):
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

        rows.sort(key=sort_key, reverse=reverse)
        self.set_rows(rows)

    def _build_values(self, row: Any) -> tuple[str, str, str, str, str, str]:
        entry_id = str(getattr(row, "id"))
        title = getattr(row, "title", "") or ""
        username = self._mask_username(getattr(row, "username", "") or "")
        password = self._format_password(row, entry_id)
        domain = self._extract_domain(getattr(row, "url", "") or "")
        updated_at = self._format_updated_at(getattr(row, "updated_at", None))
        action = "👁"

        return title, username, password, domain, updated_at, action

    def _format_password(self, row: Any, entry_id: str) -> str:
        raw_password = getattr(row, "password", "") or ""
        row_visible = self.password_visibility.get(entry_id, False)

        if self.passwords_visible or row_visible:
            return raw_password
        return "•" * max(8, len(raw_password)) if raw_password else ""

    @staticmethod
    def _mask_username(username: str) -> str:
        if not username:
            return ""
        if len(username) <= 4:
            return username
        return username[:4] + "•" * (len(username) - 4)

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
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except Exception:
            return url

    @staticmethod
    def _format_updated_at(value: Any) -> str:
        if not value:
            return ""

        if isinstance(value, datetime):
            return value.strftime("%d.%m.%Y %H:%M")

        text = str(value).strip()

        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%dT%H:%M",
        ):
            try:
                dt = datetime.strptime(text, fmt)
                return dt.strftime("%d.%m.%Y %H:%M")
            except ValueError:
                pass

        return text

    @staticmethod
    def _safe_datetime(value: Any) -> datetime:
        if isinstance(value, datetime):
            return value

        if not value:
            return datetime.min

        text = str(value).strip()
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%dT%H:%M",
        ):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                pass

        return datetime.min

    def _restore_selection(self, selected_ids: set[str]) -> None:
        if not selected_ids:
            return

        items_to_select = []
        for item_id, entry_id in self.item_to_entry_id.items():
            if entry_id in selected_ids:
                items_to_select.append(item_id)

        if items_to_select:
            self.tree.selection_set(items_to_select)

    def _on_left_click(self, event) -> None:
        region = self.tree.identify("region", event.x, event.y)
        column = self.tree.identify_column(event.x)
        item_id = self.tree.identify_row(event.y)

        if region != "cell" or not item_id:
            return

        if column == f"#{len(self.columns)}":
            entry_id = self.item_to_entry_id.get(item_id)
            if not entry_id:
                return

            self.password_visibility[entry_id] = not self.password_visibility.get(entry_id, False)
            row = self.rows_by_id.get(entry_id)
            if row is not None:
                self.tree.item(item_id, values=self._build_values(row))

    def _show_context_menu(self, event) -> None:
        item_id = self.tree.identify_row(event.y)
        if item_id:
            if item_id not in self.tree.selection():
                self.tree.selection_set(item_id)

            selected_count = len(self.get_selected_ids())
            self.menu.entryconfigure("Редактировать", state="normal" if selected_count == 1 else "disabled")
            self.menu.entryconfigure("Копировать логин", state="normal" if selected_count == 1 else "disabled")
            self.menu.entryconfigure("Копировать пароль", state="normal" if selected_count == 1 else "disabled")
            self.menu.entryconfigure("Открыть URL", state="normal" if selected_count == 1 else "disabled")
            self.menu.entryconfigure("Удалить", state="normal" if selected_count >= 1 else "disabled")

            try:
                self.menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.menu.grab_release()

    def _on_select(self, _event=None) -> None:
        if self._on_selection_changed:
            self._on_selection_changed()

    def _handle_edit(self) -> None:
        if self._on_edit:
            entry_id = self.get_first_selected_id()
            if entry_id:
                self._on_edit(entry_id)

    def _handle_delete(self) -> None:
        if self._on_delete:
            selected_ids = self.get_selected_ids()
            if selected_ids:
                self._on_delete(selected_ids)

    def _handle_copy_username(self) -> None:
        if self._on_copy_username:
            entry_id = self.get_first_selected_id()
            if entry_id:
                self._on_copy_username(entry_id)

    def _handle_copy_password(self) -> None:
        if self._on_copy_password:
            entry_id = self.get_first_selected_id()
            if entry_id:
                self._on_copy_password(entry_id)

    def _handle_open_url(self) -> None:
        if self._on_open_url:
            entry_id = self.get_first_selected_id()
            if entry_id:
                self._on_open_url(entry_id)