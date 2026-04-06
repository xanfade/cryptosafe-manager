import tkinter as tk
import difflib
import shlex
from tkinter import ttk, messagebox

from src.gui.password_change_dialog import PasswordChangeDialog
from src.gui.widgets.audit_log_viewer import AuditLogViewer
from src.gui.login_dialog import LoginDialog
from src.core.services.vault_service import VaultService
from src.gui.widgets.secure_table import SecureTable
from src.gui.entry_dialog import EntryDialog


class MainWindow(tk.Tk):
    def __init__(self, db=None, key_manager=None, auth_service=None, event_bus=None):
        super().__init__()

        self.event_bus = event_bus
        self.db = db
        self.key_manager = key_manager
        self.auth_service = auth_service
        self.vault_service = VaultService(
            db=self.db,
            key_manager=self.key_manager,
            event_bus=self.event_bus,
        )


        self.rows = []
        self.all_rows = []
        self.filtered_rows = []
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._on_search_changed)
        self.locked = False
        self._is_minimized = False
        self._has_focus = True
        self._focus_out_job = None
        self._poll_job = None
        self._clipboard_clear_job = None
        self._clipboard_clear_delay_ms = 30_000
        self.update_window_title()

        self.title("CryptoSafe Manager")
        self.geometry("1100x620")
        self.minsize(900, 540)
        self.configure(bg="#1e1e1e")

        self.setup_styles()
        self.create_menu()
        self.create_toolbar()
        self.create_table()
        self.create_statusbar()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self._bind_auth_integration()
        self.after(1000, self._poll_session_state)

        if self.auth_service and not self.auth_service.is_unlocked():
            self.apply_locked_state()
        else:
            self.apply_unlocked_state()

    def update_window_title(self):
        state_text = "Хранилище открыто" if not self.locked else "Хранилище заблокировано"
        self.title(f"CryptoSafe Manager — {state_text}")

    def setup_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Treeview",
            background="#252526",
            foreground="#ffffff",
            fieldbackground="#252526",
            rowheight=32,
            borderwidth=0,
            relief="flat",
            font=("Arial", 11)
        )
        style.map(
            "Treeview",
            background=[("selected", "#2f6fed")],
            foreground=[("selected", "#ffffff")]
        )

        style.configure(
            "Treeview.Heading",
            background="#2d2d30",
            foreground="#ffffff",
            font=("Arial", 11, "bold"),
            relief="flat",
            borderwidth=0
        )
        style.map("Treeview.Heading", background=[("active", "#3a3a3a")])

        style.configure(
            "Dark.TButton",
            background="#3a3a3a",
            foreground="#ffffff",
            borderwidth=0,
            focusthickness=0,
            focuscolor="none",
            padding=(18, 10),
            font=("Arial", 10)
        )
        style.map(
            "Dark.TButton",
            background=[("active", "#4a4a4a"), ("pressed", "#2f2f2f")],
            foreground=[("active", "#ffffff"), ("pressed", "#ffffff")]
        )

    def create_menu(self):
        menubar = tk.Menu(
            self,
            bg="#2b2b2b",
            fg="#ffffff",
            activebackground="#3a3a3a",
            activeforeground="#ffffff",
            bd=0
        )

        file_menu = tk.Menu(
            menubar, tearoff=0,
            bg="#2b2b2b", fg="#ffffff",
            activebackground="#3a3a3a", activeforeground="#ffffff"
        )
        file_menu.add_command(label="Разблокировать", command=self.unlock_vault)
        file_menu.add_command(label="Заблокировать", command=self.lock_vault)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        edit_menu = tk.Menu(
            menubar, tearoff=0,
            bg="#2b2b2b", fg="#ffffff",
            activebackground="#3a3a3a", activeforeground="#ffffff"
        )
        edit_menu.add_command(label="Добавить", command=self.add_record)
        edit_menu.add_command(label="Изменить", command=self.edit_record)
        edit_menu.add_command(label="Удалить", command=self.delete_record)
        menubar.add_cascade(label="Edit", menu=edit_menu)

        security_menu = tk.Menu(
            menubar, tearoff=0,
            bg="#2b2b2b", fg="#ffffff",
            activebackground="#3a3a3a", activeforeground="#ffffff"
        )
        security_menu.add_command(label="Сменить мастер-пароль", command=self.open_password_change_dialog)
        menubar.add_cascade(label="Security", menu=security_menu)

        view_menu = tk.Menu(
            menubar, tearoff=0,
            bg="#2b2b2b", fg="#ffffff",
            activebackground="#3a3a3a", activeforeground="#ffffff"
        )
        view_menu.add_command(label="Logs", command=lambda: AuditLogViewer(self))
        menubar.add_cascade(label="View", menu=view_menu)

        help_menu = tk.Menu(
            menubar, tearoff=0,
            bg="#2b2b2b", fg="#ffffff",
            activebackground="#3a3a3a", activeforeground="#ffffff"
        )
        help_menu.add_command(label="About")
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def create_toolbar(self):
        toolbar = tk.Frame(self, bg="#2d2d30", height=56)
        toolbar.pack(fill="x", padx=10, pady=(10, 0))
        toolbar.pack_propagate(False)

        self.btn_unlock = ttk.Button(
            toolbar,
            text="Разблокировать",
            command=self.unlock_vault,
            style="Dark.TButton"
        )
        self.btn_unlock.pack(side="left", padx=(10, 6), pady=8)

        self.btn_lock = ttk.Button(
            toolbar,
            text="Заблокировать",
            command=self.lock_vault,
            style="Dark.TButton"
        )
        self.btn_lock.pack(side="left", padx=6, pady=8)

        self.btn_add = ttk.Button(
            toolbar,
            text="Добавить",
            command=self.add_record,
            style="Dark.TButton"
        )
        self.btn_add.pack(side="left", padx=6, pady=8)

        self.btn_edit = ttk.Button(
            toolbar,
            text="Изменить",
            command=self.edit_record,
            style="Dark.TButton"
        )
        self.btn_edit.pack(side="left", padx=6, pady=8)

        self.btn_delete = ttk.Button(
            toolbar,
            text="Удалить",
            command=self.delete_record,
            style="Dark.TButton"
        )
        self.btn_delete.pack(side="left", padx=6, pady=8)
        self.btn_toggle_passwords = ttk.Button(
            toolbar,
            text="Показать пароли",
            command=self.toggle_passwords_visibility,
            style="Dark.TButton"
        )
        self.btn_toggle_passwords.pack(side="left", padx=6, pady=8)
        spacer = tk.Frame(toolbar, bg="#2d2d30")
        spacer.pack(side="left", fill="x", expand=True)

        search_wrap = tk.Frame(toolbar, bg="#2d2d30")
        search_wrap.pack(side="right", padx=(6, 10), pady=8)

        tk.Label(
            search_wrap,
            text="Поиск:",
            bg="#2d2d30",
            fg="#cfcfcf",
            font=("Arial", 10)
        ).pack(side="left", padx=(0, 8))

        self.search_entry = tk.Entry(
            search_wrap,
            textvariable=self.search_var,
            bg="#1e1e1e",
            fg="white",
            insertbackground="white",
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground="#3a3a3a",
            highlightcolor="#5a5a5a",
            font=("Arial", 10),
            width=34
        )
        self.search_entry.pack(side="left", ipady=7)

        self.btn_clear_search = ttk.Button(
            search_wrap,
            text="Сброс",
            command=self.clear_search,
            style="Dark.TButton"
        )
        self.btn_clear_search.pack(side="left", padx=(8, 0))


    def create_table(self):
        outer = tk.Frame(self, bg="#1e1e1e")
        outer.pack(fill="both", expand=True, padx=10, pady=10)

        table_frame = tk.Frame(outer, bg="#252526")
        table_frame.pack(fill="both", expand=True)

        self.table = SecureTable(table_frame)
        self.table.pack(fill="both", expand=True)

        self.table.bind_actions(
            on_edit=self._edit_entry_from_table,
            on_delete=self._delete_entries_from_table,
            on_copy_username=self._copy_username_from_table,
            on_copy_password=self._copy_password_from_table,
            on_open_url=self._open_url_from_table,
            on_selection_changed=self._on_table_selection_changed,
        )

        self.table.tree.bind("<Double-1>", lambda event: self.edit_record(), add="+")

    def create_statusbar(self):
        self.status = tk.StringVar(value="Готово")
        statusbar = tk.Label(
            self,
            textvariable=self.status,
            anchor="w",
            bg="#2d2d30",
            fg="#cfcfcf",
            font=("Arial", 10),
            padx=10,
            pady=6
        )
        statusbar.pack(fill="x", side="bottom")

    def set_status(self, text):
        self.status.set(text)

    def _clear_table(self):
        if not hasattr(self, "table"):
            return
        self.table.clear()

    def load_entries(self):
        if getattr(self, "locked", False):
            self.rows = []
            self.all_rows = []
            self.filtered_rows = []
            self._clear_table()
            return

        if not self.db:
            self.rows = []
            self.all_rows = []
            self.filtered_rows = []
            self._clear_table()
            return

        self.all_rows = self.vault_service.list_entries()
        self.apply_search()

    def refresh_table(self):
        self.table.set_rows(self.rows)

    def clear_search(self):
        self.search_var.set("")

    def _on_search_changed(self, *args):
        self.apply_search()

    def apply_search(self):
        if getattr(self, "locked", False):
            self.rows = []
            self.filtered_rows = []
            self._clear_table()
            return

        query = self.search_var.get().strip()
        self.filtered_rows = self.filter_rows(self.all_rows, query)
        self.rows = self.filtered_rows
        self.refresh_table()

        total = len(self.all_rows)
        shown = len(self.filtered_rows)

        if query:
            self.set_status(f"Найдено записей: {shown} из {total}")
        else:
            self.set_status(f"Записей: {shown}")

    def filter_rows(self, rows, query: str):
        if not query:
            return list(rows)

        tokens = self.parse_search_query(query)
        result = []

        for row in rows:
            if self.row_matches_search(row, tokens):
                result.append(row)

        return result

    def parse_search_query(self, query: str):
        try:
            parts = shlex.split(query)
        except ValueError:
            parts = query.split()

        tokens = []
        supported_fields = {"title", "username", "url", "notes"}

        for part in parts:
            if ":" in part:
                field, value = part.split(":", 1)
                field = field.lower().strip()
                value = value.strip()
                if field in supported_fields and value:
                    tokens.append(("field", field, value))
                    continue

            if part.strip():
                tokens.append(("text", part.strip()))

        return tokens

    def row_matches_search(self, row, tokens):
        for token in tokens:
            token_type = token[0]

            if token_type == "field":
                _, field, value = token
                row_value = self.get_row_field_value(row, field)
                if not self.match_text(row_value, value):
                    return False

            elif token_type == "text":
                _, value = token
                searchable = " ".join([
                    self.get_row_field_value(row, "title"),
                    self.get_row_field_value(row, "username"),
                    self.get_row_field_value(row, "url"),
                    self.get_row_field_value(row, "notes"),
                ])
                if not self.match_text(searchable, value):
                    return False

        return True

    def get_row_field_value(self, row, field_name: str) -> str:
        value = getattr(row, field_name, "")
        if value is None:
            return ""
        return str(value)

    def normalize_search_text(self, value: str) -> str:
        return " ".join(str(value).lower().strip().split())

    def match_text(self, haystack: str, needle: str) -> bool:
        haystack_norm = self.normalize_search_text(haystack)
        needle_norm = self.normalize_search_text(needle)

        if not needle_norm:
            return True

        if needle_norm in haystack_norm:
            return True

        haystack_words = haystack_norm.split()
        needle_words = needle_norm.split()

        for n_word in needle_words:
            if not any(self.is_fuzzy_match(n_word, h_word) for h_word in haystack_words):
                return False

        return True

    def is_fuzzy_match(self, needle: str, candidate: str) -> bool:
        if needle == candidate:
            return True

        if needle in candidate or candidate in needle:
            return True

        ratio = difflib.SequenceMatcher(None, needle, candidate).ratio()

        if len(needle) <= 4:
            return ratio >= 0.84
        if len(needle) <= 8:
            return ratio >= 0.76
        return ratio >= 0.72

    def open_password_change_dialog(self):
        dialog = PasswordChangeDialog(
            self,
            db=self.db,
            key_manager=self.key_manager,
            auth_service=self.auth_service,
        )
        self.wait_window(dialog)

    def get_selected_id(self):
        if self.locked:
            return None
        selected_id = self.table.get_first_selected_id()
        if not selected_id:
            return None
        return int(selected_id)

    def get_selected_ids(self):
        if self.locked:
            return []
        return [int(entry_id) for entry_id in self.table.get_selected_ids()]

    def get_row_by_id(self, entry_id: int):
        for row in self.rows:
            if row.id == entry_id:
                return row
        return None

    def _select_table_entry(self, entry_id: int):
        entry_id = str(entry_id)

        for item_id, mapped_id in self.table.item_to_entry_id.items():
            if mapped_id == entry_id:
                self.table.tree.selection_set(item_id)
                self.table.tree.focus(item_id)
                self.table.tree.see(item_id)
                return

    def _edit_entry_from_table(self, entry_id: str):
        if entry_id:
            self.edit_record()

    def _delete_entries_from_table(self, entry_ids: list[str]):
        if not entry_ids:
            return

        if self.locked:
            messagebox.showwarning("Хранилище заблокировано", "Сначала разблокируй хранилище", parent=self)
            return

        count = len(entry_ids)
        text = (
            f"Удалить выбранную запись?"
            if count == 1
            else f"Удалить выбранные записи: {count} шт.?"
        )

        if not messagebox.askyesno("Подтверждение", text, parent=self):
            return

        for entry_id in entry_ids:
            self.vault_service.delete_entry(int(entry_id))

        self.load_entries()
        self.set_status("Записи удалены")

    def _copy_username_from_table(self, entry_id: str):
        row = self.get_row_by_id(int(entry_id))
        if not row:
            return
        value = row.username or ""
        self.clipboard_clear()
        self.clipboard_append(row.username or "")
        if self.auth_service:
            self.auth_service.state.set_clipboard(value, 30)
        self.set_status("Логин скопирован")

    def _copy_password_from_table(self, entry_id: str):
        row = self.get_row_by_id(int(entry_id))
        if not row:
            return

        value = row.password or ""

        self.clipboard_clear()
        self.clipboard_append(row.password or "")
        if self.auth_service:
            self.auth_service.state.set_clipboard(value, 30)
        self.set_status("Пароль скопирован")


    def _open_url_from_table(self, entry_id: str):
        import webbrowser

        row = self.get_row_by_id(int(entry_id))
        if not row or not row.url:
            return

        url = row.url.strip()
        if "://" not in url:
            url = "https://" + url

        webbrowser.open(url)

    def _on_table_selection_changed(self):
        pass

    def toggle_passwords_visibility(self):
        self.table.toggle_password_visibility()

        if getattr(self.table, "passwords_visible", False):
            self.btn_toggle_passwords.config(text="Скрыть пароли")
            self.set_status("Пароли показаны")
        else:
            self.btn_toggle_passwords.config(text="Показать пароли")
            self.set_status("Пароли скрыты")

    def add_record(self):
        if self.locked:
            messagebox.showwarning("Хранилище заблокировано", "Сначала разблокируй хранилище", parent=self)
            return

        dialog = EntryDialog(self, title="Добавить запись")
        self.wait_window(dialog)

        if dialog.result:
            self.vault_service.add_entry({
                "title": dialog.result["title"],
                "username": dialog.result["username"],
                "password": dialog.result["password"],
                "url": dialog.result["url"],
                "category": dialog.result.get("category", ""),
                "notes": dialog.result["notes"],
                "tags": dialog.result.get("tags", ""),
            })
            self.load_entries()
            self.set_status("Запись добавлена")

    def edit_record(self):
        if self.locked:
            messagebox.showwarning("Хранилище заблокировано", "Сначала разблокируй хранилище", parent=self)
            return

        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showwarning("Внимание", "Сначала выберите запись.", parent=self)
            return

        row = self.get_row_by_id(entry_id)
        if row is None:
            messagebox.showerror("Ошибка", "Запись не найдена.", parent=self)
            return

        dialog = EntryDialog(
            self,
            title="Изменить запись",
            data={
                "title": row.title,
                "username": row.username,
                "password": row.password,
                "url": row.url,
                "category": row.category,
                "notes": row.notes,
                "tags": row.tags,
            }
        )
        self.wait_window(dialog)

        if dialog.result:
            self.vault_service.update_entry(entry_id, {
                "title": dialog.result["title"],
                "username": dialog.result["username"],
                "password": dialog.result["password"],
                "url": dialog.result["url"],
                "category": dialog.result.get("category", ""),
                "notes": dialog.result["notes"],
                "tags": dialog.result.get("tags", ""),
            })
            self.load_entries()
            self._select_table_entry(entry_id)
            self.set_status("Запись изменена")

    def delete_record(self):
        if self.locked:
            messagebox.showwarning("Хранилище заблокировано", "Сначала разблокируй хранилище", parent=self)
            return

        selected_ids = self.get_selected_ids()
        if not selected_ids:
            messagebox.showwarning("Внимание", "Сначала выберите запись.", parent=self)
            return

        count = len(selected_ids)
        text = (
            "Удалить выбранную запись?"
            if count == 1
            else f"Удалить выбранные записи: {count} шт.?"
        )

        if not messagebox.askyesno("Подтверждение", text, parent=self):
            return

        for entry_id in selected_ids:
            self.vault_service.delete_entry(entry_id)

        self.load_entries()
        self.set_status("Записи удалены")

    def _cancel_clipboard_clear_timer(self):
        if self._clipboard_clear_job is not None:
            try:
                self.after_cancel(self._clipboard_clear_job)
            except Exception:
                pass
            self._clipboard_clear_job = None

    def _clear_system_clipboard(self):
        self._clipboard_clear_job = None

        try:
            self.clipboard_clear()
            self.update_idletasks()
        except Exception:
            pass

        if self.auth_service:
            try:
                self.auth_service.state.clear_clipboard()
            except Exception:
                pass

        self.set_status("Буфер обмена очищен")

    def _schedule_clipboard_clear_after_lock(self):
        self._cancel_clipboard_clear_timer()
        self._clipboard_clear_job = self.after(
            self._clipboard_clear_delay_ms,
            self._clear_system_clipboard
        )

    def apply_locked_state(self):
        self.locked = True
        self._schedule_clipboard_clear_after_lock()

        self.rows = []
        self._clear_table()
        self.all_rows = []
        self.filtered_rows = []
        self.search_var.set("")

        self.btn_unlock.config(state="normal")
        self.btn_lock.config(state="disabled")
        self.btn_add.config(state="disabled")
        self.btn_edit.config(state="disabled")
        self.btn_delete.config(state="disabled")

        self.set_status("Хранилище заблокировано")
        self.update_window_title()

    def apply_unlocked_state(self):
        self._cancel_clipboard_clear_timer()
        self.locked = False
        self.btn_unlock.config(state="disabled")
        self.btn_lock.config(state="normal")
        self.btn_add.config(state="normal")
        self.btn_edit.config(state="normal")
        self.btn_delete.config(state="normal")
        self.load_entries()
        self.set_status("Хранилище разблокировано")
        self.update_window_title()

    def lock_vault(self):
        if self.auth_service:
            try:
                self.auth_service.logout()
            except Exception:
                pass
        self.apply_locked_state()

    def unlock_vault(self):
        if not self.auth_service:
            messagebox.showerror("Ошибка", "Сервис аутентификации не подключён", parent=self)
            return

        dlg = LoginDialog(self, self.auth_service)
        self.wait_window(dlg)

        if getattr(dlg, "result", False):
            self.apply_unlocked_state()
        else:
            self.apply_locked_state()

    def _bind_auth_integration(self):
        if not self.auth_service:
            return

        self.bind_all("<Any-KeyPress>", self._mark_activity, add="+")
        self.bind_all("<Any-ButtonPress>", self._mark_activity, add="+")
        self.bind("<FocusIn>", self._on_focus_in, add="+")
        self.bind("<FocusOut>", self._on_focus_out, add="+")
        self.bind("<Unmap>", self._on_unmap, add="+")
        self.bind("<Map>", self._on_map, add="+")
        self.bind_all("<Control-Shift-P>", lambda event: self.toggle_passwords_visibility(), add="+")

    def _mark_activity(self, event=None):
        if self.auth_service and self.auth_service.is_unlocked():
            self.auth_service.touch()

    def _on_focus_out(self, event=None):
        if self._focus_out_job is not None:
            self.after_cancel(self._focus_out_job)

        self._focus_out_job = self.after(50, self._handle_real_focus_loss)

    def _handle_real_focus_loss(self):
        self._focus_out_job = None

        current = self.focus_displayof()
        if current is not None:
            return

        if not self._has_focus:
            return

        self._has_focus = False

        if self.auth_service and self.auth_service.is_unlocked():
            self.auth_service.on_app_focus_lost()
            self.apply_locked_state()

    def _on_focus_in(self, event=None):
        if not self._has_focus:
            self._has_focus = True
            if self.auth_service:
                self.auth_service.on_app_focus_gained()

    def _on_unmap(self, event=None):
        if self.state() == "iconic" and not self._is_minimized:
            self._is_minimized = True

        if self.auth_service and self.auth_service.is_unlocked():
            self.auth_service.on_app_minimized()
            self.apply_locked_state()

    def _on_map(self, event=None):
        if self._is_minimized:
            self._is_minimized = False

            if self.auth_service:
                self.auth_service.on_app_restored()

    def _poll_session_state(self):
        try:
            if self.auth_service and self.auth_service.check_auto_lock():
                self.apply_locked_state()
                return
        finally:
            self.after(1000, self._poll_session_state)

    def on_close(self):
        if self.auth_service:
            try:
                self.auth_service.logout()
            except Exception:
                pass

        if hasattr(self.db, "close_thread_connection"):
            self.db.close_thread_connection()

        self.destroy()


if __name__ == "__main__":
    MainWindow().mainloop()