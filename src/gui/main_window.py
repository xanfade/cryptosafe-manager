import tkinter as tk
from tkinter import ttk, messagebox
from src.gui.password_change_dialog import PasswordChangeDialog
from src.database.db import Database
from src.gui.widgets.audit_log_viewer import AuditLogViewer


class EntryDialog(tk.Toplevel):
    def __init__(self, parent, title="Добавить запись", data=None):
        super().__init__(parent)
        self.parent = parent
        self.result = None

        self.title(title)
        self.geometry("640x520")
        self.resizable(False, False)
        self.configure(bg="#1e1e1e")
        self.transient(parent)
        self.grab_set()

        initial = data if data else {
            "title": "",
            "username": "",
            "password": "",
            "url": "",
            "notes": "",
        }

        container = tk.Frame(self, bg="#1e1e1e", padx=24, pady=20)
        container.pack(fill="both", expand=True)

        tk.Label(
            container,
            text=title,
            font=("Arial", 20, "bold"),
            bg="#1e1e1e",
            fg="#ffffff"
        ).pack(anchor="w", pady=(0, 18))

        form = tk.Frame(container, bg="#1e1e1e")
        form.pack(fill="x", expand=False)

        self.fields = {}

        self._create_label(form, "Название", 0)
        self.fields["title"] = self._create_entry(form, 1, initial["title"])

        self._create_label(form, "Имя пользователя", 2)
        self.fields["username"] = self._create_entry(form, 3, initial["username"])

        self._create_label(form, "Пароль", 4)
        self.fields["password"] = self._create_entry(form, 5, initial["password"])

        self._create_label(form, "URL", 6)
        self.fields["url"] = self._create_entry(form, 7, initial["url"])

        self._create_label(form, "Заметки", 8)
        notes = tk.Text(
            form,
            height=4,
            font=("Arial", 11),
            bg="#2b2b2b",
            fg="#ffffff",
            insertbackground="#ffffff",
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground="#3a3a3a",
            highlightcolor="#5a5a5a",
            wrap="word"
        )
        notes.grid(row=9, column=0, sticky="ew", pady=(0, 18), ipady=6)
        notes.insert("1.0", initial["notes"])
        self.fields["notes"] = notes

        form.columnconfigure(0, weight=1)

        buttons = tk.Frame(container, bg="#1e1e1e")
        buttons.pack(fill="x", pady=(8, 0))

        self.save_btn = self._make_action_button(
            buttons,
            text="Добавить запись" if "Добавить" in title else "Сохранить",
            command=self.on_save,
            bg="#2f6fed",
            hover_bg="#2559be",
            width=18
        )
        self.save_btn.pack(side="left")

        self.cancel_btn = self._make_action_button(
            buttons,
            text="Отмена",
            command=self.destroy,
            bg="#3a3a3a",
            hover_bg="#4a4a4a",
            width=14
        )
        self.cancel_btn.pack(side="right")

        self.bind("<Return>", lambda event: self.on_save())
        self.bind("<Escape>", lambda event: self.destroy())

        self.after(10, self.center_window)

    def _create_label(self, parent, text, row):
        tk.Label(
            parent,
            text=text,
            font=("Arial", 11, "bold"),
            bg="#1e1e1e",
            fg="#d7d7d7"
        ).grid(row=row, column=0, sticky="w", pady=(0, 6))

    def _create_entry(self, parent, row, value=""):
        entry = tk.Entry(
            parent,
            font=("Arial", 11),
            bg="#2b2b2b",
            fg="#ffffff",
            insertbackground="#ffffff",
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground="#3a3a3a",
            highlightcolor="#5a5a5a"
        )
        entry.grid(row=row, column=0, sticky="ew", pady=(0, 16), ipady=10)
        entry.insert(0, value)
        return entry

    def _make_action_button(self, parent, text, command, bg, hover_bg, width=14):
        btn = tk.Label(
            parent,
            text=text,
            bg=bg,
            fg="#ffffff",
            font=("Arial", 10, "bold"),
            padx=14,
            pady=10,
            cursor="hand2",
            width=width
        )
        btn.bind("<Button-1>", lambda e: command())
        btn.bind("<Enter>", lambda e: btn.config(bg=hover_bg))
        btn.bind("<Leave>", lambda e: btn.config(bg=bg))
        return btn

    def center_window(self):
        self.update_idletasks()
        parent_x = self.parent.winfo_rootx()
        parent_y = self.parent.winfo_rooty()
        parent_w = self.parent.winfo_width()
        parent_h = self.parent.winfo_height()
        win_w = self.winfo_width()
        win_h = self.winfo_height()

        x = parent_x + (parent_w // 2) - (win_w // 2)
        y = parent_y + (parent_h // 2) - (win_h // 2)
        self.geometry(f"+{x}+{y}")

    def on_save(self):
        title_value = self.fields["title"].get().strip()
        username = self.fields["username"].get().strip()
        password = self.fields["password"].get().strip()
        url = self.fields["url"].get().strip()
        notes = self.fields["notes"].get("1.0", "end").strip()

        if not title_value:
            messagebox.showwarning("Ошибка", "Поле 'Название' обязательно.", parent=self)
            return

        self.result = {
            "title": title_value,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
        }
        self.destroy()


class MainWindow(tk.Tk):
    def __init__(self, db=None, key_manager=None, auth_service=None):
        super().__init__()
        self.title("CryptoSafe Manager")
        self.geometry("1100x620")
        self.minsize(900, 540)
        self.configure(bg="#1e1e1e")

        self.db = db
        self.key_manager = key_manager
        self.auth_service = auth_service

        self._focus_out_job = None
        self._poll_job = None
        self._is_minimized = False

        self.rows = []

        self.setup_styles()
        self.create_menu()
        self.create_toolbar()
        self.create_table()
        self.create_statusbar()
        self.load_entries()
        self.set_status("Готово")


        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.bind("<FocusIn>", self._on_focus_in)
        self.bind("<FocusOut>", self._on_focus_out)
        self.bind("<Unmap>", self._on_unmap)
        self.bind("<Map>", self._on_map)
        self.bind_all("<Any-KeyPress>", self._on_user_activity)
        self.bind_all("<Any-ButtonPress>", self._on_user_activity)
        self.bind_all("<Motion>", self._on_user_activity)

        self._start_security_poll()

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
            background=[
                ("active", "#4a4a4a"),
                ("pressed", "#2f2f2f")
            ],
            foreground=[
                ("active", "#ffffff"),
                ("pressed", "#ffffff")
            ]
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
            menubar,
            tearoff=0,
            bg="#2b2b2b",
            fg="#ffffff",
            activebackground="#3a3a3a",
            activeforeground="#ffffff"
        )
        file_menu.add_command(label="New")
        file_menu.add_command(label="Open")
        file_menu.add_command(label="Backup")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close if hasattr(self, "on_close") else self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        edit_menu = tk.Menu(
            menubar,
            tearoff=0,
            bg="#2b2b2b",
            fg="#ffffff",
            activebackground="#3a3a3a",
            activeforeground="#ffffff"
        )
        edit_menu.add_command(label="Добавить", command=self.add_record)
        edit_menu.add_command(label="Изменить", command=self.edit_record)
        edit_menu.add_command(label="Удалить", command=self.delete_record)
        menubar.add_cascade(label="Edit", menu=edit_menu)

        security_menu = tk.Menu(
            menubar,
            tearoff=0,
            bg="#2b2b2b",
            fg="#ffffff",
            activebackground="#3a3a3a",
            activeforeground="#ffffff"
        )
        security_menu.add_command(label="Сменить мастер-пароль", command=self.open_password_change_dialog)
        menubar.add_cascade(label="Security", menu=security_menu)

        view_menu = tk.Menu(
            menubar,
            tearoff=0,
            bg="#2b2b2b",
            fg="#ffffff",
            activebackground="#3a3a3a",
            activeforeground="#ffffff"
        )
        view_menu.add_command(label="Logs", command=lambda: AuditLogViewer(self))
        view_menu.add_command(label="Settings")
        menubar.add_cascade(label="View", menu=view_menu)

        help_menu = tk.Menu(
            menubar,
            tearoff=0,
            bg="#2b2b2b",
            fg="#ffffff",
            activebackground="#3a3a3a",
            activeforeground="#ffffff"
        )
        help_menu.add_command(label="About")
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def create_toolbar(self):
        toolbar = tk.Frame(self, bg="#2d2d30", height=56)
        toolbar.pack(fill="x", padx=10, pady=(10, 0))
        toolbar.pack_propagate(False)

        self.add_btn = ttk.Button(
            toolbar,
            text="Добавить",
            command=self.add_record,
            style="Dark.TButton"
        )
        self.add_btn.pack(side="left", padx=(10, 6), pady=8)

        self.edit_btn = ttk.Button(
            toolbar,
            text="Изменить",
            command=self.edit_record,
            style="Dark.TButton"
        )
        self.edit_btn.pack(side="left", padx=6, pady=8)

        self.delete_btn = ttk.Button(
            toolbar,
            text="Удалить",
            command=self.delete_record,
            style="Dark.TButton"
        )
        self.delete_btn.pack(side="left", padx=6, pady=8)

    def create_table(self):
        outer = tk.Frame(self, bg="#1e1e1e")
        outer.pack(fill="both", expand=True, padx=10, pady=10)

        table_frame = tk.Frame(outer, bg="#252526")
        table_frame.pack(fill="both", expand=True)

        columns = ("title", "username", "password", "url", "notes")
        self.table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        self.table.heading("title", text="Название")
        self.table.heading("username", text="Имя пользователя")
        self.table.heading("password", text="Пароль")
        self.table.heading("url", text="URL")
        self.table.heading("notes", text="Заметки")

        self.table.column("title", width=180, anchor="w")
        self.table.column("username", width=170, anchor="w")
        self.table.column("password", width=140, anchor="w")
        self.table.column("url", width=240, anchor="w")
        self.table.column("notes", width=300, anchor="w")

        y_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        x_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.table.xview)

        self.table.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.table.pack(side="left", fill="both", expand=True)
        y_scroll.pack(side="right", fill="y")
        x_scroll.pack(side="bottom", fill="x")

        self.table.bind("<Double-1>", lambda event: self.edit_record())

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

    def load_entries(self):
        self.rows = self.db.get_all_entries()
        self.refresh_table()

    def refresh_table(self):
        for item in self.table.get_children():
            self.table.delete(item)

        for row in self.rows:
            self.table.insert(
                "",
                "end",
                iid=str(row["id"]),
                values=(
                    row["title"],
                    row["username"],
                    row["password"],
                    row["url"],
                    row["notes"]
                )
            )

    def open_password_change_dialog(self):
        dialog = PasswordChangeDialog(
            self,
            db=self.db,
            key_manager=self.key_manager,
            auth_service=self.auth_service,
        )
        self.wait_window(dialog)

    def get_selected_id(self):
        selected = self.table.selection()
        if not selected:
            return None
        return int(selected[0])

    def get_row_by_id(self, entry_id: int):
        for row in self.rows:
            if row["id"] == entry_id:
                return row
        return None

    def add_record(self):
        dialog = EntryDialog(self, title="Добавить запись")
        self.wait_window(dialog)

        if dialog.result:
            self.db.add_entry(
                title=dialog.result["title"],
                username=dialog.result["username"],
                password=dialog.result["password"],
                url=dialog.result["url"],
                notes=dialog.result["notes"]
            )
            self.load_entries()
            self.set_status("Запись добавлена")

    def edit_record(self):
        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showwarning("Внимание", "Сначала выберите запись.", parent=self)
            return

        row = self.get_row_by_id(entry_id)
        if row is None:
            messagebox.showerror("Ошибка", "Запись не найдена.", parent=self)
            return

        dialog = EntryDialog(self, title="Изменить запись", data=row)
        self.wait_window(dialog)

        if dialog.result:
            self.db.update_entry(
                entry_id=entry_id,
                title=dialog.result["title"],
                username=dialog.result["username"],
                password=dialog.result["password"],
                url=dialog.result["url"],
                notes=dialog.result["notes"]
            )
            self.load_entries()
            self.table.selection_set(str(entry_id))
            self.table.focus(str(entry_id))
            self.set_status("Запись изменена")

    def delete_record(self):
        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showwarning("Внимание", "Сначала выберите запись.", parent=self)
            return

        confirm = messagebox.askyesno(
            "Подтверждение",
            "Удалить выбранную запись?",
            parent=self
        )
        if confirm:
            self.db.delete_entry(entry_id)
            self.load_entries()
            self.set_status("Запись удалена")

    def on_close(self):
        if hasattr(self.db, "close_thread_connection"):
            self.db.close_thread_connection()
        self.destroy()

    def _on_user_activity(self, event=None):
        if self.auth_service:
            self.auth_service.touch()

    def _on_focus_out(self, event=None):
        if not self.auth_service:
            return

        if self._focus_out_job is not None:
            self.after_cancel(self._focus_out_job)

        self._focus_out_job = self.after(150, self._apply_focus_out)

    def _apply_focus_out(self):
        self._focus_out_job = None
        if self.auth_service:
            self.auth_service.on_app_focus_lost()
            self.set_status("Ключ очищен: приложение потеряло фокус")

    def _on_focus_in(self, event=None):
        if self._focus_out_job is not None:
            self.after_cancel(self._focus_out_job)
            self._focus_out_job = None

        if self.auth_service:
            self.auth_service.on_app_focus_gained()
            self.set_status("Приложение активно")

    def _on_unmap(self, event=None):
        if self.state() == "iconic":
            self._is_minimized = True
            if self.auth_service:
                self.auth_service.on_app_minimized()
                self.set_status("Ключ очищен: приложение свёрнуто")

    def _on_map(self, event=None):
        if self._is_minimized:
            self._is_minimized = False
            if self.auth_service:
                self.auth_service.on_app_restored()
                self.set_status("Приложение восстановлено")

    def _start_security_poll(self):
        self._poll_job = self.after(15_000, self._security_tick)

    def _security_tick(self):
        try:
            if self.auth_service and not self.auth_service.is_unlocked():
                self.set_status("Хранилище заблокировано")
        finally:
            self._poll_job = self.after(15_000, self._security_tick)

    def on_close(self):
        try:
            if self.auth_service:
                self.auth_service.logout()
        finally:
            self.destroy()


if __name__ == "__main__":
    MainWindow().mainloop()