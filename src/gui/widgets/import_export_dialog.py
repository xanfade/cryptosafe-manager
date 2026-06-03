from __future__ import annotations

import json
import os
import hashlib
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from src.core.import_export import KeyExchangeService, SecureSharingService, VaultExporter, VaultImporter
from src.core.events import EntryShared, NetworkShareRequested, VaultDataImported
from src.gui.login_dialog import LoginDialog
from src.gui.theme import COLORS, FONTS
from src.gui.widgets.qr_exchange_window import QrExchangeWindow


FORMAT_DESCRIPTIONS = {
    "json": "Зашифрованный нативный JSON со всеми метаданными и защитой целостности.",
    "csv": "Экспорт CSV для миграции и работы в таблицах.",
    "bitwarden_encrypted_json": "Зашифрованный экспорт Bitwarden JSON с паролем.",
    "lastpass_csv": "CSV-формат LastPass для миграции.",
    "password_manager_json": "Универсальная JSON-структура менеджера паролей.",
}


class ImportExportDialog(tk.Toplevel):
    def __init__(self, master, db, vault_service, key_manager, event_bus=None):
        super().__init__(master)
        self.db = db
        self.vault_service = vault_service
        self.key_manager = key_manager
        self.event_bus = event_bus
        self.key_exchange = KeyExchangeService.from_database(db, algorithm="p256")
        panic_checker = lambda: bool(getattr(master, "_panic_in_progress", False))
        self.exporter = VaultExporter(
            vault_service,
            key_manager,
            event_bus=event_bus,
            key_exchange=self.key_exchange,
            panic_checker=panic_checker,
        )
        self.importer = VaultImporter(
            vault_service,
            key_manager,
            key_exchange=self.key_exchange,
            panic_checker=panic_checker,
        )
        self.sharing = SecureSharingService(self.exporter, importer=self.importer, key_exchange=self.key_exchange)

        self.selected_export_ids: set[int] = set()
        self.current_import_path: str | None = None
        self.current_import_format: str | None = None
        self.import_preview_result = None

        self.title("Импорт / Экспорт / Обмен")
        self.geometry("1180x820")
        self.minsize(1040, 760)
        self.configure(bg=COLORS["bg"])
        self.transient(master)
        self.grab_set()

        self._setup_styles()
        self._build()
        self._load_export_entries()
        self._load_share_entries()
        self._load_share_history()

    def _setup_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Vault.TNotebook", background=COLORS["bg"], borderwidth=0)
        style.configure(
            "Vault.TNotebook.Tab",
            background=COLORS["surface"],
            foreground=COLORS["text"],
            padding=(12, 8),
        )
        style.map(
            "Vault.TNotebook.Tab",
            background=[("selected", "#7c3aed"), ("active", "#6d28d9")],
            foreground=[("selected", "#ffffff"), ("active", "#ffffff")],
        )
        style.configure(
            "Vault.Treeview",
            background=COLORS["surface"],
            fieldbackground=COLORS["surface"],
            foreground=COLORS["text"],
            rowheight=30,
        )
        style.configure(
            "Vault.Treeview.Heading",
            background=COLORS["surface_2"],
            foreground=COLORS["text"],
        )
        style.map("Vault.Treeview", background=[("selected", "#7c3aed")], foreground=[("selected", "#ffffff")])

    def _build(self):
        self._scroll_canvas = tk.Canvas(self, bg=COLORS["bg"], highlightthickness=0, bd=0)
        self._scroll_canvas.pack(side="left", fill="both", expand=True)
        scrollbar = tk.Scrollbar(
            self,
            orient="vertical",
            command=self._scroll_canvas.yview,
            bg="#7c3aed",
            troughcolor="#1b1524",
            activebackground="#8b5cf6",
            highlightthickness=0,
            bd=0,
            relief="flat",
            width=14,
        )
        scrollbar.pack(side="right", fill="y")
        self._scroll_canvas.configure(yscrollcommand=scrollbar.set)

        wrapper = tk.Frame(self._scroll_canvas, bg=COLORS["bg"])
        canvas_window = self._scroll_canvas.create_window((0, 0), window=wrapper, anchor="nw")
        wrapper.bind("<Configure>", lambda _event: self._scroll_canvas.configure(scrollregion=self._scroll_canvas.bbox("all")))
        self._scroll_canvas.bind("<Configure>", lambda event: self._scroll_canvas.itemconfigure(canvas_window, width=event.width))
        self._bind_mousewheel_to_canvas(self._scroll_canvas)

        notebook = ttk.Notebook(wrapper, style="Vault.TNotebook")
        notebook.pack(fill="both", expand=True, padx=14, pady=14)

        self.export_tab = tk.Frame(notebook, bg=COLORS["bg"])
        self.import_tab = tk.Frame(notebook, bg=COLORS["bg"])
        self.share_tab = tk.Frame(notebook, bg=COLORS["bg"])
        notebook.add(self.export_tab, text="Экспорт")
        notebook.add(self.import_tab, text="Импорт")
        notebook.add(self.share_tab, text="Обмен")

        self._build_export_tab()
        self._build_import_tab()
        self._build_share_tab()

    def _build_export_tab(self):
        left = tk.Frame(self.export_tab, bg=COLORS["bg"])
        left.pack(side="left", fill="y", padx=(0, 12), pady=8)
        center = tk.Frame(self.export_tab, bg=COLORS["surface"])
        center.pack(side="left", fill="both", expand=True, pady=8)
        right = tk.Frame(self.export_tab, bg=COLORS["surface_2"], width=360)
        right.pack(side="right", fill="y", pady=8)
        right.pack_propagate(False)

        self.export_format = tk.StringVar(value="json")
        self.export_encryption = tk.StringVar(value="master")
        self.export_strength = tk.StringVar(value="256")
        self.export_compress = tk.BooleanVar(value=False)
        self.export_password = tk.StringVar()
        self.export_include_notes = tk.BooleanVar(value=True)
        self.export_public_recipient = tk.StringVar()
        self.export_query = tk.StringVar()

        tk.Label(left, text="Формат", bg=COLORS["bg"], fg=COLORS["text"], font=FONTS["subtitle"]).pack(anchor="w")
        fmt = ttk.Combobox(left, textvariable=self.export_format, state="readonly", values=["json", "csv", "bitwarden_encrypted_json", "lastpass_csv", "password_manager_json"], width=26)
        fmt.pack(fill="x", pady=(4, 8))
        fmt.bind("<<ComboboxSelected>>", lambda _e: self._update_export_description())
        self.export_desc = tk.Label(left, text="", bg=COLORS["bg"], fg=COLORS["muted"], justify="left", wraplength=280)
        self.export_desc.pack(anchor="w", pady=(0, 14))

        tk.Label(left, text="Шифрование", bg=COLORS["bg"], fg=COLORS["text"], font=FONTS["subtitle"]).pack(anchor="w")
        ttk.Combobox(left, textvariable=self.export_encryption, state="readonly", values=["master", "password", "public_key"], width=26).pack(fill="x", pady=(4, 8))
        tk.Label(left, text="Контакт получателя", bg=COLORS["bg"], fg=COLORS["muted"]).pack(anchor="w")
        self.export_recipient_combo = ttk.Combobox(left, textvariable=self.export_public_recipient, state="readonly", width=26)
        self.export_recipient_combo.pack(fill="x", pady=(4, 8))
        tk.Label(left, text="Пароль экспорта", bg=COLORS["bg"], fg=COLORS["muted"]).pack(anchor="w")
        tk.Entry(left, textvariable=self.export_password, show="*", bg=COLORS["surface"], fg=COLORS["text"], insertbackground=COLORS["text"]).pack(fill="x", pady=(4, 8))
        tk.Label(left, text="Стойкость", bg=COLORS["bg"], fg=COLORS["muted"]).pack(anchor="w")
        ttk.Combobox(left, textvariable=self.export_strength, state="readonly", values=["128", "256"], width=10).pack(fill="x", pady=(4, 8))
        tk.Checkbutton(left, text="Сжать с помощью GZIP", variable=self.export_compress, bg=COLORS["bg"], fg=COLORS["text"], selectcolor=COLORS["surface_2"]).pack(anchor="w", pady=(6, 2))
        tk.Checkbutton(left, text="Включать заметки", variable=self.export_include_notes, bg=COLORS["bg"], fg=COLORS["text"], selectcolor=COLORS["surface_2"]).pack(anchor="w", pady=(2, 12))
        tk.Label(left, text="Запрос по хранилищу", bg=COLORS["bg"], fg=COLORS["muted"]).pack(anchor="w")
        tk.Entry(left, textvariable=self.export_query, bg=COLORS["surface"], fg=COLORS["text"], insertbackground=COLORS["text"]).pack(fill="x", pady=(4, 8))
        ttk.Button(left, text="Выбрать по запросу", command=self._select_query_matches).pack(fill="x", pady=(0, 8))

        ttk.Button(left, text="Предпросмотр экспорта", command=self._preview_export).pack(fill="x", pady=(8, 6))
        ttk.Button(left, text="Экспортировать файл", command=self._run_export).pack(fill="x")

        tk.Label(center, text="Записи", bg=COLORS["surface"], fg=COLORS["text"], font=FONTS["subtitle"]).pack(anchor="w", padx=12, pady=(10, 6))
        tools = tk.Frame(center, bg=COLORS["surface"])
        tools.pack(fill="x", padx=12, pady=(0, 8))
        ttk.Button(tools, text="Выбрать все", command=lambda: self._toggle_all_export_entries(True)).pack(side="left")
        ttk.Button(tools, text="Сброс", command=lambda: self._toggle_all_export_entries(False)).pack(side="left", padx=(8, 0))

        export_tree_wrap = tk.Frame(center, bg=COLORS["surface"])
        export_tree_wrap.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        export_tree_wrap.grid_rowconfigure(0, weight=1)
        export_tree_wrap.grid_columnconfigure(0, weight=1)
        self.export_tree = ttk.Treeview(export_tree_wrap, columns=("check", "id", "title", "username", "url"), show="headings", height=18, style="Vault.Treeview")
        for col, title, width in [
            ("check", "", 50),
            ("id", "ID", 70),
            ("title", "Название", 200),
            ("username", "Логин", 200),
            ("url", "URL", 260),
        ]:
            self.export_tree.heading(col, text=title)
            self.export_tree.column(col, width=width, anchor="w")
        self.export_tree.grid(row=0, column=0, sticky="nsew")
        export_tree_scroll = ttk.Scrollbar(export_tree_wrap, orient="vertical", style="Vertical.TScrollbar", command=self.export_tree.yview)
        export_tree_scroll.grid(row=0, column=1, sticky="ns")
        self.export_tree.configure(yscrollcommand=export_tree_scroll.set)
        self.export_tree.bind("<Button-1>", self._on_export_tree_click)

        tk.Label(right, text="Предпросмотр", bg=COLORS["surface_2"], fg=COLORS["text"], font=FONTS["subtitle"]).pack(anchor="w", padx=12, pady=(10, 6))
        export_preview_wrap = tk.Frame(right, bg=COLORS["surface_2"])
        export_preview_wrap.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        export_preview_wrap.grid_rowconfigure(0, weight=1)
        export_preview_wrap.grid_columnconfigure(0, weight=1)
        self.export_preview = tk.Text(export_preview_wrap, bg=COLORS["surface"], fg=COLORS["text"], insertbackground=COLORS["text"], wrap="word")
        self.export_preview.grid(row=0, column=0, sticky="nsew")
        export_preview_scroll = ttk.Scrollbar(export_preview_wrap, orient="vertical", style="Vertical.TScrollbar", command=self.export_preview.yview)
        export_preview_scroll.grid(row=0, column=1, sticky="ns")
        self.export_preview.configure(yscrollcommand=export_preview_scroll.set)
        self._update_export_description()

    def _build_import_tab(self):
        left = tk.Frame(self.import_tab, bg=COLORS["bg"])
        left.pack(side="left", fill="y", padx=(0, 12), pady=8)
        right = tk.Frame(self.import_tab, bg=COLORS["surface"])
        right.pack(side="right", fill="both", expand=True, pady=8)

        self.import_detected_format = tk.StringVar(value="Файл не выбран")
        self.import_mode = tk.StringVar(value="merge")
        self.import_conflicts = tk.StringVar(value="update")
        self.import_password = tk.StringVar()
        self.import_summary = tk.StringVar(value="Предпросмотр ещё не выполнен")

        ttk.Button(left, text="Выбрать файл", command=self._choose_import_file).pack(fill="x")
        tk.Label(left, textvariable=self.import_detected_format, bg=COLORS["bg"], fg=COLORS["muted"], justify="left", wraplength=280).pack(anchor="w", pady=(8, 14))
        tk.Label(left, text="Пароль импорта", bg=COLORS["bg"], fg=COLORS["muted"]).pack(anchor="w")
        tk.Entry(left, textvariable=self.import_password, show="*", bg=COLORS["surface"], fg=COLORS["text"], insertbackground=COLORS["text"]).pack(fill="x", pady=(4, 8))
        tk.Label(left, text="Режим", bg=COLORS["bg"], fg=COLORS["text"], font=FONTS["subtitle"]).pack(anchor="w")
        ttk.Combobox(left, textvariable=self.import_mode, state="readonly", values=["merge", "replace", "dry-run"], width=22).pack(fill="x", pady=(4, 8))
        tk.Label(left, text="Конфликты", bg=COLORS["bg"], fg=COLORS["text"], font=FONTS["subtitle"]).pack(anchor="w")
        ttk.Combobox(left, textvariable=self.import_conflicts, state="readonly", values=["update", "skip", "error"], width=22).pack(fill="x", pady=(4, 14))
        ttk.Button(left, text="Предпросмотр импорта", command=self._preview_import).pack(fill="x", pady=(0, 6))
        ttk.Button(left, text="Выполнить импорт", command=self._run_import).pack(fill="x")
        tk.Label(left, textvariable=self.import_summary, bg=COLORS["bg"], fg=COLORS["muted"], justify="left", wraplength=280).pack(anchor="w", pady=(14, 0))

        header = tk.Frame(right, bg=COLORS["surface"])
        header.pack(fill="x", padx=12, pady=(10, 6))
        tk.Label(header, text="Предпросмотр импорта", bg=COLORS["surface"], fg=COLORS["text"], font=FONTS["subtitle"]).pack(side="left")
        import_preview_wrap = tk.Frame(right, bg=COLORS["surface"])
        import_preview_wrap.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        import_preview_wrap.grid_rowconfigure(0, weight=1)
        import_preview_wrap.grid_columnconfigure(0, weight=1)
        self.import_preview = tk.Text(import_preview_wrap, bg=COLORS["surface_2"], fg=COLORS["text"], insertbackground=COLORS["text"], wrap="word")
        self.import_preview.grid(row=0, column=0, sticky="nsew")
        import_preview_scroll = ttk.Scrollbar(import_preview_wrap, orient="vertical", style="Vertical.TScrollbar", command=self.import_preview.yview)
        import_preview_scroll.grid(row=0, column=1, sticky="ns")
        self.import_preview.configure(yscrollcommand=import_preview_scroll.set)

    def _build_share_tab(self):
        left = tk.Frame(self.share_tab, bg=COLORS["bg"])
        left.pack(side="left", fill="y", padx=(0, 12), pady=8)
        right = tk.Frame(self.share_tab, bg=COLORS["surface"])
        right.pack(side="right", fill="both", expand=True, pady=8)

        self.share_entry_id = tk.StringVar()
        self.share_recipient = tk.StringVar()
        self.share_method = tk.StringVar(value="public_key")
        self.share_permission = tk.StringVar(value="read-only")
        self.share_expiration = tk.IntVar(value=5)
        self.share_delivery = tk.StringVar(value="qr")
        self.share_password = tk.StringVar()
        self.share_link_base = tk.StringVar(value="https://shares.local")
        self.share_status = tk.StringVar(value="Общий пакет не создан")

        tk.Label(left, text="Запись", bg=COLORS["bg"], fg=COLORS["text"], font=FONTS["subtitle"]).pack(anchor="w")
        self.share_entry_combo = ttk.Combobox(left, textvariable=self.share_entry_id, state="readonly", width=28)
        self.share_entry_combo.pack(fill="x", pady=(4, 8))
        tk.Label(left, text="Получатель", bg=COLORS["bg"], fg=COLORS["text"], font=FONTS["subtitle"]).pack(anchor="w")
        self.share_recipient_combo = ttk.Combobox(left, textvariable=self.share_recipient, width=28)
        self.share_recipient_combo.pack(fill="x", pady=(4, 8))
        tk.Label(left, text="Метод", bg=COLORS["bg"], fg=COLORS["text"], font=FONTS["subtitle"]).pack(anchor="w")
        ttk.Combobox(left, textvariable=self.share_method, state="readonly", values=["public_key", "password"], width=28).pack(fill="x", pady=(4, 8))
        tk.Label(left, text="Пароль", bg=COLORS["bg"], fg=COLORS["muted"]).pack(anchor="w")
        tk.Entry(left, textvariable=self.share_password, show="*", bg=COLORS["surface"], fg=COLORS["text"], insertbackground=COLORS["text"]).pack(fill="x", pady=(4, 8))
        tk.Label(left, text="Права", bg=COLORS["bg"], fg=COLORS["text"], font=FONTS["subtitle"]).pack(anchor="w")
        ttk.Combobox(left, textvariable=self.share_permission, state="readonly", values=["read-only", "editable"], width=28).pack(fill="x", pady=(4, 8))
        tk.Label(left, text="Срок действия (дни)", bg=COLORS["bg"], fg=COLORS["text"], font=FONTS["subtitle"]).pack(anchor="w")
        tk.Spinbox(left, from_=1, to=30, textvariable=self.share_expiration, bg=COLORS["surface"], fg=COLORS["text"], buttonbackground=COLORS["surface_2"]).pack(fill="x", pady=(4, 8))
        tk.Label(left, text="Способ передачи", bg=COLORS["bg"], fg=COLORS["text"], font=FONTS["subtitle"]).pack(anchor="w")
        ttk.Combobox(left, textvariable=self.share_delivery, state="readonly", values=["qr", "file", "link"], width=28).pack(fill="x", pady=(4, 8))
        tk.Label(left, text="Базовый URL", bg=COLORS["bg"], fg=COLORS["muted"]).pack(anchor="w")
        tk.Entry(left, textvariable=self.share_link_base, bg=COLORS["surface"], fg=COLORS["text"], insertbackground=COLORS["text"]).pack(fill="x", pady=(4, 12))
        ttk.Button(left, text="Создать общий пакет", command=self._run_share).pack(fill="x")
        tk.Label(left, textvariable=self.share_status, bg=COLORS["bg"], fg=COLORS["muted"], justify="left", wraplength=280).pack(anchor="w", pady=(12, 0))

        tk.Label(right, text="История обмена", bg=COLORS["surface"], fg=COLORS["text"], font=FONTS["subtitle"]).pack(anchor="w", padx=12, pady=(10, 6))
        share_tree_wrap = tk.Frame(right, bg=COLORS["surface"])
        share_tree_wrap.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        share_tree_wrap.grid_rowconfigure(0, weight=1)
        share_tree_wrap.grid_columnconfigure(0, weight=1)
        self.share_history_tree = ttk.Treeview(share_tree_wrap, columns=("time", "entry", "recipient", "delivery", "status"), show="headings", height=10, style="Vault.Treeview")
        for col, title, width in [
            ("time", "Время", 160),
            ("entry", "Запись", 180),
            ("recipient", "Получатель", 180),
            ("delivery", "Передача", 100),
            ("status", "Статус", 120),
        ]:
            self.share_history_tree.heading(col, text=title)
            self.share_history_tree.column(col, width=width, anchor="w")
        self.share_history_tree.grid(row=0, column=0, sticky="nsew")
        share_tree_scroll = ttk.Scrollbar(share_tree_wrap, orient="vertical", style="Vertical.TScrollbar", command=self.share_history_tree.yview)
        share_tree_scroll.grid(row=0, column=1, sticky="ns")
        self.share_history_tree.configure(yscrollcommand=share_tree_scroll.set)
        share_text_wrap = tk.Frame(right, bg=COLORS["surface"])
        share_text_wrap.pack(fill="x", padx=12, pady=(0, 12))
        share_text_wrap.grid_rowconfigure(0, weight=1)
        share_text_wrap.grid_columnconfigure(0, weight=1)
        self.share_history_text = tk.Text(share_text_wrap, height=10, bg=COLORS["surface_2"], fg=COLORS["text"], insertbackground=COLORS["text"], wrap="word")
        self.share_history_text.grid(row=0, column=0, sticky="nsew")
        share_text_scroll = ttk.Scrollbar(share_text_wrap, orient="vertical", style="Vertical.TScrollbar", command=self.share_history_text.yview)
        share_text_scroll.grid(row=0, column=1, sticky="ns")
        self.share_history_text.configure(yscrollcommand=share_text_scroll.set)
        self.share_history_tree.bind("<<TreeviewSelect>>", self._show_share_history_item)

    def _update_export_description(self):
        self.export_desc.config(text=FORMAT_DESCRIPTIONS.get(self.export_format.get(), ""))
        if self.export_format.get() == "bitwarden_encrypted_json":
            self.export_encryption.set("password")
            self.export_compress.set(False)
        contacts = self.key_exchange.list_contacts()
        self.export_recipient_combo["values"] = sorted(contacts.keys())

    def _load_export_entries(self):
        self.export_tree.delete(*self.export_tree.get_children())
        self.selected_export_ids.clear()
        for entry in self.vault_service.get_all_entries():
            self.selected_export_ids.add(int(entry.id))
            self.export_tree.insert("", "end", iid=str(entry.id), values=("☑", entry.id, entry.title, entry.username, entry.url))

    def _load_share_entries(self):
        entries = self.vault_service.get_all_entries()
        share_values = [f"{entry.id} | {entry.title} | {entry.username}" for entry in entries]
        self.share_entry_combo["values"] = share_values
        contacts = sorted(self.key_exchange.list_contacts().keys())
        self.share_recipient_combo["values"] = contacts

    def _toggle_all_export_entries(self, selected: bool):
        self.selected_export_ids = {int(item) for item in self.export_tree.get_children()} if selected else set()
        for item in self.export_tree.get_children():
            values = list(self.export_tree.item(item, "values"))
            values[0] = "☑" if selected else "☐"
            self.export_tree.item(item, values=values)

    def _on_export_tree_click(self, event):
        item = self.export_tree.identify_row(event.y)
        column = self.export_tree.identify_column(event.x)
        if not item or column != "#1":
            return
        entry_id = int(item)
        values = list(self.export_tree.item(item, "values"))
        if entry_id in self.selected_export_ids:
            self.selected_export_ids.remove(entry_id)
            values[0] = "☐"
        else:
            self.selected_export_ids.add(entry_id)
            values[0] = "☑"
        self.export_tree.item(item, values=values)

    def _export_include_exclude(self):
        exclude = [] if self.export_include_notes.get() else ["notes"]
        return None, exclude

    def _select_query_matches(self):
        query = self.export_query.get().strip()
        entries = self.vault_service.find_entries(query) if query else self.vault_service.get_all_entries()
        matched_ids = {int(entry.id) for entry in entries}
        self.selected_export_ids = matched_ids
        for item in self.export_tree.get_children():
            values = list(self.export_tree.item(item, "values"))
            values[0] = "в‘" if int(item) in matched_ids else "вђ"
            self.export_tree.item(item, values=values)

    def _preview_export(self):
        include_fields, exclude_fields = self._export_include_exclude()
        rows = []
        for entry in self.vault_service.get_all_entries():
            if int(entry.id) in self.selected_export_ids:
                rows.append({
                    "id": entry.id,
                    "title": entry.title,
                    "username": entry.username,
                    "password": "[included]",
                    "url": entry.url,
                    "notes": entry.notes if self.export_include_notes.get() else "",
                    "category": entry.category,
                    "tags": entry.tags,
                })
        preview = {
            "format": self.export_format.get(),
            "entry_count": len(rows),
            "selected_ids": sorted(self.selected_export_ids),
            "encryption": self.export_encryption.get(),
            "strength": self.export_strength.get(),
            "compression": self.export_compress.get(),
            "exclude_fields": exclude_fields,
            "entries": rows[:20],
        }
        self.export_preview.delete("1.0", "end")
        self.export_preview.insert("1.0", json.dumps(preview, ensure_ascii=False, indent=2))

    def _run_export(self):
        if not self.selected_export_ids:
            messagebox.showwarning("Экспорт", "Выберите хотя бы одну запись.", parent=self)
            return
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".json")
        if not path:
            return
        include_fields, exclude_fields = self._export_include_exclude()
        kwargs = {
            "fmt": self.export_format.get(),
            "entry_ids": sorted(self.selected_export_ids),
            "include_fields": include_fields,
            "exclude_fields": exclude_fields,
            "key_bits": int(self.export_strength.get()),
            "compress": bool(self.export_compress.get()),
            "protection_mode": self.export_encryption.get(),
        }
        if self.export_encryption.get() == "master":
            if not self._confirm_master_password():
                return
            kwargs["confirmation_password"] = self._last_master_password
        elif self.export_encryption.get() == "password":
            if not self.export_password.get().strip():
                messagebox.showwarning("Экспорт", "Задайте пароль экспорта.", parent=self)
                return
            kwargs["export_password"] = self.export_password.get().strip()
        else:
            contacts = self.key_exchange.list_contacts()
            contact = contacts.get(self.export_public_recipient.get().strip())
            if not contact:
                messagebox.showwarning("Экспорт", "Выберите контакт получателя.", parent=self)
                return
            kwargs["recipient_public_key"] = bytes.fromhex(contact["public_key"])

        payload = self.exporter.export_vault(**kwargs)
        Path(path).write_bytes(payload)
        checksum = hashlib.sha256(payload).hexdigest()
        self.db.record_import_export_history(
            operation_type="export",
            format=self.export_format.get(),
            encryption_used=self.export_encryption.get(),
            entry_count=len(self.selected_export_ids),
            file_size=len(payload),
            checksum=checksum,
            verification_status="generated",
        )
        self.export_preview.delete("1.0", "end")
        self.export_preview.insert("1.0", f"Экспорт сохранён: {path}\nБайт: {len(payload)}")

    def _choose_import_file(self):
        path = filedialog.askopenfilename(parent=self)
        if not path:
            return
        self.current_import_path = path
        detected = self._detect_import_format(path)
        self.current_import_format = detected
        self.import_detected_format.set(f"Обнаружен формат: {detected}\nФайл: {Path(path).name}")

    def _detect_import_format(self, path: str) -> str:
        raw = Path(path).read_bytes()
        mapping = {
            "encrypted_json": "Зашифрованный JSON",
            "json": "JSON",
            "csv": "CSV",
            "bitwarden_json": "Bitwarden JSON (отключен)",
            "bitwarden_encrypted_json": "Bitwarden зашифрованный JSON",
            "lastpass_csv": "LastPass CSV",
        }
        return mapping.get(self.importer.detect_format(raw), "Неизвестно")

    def _preview_import(self):
        if not self.current_import_path:
            return
        if self.current_import_format == "Bitwarden JSON (отключен)":
            messagebox.showwarning("Импорт", "Обычный Bitwarden JSON отключён.", parent=self)
            return
        raw = Path(self.current_import_path).read_bytes()
        result = self.importer.import_package(
            raw,
            import_password=self.import_password.get().strip() or None,
            mode="dry-run",
            duplicate_handling=self.import_conflicts.get(),
            format_hint=self._canonical_import_format(),
        )
        self.import_preview_result = result
        preview = {
            "mode": self.import_mode.get(),
            "duplicates": result.duplicates,
            "preview_entries": result.preview_entries[:30],
        }
        self.import_preview.delete("1.0", "end")
        self.import_preview.insert("1.0", json.dumps(preview, ensure_ascii=False, indent=2))
        self.import_summary.set(
            f"Записей в предпросмотре: {len(result.preview_entries)}\nДубликатов: {len(result.duplicates)}\nРежим конфликтов: {self.import_conflicts.get()}"
        )

    def _run_import(self):
        if not self.current_import_path:
            return
        if self.current_import_format == "Bitwarden JSON (отключен)":
            messagebox.showwarning("Импорт", "Обычный Bitwarden JSON отключён.", parent=self)
            return
        raw = Path(self.current_import_path).read_bytes()
        result = self.importer.import_package(
            raw,
            import_password=self.import_password.get().strip() or None,
            mode=self.import_mode.get(),
            duplicate_handling=self.import_conflicts.get(),
            format_hint=self._canonical_import_format(),
        )
        checksum = hashlib.sha256(raw).hexdigest()
        self.db.record_import_export_history(
            operation_type="import",
            format=self._canonical_import_format() or "auto",
            encryption_used="encrypted_json" if self._canonical_import_format() == "encrypted_json" else "plaintext_or_external",
            entry_count=len(result.imported_ids) + len(result.updated_ids),
            file_size=len(raw),
            checksum=checksum,
            verification_status="imported",
        )
        if self.event_bus is not None:
            self.event_bus.publish(
                VaultDataImported(
                    format=self._canonical_import_format() or "auto",
                    entry_count=len(result.preview_entries),
                    imported_count=len(result.imported_ids),
                    updated_count=len(result.updated_ids),
                    mode=self.import_mode.get(),
                )
            )
        self.import_summary.set(
            f"Импортировано: {len(result.imported_ids)}\nОбновлено: {len(result.updated_ids)}\nПропущено: {result.skipped_duplicates}"
        )
        self.import_preview.delete("1.0", "end")
        self.import_preview.insert("1.0", json.dumps({
            "imported_ids": result.imported_ids,
            "updated_ids": result.updated_ids,
            "skipped_duplicates": result.skipped_duplicates,
        }, ensure_ascii=False, indent=2))

    def _run_share(self):
        entry_value = self.share_entry_id.get().strip()
        if not entry_value:
            return
        entry_id = int(entry_value.split("|", 1)[0].strip())
        recipient = self.share_recipient.get().strip()
        if not recipient:
            messagebox.showwarning("Обмен", "Нужно указать получателя.", parent=self)
            return
        expires = int(self.share_expiration.get())
        method = self.share_method.get()
        delivery = self.share_delivery.get()

        if method == "password":
            if not self.share_password.get().strip():
                messagebox.showwarning("Обмен", "Для обмена по паролю укажите пароль.", parent=self)
                return
            package = self.sharing.share_entry_with_password(
                entry_id,
                export_password=self.share_password.get().strip(),
                sharer="local",
                recipient=recipient,
                expires_in_days=expires,
                permission=self.share_permission.get(),
            )
        else:
            contact = self.key_exchange.list_contacts().get(recipient)
            if not contact:
                messagebox.showwarning("Обмен", "Контакт получателя не найден.", parent=self)
                return
            package = self.sharing.share_entry_with_public_key(
                entry_id,
                bytes.fromhex(contact["public_key"]),
                sharer="local",
                recipient=recipient,
                expires_in_days=expires,
                permission=self.share_permission.get(),
            )

        status = "generated"
        detail_text = package.decode("utf-8", errors="replace")
        if delivery == "file":
            path = filedialog.asksaveasfilename(parent=self, defaultextension=".share.json")
            if path:
                Path(path).write_bytes(package)
                status = f"saved: {Path(path).name}"
        elif delivery == "link":
            link = self.sharing.generate_share_link(package, self.share_link_base.get().strip(), expires)
            detail_text = link
            self._copy_share_link(link)
            status = "link copied"
        else:
            viewer = QrExchangeWindow(
                self,
                db=self.db,
                vault_service=self.vault_service,
                key_manager=self.key_manager,
                initial_payload_type="encrypted_entry",
                initial_payload=package,
            )
            viewer.focus_set()
            status = "qr shown"
        if delivery == "link" and self.event_bus is not None:
            self.event_bus.publish(NetworkShareRequested(protocol="share_link", recipient=recipient))

        self.share_status.set(f"Передача: {delivery}\nПолучатель: {recipient}\nСтатус: {status}")
        self.share_history_text.delete("1.0", "end")
        self.share_history_text.insert("1.0", detail_text[:8000])
        shared_at = self._utc_now()
        expires_at = self._utc_plus_days(expires)
        permissions = json.dumps(
            {
                "permission": self.share_permission.get(),
                "delivery": delivery,
                "status": status,
            },
            ensure_ascii=False,
        )
        self.db.record_shared_entry(
            shared_id=hashlib.sha256(f"{entry_id}:{recipient}:{shared_at}".encode("utf-8")).hexdigest()[:24],
            original_entry_id=entry_id,
            encryption_method=method,
            recipient_info=recipient,
            permissions=permissions,
            shared_at=shared_at,
            expires_at=expires_at,
        )
        if self.event_bus is not None:
            self.event_bus.publish(
                EntryShared(
                    entry_id=entry_id,
                    recipient=recipient,
                    method=method,
                    delivery=delivery,
                    permission=self.share_permission.get(),
                    expires_in_days=expires,
                )
            )
        self._load_share_history()

    def _load_share_history(self):
        self.share_history_tree.delete(*self.share_history_tree.get_children())
        with self.db.connection() as conn:
            items = conn.execute(
                """
                SELECT shared_id, original_entry_id, recipient_info, permissions, shared_at, expires_at
                FROM shared_entries
                ORDER BY shared_at DESC
                LIMIT 100
                """
            ).fetchall()
        for index, item in enumerate(items, start=1):
            iid = str(index)
            permissions = json.loads(item["permissions"])
            payload = {
                "shared_id": item["shared_id"],
                "entry": item["original_entry_id"],
                "recipient": item["recipient_info"],
                "delivery": permissions.get("delivery"),
                "status": permissions.get("status"),
                "permission": permissions.get("permission"),
                "shared_at": item["shared_at"],
                "expires_at": item["expires_at"],
            }
            self.share_history_tree.insert("", "end", iid=iid, values=(payload["shared_at"], payload["entry"], payload["recipient"], payload["delivery"], payload["status"]))
            self.share_history_tree.item(iid, tags=(json.dumps(payload, ensure_ascii=False),))

    def _show_share_history_item(self, _event=None):
        selected = self.share_history_tree.selection()
        if not selected:
            return
        item = self.share_history_tree.item(selected[0])
        if not item["tags"]:
            return
        payload = json.loads(item["tags"][0])
        self.share_history_text.delete("1.0", "end")
        self.share_history_text.insert("1.0", json.dumps(payload, ensure_ascii=False, indent=2))

    def _confirm_master_password(self) -> bool:
        self._last_master_password = None
        auth_service = getattr(self.master, "auth_service", None)
        if auth_service is None or not auth_service.is_unlocked():
            return False
        dialog = LoginDialog(self, auth_service)
        dialog.title("Подтверждение экспорта")
        self.wait_window(dialog)
        if not getattr(dialog, "result", False):
            return False
        self._last_master_password = getattr(dialog, "entered_password", None) or getattr(dialog, "password", None)
        if self._last_master_password:
            return True
        return bool(self._last_master_password)

    def _canonical_import_format(self) -> str | None:
        mapping = {
            "Зашифрованный JSON": "encrypted_json",
            "JSON": "json",
            "CSV": "csv",
            "Bitwarden зашифрованный JSON": "bitwarden_encrypted_json",
            "LastPass CSV": "lastpass_csv",
        }
        return mapping.get(self.current_import_format or "")

    def _copy_share_link(self, link: str) -> None:
        clipboard_service = getattr(self.master, "clipboard_service", None)
        if clipboard_service is not None:
            clipboard_service.copy_text(link)
            return
        self.clipboard_clear()
        self.clipboard_append(link)

    def _bind_mousewheel_to_canvas(self, canvas: tk.Canvas):
        self._mw_bind_ids = []

        def _on_mousewheel(event):
            if not canvas.winfo_exists():
                return "break"
            delta = 0
            if hasattr(event, "delta") and event.delta:
                delta = int(-event.delta / 120) if event.delta % 120 == 0 else (-1 if event.delta > 0 else 1)
            elif getattr(event, "num", None) == 4:
                delta = -1
            elif getattr(event, "num", None) == 5:
                delta = 1
            if delta:
                try:
                    canvas.yview_scroll(delta, "units")
                except tk.TclError:
                    return "break"
                return "break"
            return None

        self._mw_bind_ids.append(("<MouseWheel>", self.bind("<MouseWheel>", _on_mousewheel, add="+")))
        self._mw_bind_ids.append(("<Button-4>", self.bind("<Button-4>", _on_mousewheel, add="+")))
        self._mw_bind_ids.append(("<Button-5>", self.bind("<Button-5>", _on_mousewheel, add="+")))

    def destroy(self):
        if hasattr(self, "_mw_bind_ids"):
            for sequence, func_id in self._mw_bind_ids:
                try:
                    self.unbind(sequence, func_id)
                except Exception:
                    pass
            self._mw_bind_ids = []
        super().destroy()

    @staticmethod
    def _utc_now() -> str:
        from datetime import datetime, timezone

        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    @staticmethod
    def _utc_plus_days(days: int) -> str:
        from datetime import datetime, timedelta, timezone

        return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec="seconds")
