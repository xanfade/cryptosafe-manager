from __future__ import annotations

import json
import hashlib
import tkinter as tk
from datetime import datetime, timedelta, timezone
from tkinter import filedialog, messagebox, ttk

from src.core.audit.audit_exporter import AuditExportManager
from src.gui.login_dialog import LoginDialog


class AuditLogViewer(tk.Toplevel):
    PAGE_SIZE = 50

    def __init__(self, master=None, db=None, signer=None):
        super().__init__(master)
        if not self._ensure_access(parent=master):
            messagebox.showerror("Доступ запрещён", "Сначала разблокируй хранилище.", parent=master)
            self.destroy()
            return

        self.db = db or getattr(master, "db", None)
        self.signer = signer
        self.export_manager = AuditExportManager(
            self.db,
            key_manager=getattr(master, "key_manager", None),
            event_bus=getattr(master, "event_bus", None),
        )
        self.page = 0
        self.rows = []

        self.title("Журнал аудита")
        self.geometry("1100x700")
        self.minsize(900, 560)
        self.configure(bg="#120d18")
        self.bg = "#120d18"
        self.surface = "#1b1524"
        self.surface_2 = "#251d31"
        self.border = "#3a2d4f"
        self.text = "#f7f2ff"
        self.muted = "#c4b5fd"
        self.purple = "#7c3aed"
        self.purple_hover = "#8b5cf6"

        self.event_type_var = tk.StringVar()
        self.severity_var = tk.StringVar()
        self.user_var = tk.StringVar()
        self.date_from_var = tk.StringVar()
        self.date_to_var = tk.StringVar()
        self.search_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Целостность: не проверялась")
        self.stats_window_var = tk.StringVar(value="30")
        self.last_verification_report = None

        self._build()
        self.refresh()
        self.refresh_stats()

    def _build(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Audit.Treeview", background="#1d1428", fieldbackground="#1d1428", foreground="#f7f2ff", rowheight=32)
        style.configure("Audit.Treeview.Heading", background="#2b1b3d", foreground="#cdb8ff")
        style.map("Audit.Treeview", background=[("selected", "#7c3aed")], foreground=[("selected", "#ffffff")])
        style.configure("TCombobox", fieldbackground=self.surface_2, background=self.surface_2, foreground=self.text)
        style.map("TCombobox", fieldbackground=[("readonly", self.surface_2)], foreground=[("readonly", self.text)])
        style.configure("Audit.Vertical.TScrollbar", background=self.purple, troughcolor=self.surface, bordercolor=self.surface, arrowcolor=self.text, relief="flat")
        style.map("Audit.Vertical.TScrollbar", background=[("active", self.purple_hover)])

        canvas = tk.Canvas(self, bg=self.bg, highlightthickness=0, bd=0)
        canvas.pack(side="left", fill="both", expand=True)
        outer_scroll = ttk.Scrollbar(self, orient="vertical", style="Audit.Vertical.TScrollbar", command=canvas.yview)
        outer_scroll.pack(side="right", fill="y")
        canvas.configure(yscrollcommand=outer_scroll.set)

        root = tk.Frame(canvas, bg=self.bg)
        canvas_window = canvas.create_window((0, 0), window=root, anchor="nw")
        root.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(canvas_window, width=event.width))

        toolbar = tk.Frame(root, bg=self.bg)
        toolbar.pack(fill="x", padx=10, pady=(10, 6))
        for i in range(10):
            toolbar.grid_columnconfigure(i, weight=1 if i in {1, 3, 5, 7} else 0)

        tk.Label(toolbar, text="Событие", bg=self.bg, fg=self.muted, font=("Arial", 10)).grid(row=0, column=0, sticky="w", padx=(0, 6))
        tk.Entry(toolbar, textvariable=self.event_type_var, width=16, bg=self.surface_2, fg=self.text, insertbackground=self.text, relief="flat").grid(row=0, column=1, sticky="ew", padx=(0, 10), ipady=6)

        tk.Label(toolbar, text="Уровень", bg=self.bg, fg=self.muted, font=("Arial", 10)).grid(row=0, column=2, sticky="w", padx=(0, 6))
        severity = ttk.Combobox(
            toolbar,
            textvariable=self.severity_var,
            values=["", "INFO", "WARN", "ERROR", "CRITICAL"],
            width=12,
            state="readonly",
        )
        severity.grid(row=0, column=3, sticky="ew", padx=(0, 10))

        tk.Label(toolbar, text="Пользователь", bg=self.bg, fg=self.muted, font=("Arial", 10)).grid(row=0, column=4, sticky="w", padx=(0, 6))
        tk.Entry(toolbar, textvariable=self.user_var, width=12, bg=self.surface_2, fg=self.text, insertbackground=self.text, relief="flat").grid(row=0, column=5, sticky="ew", padx=(0, 10), ipady=6)

        tk.Label(toolbar, text="Поиск", bg=self.bg, fg=self.muted, font=("Arial", 10)).grid(row=0, column=6, sticky="w", padx=(0, 6))
        tk.Entry(toolbar, textvariable=self.search_var, width=18, bg=self.surface_2, fg=self.text, insertbackground=self.text, relief="flat").grid(row=0, column=7, sticky="ew", padx=(0, 10), ipady=6)

        actions = tk.Frame(root, bg=self.bg)
        actions.pack(fill="x", padx=10, pady=(0, 8))
        for i in range(11):
            actions.grid_columnconfigure(i, weight=1 if i in {1, 3, 5, 7, 9} else 0)

        tk.Label(actions, text="С", bg=self.bg, fg=self.muted, font=("Arial", 10)).grid(row=0, column=0, sticky="w", padx=(0, 6))
        tk.Entry(actions, textvariable=self.date_from_var, width=14, bg=self.surface_2, fg=self.text, insertbackground=self.text, relief="flat").grid(row=0, column=1, sticky="ew", padx=(0, 10), ipady=6)
        tk.Label(actions, text="По", bg=self.bg, fg=self.muted, font=("Arial", 10)).grid(row=0, column=2, sticky="w", padx=(0, 6))
        tk.Entry(actions, textvariable=self.date_to_var, width=14, bg=self.surface_2, fg=self.text, insertbackground=self.text, relief="flat").grid(row=0, column=3, sticky="ew", padx=(0, 10), ipady=6)
        tk.Label(actions, text="Статистика", bg=self.bg, fg=self.muted, font=("Arial", 10)).grid(row=0, column=4, sticky="w", padx=(0, 6))
        ttk.Combobox(
            actions,
            textvariable=self.stats_window_var,
            values=["7", "30", "90"],
            width=5,
            state="readonly",
        ).grid(row=0, column=5, sticky="w", padx=(0, 10))

        self._make_action_button(actions, "Применить", self.refresh).grid(row=0, column=6, sticky="ew", padx=(0, 8))
        self._make_action_button(actions, "Проверить", self.verify).grid(row=0, column=7, sticky="ew", padx=(0, 8))
        self._make_action_button(actions, "Экспорт отчёта", self.export_verification_report).grid(row=0, column=8, sticky="ew", padx=(0, 8))
        self._make_action_button(actions, "JSON", lambda: self.export("json")).grid(row=0, column=9, sticky="ew", padx=(0, 8))
        self._make_action_button(actions, "CSV", lambda: self.export("csv")).grid(row=0, column=10, sticky="ew")

        stats_frame = tk.Frame(root, bg=self.surface, highlightthickness=1, highlightbackground=self.border)
        stats_frame.pack(fill="x", padx=8, pady=(0, 8))
        stats_header = tk.Frame(stats_frame, bg=self.surface)
        stats_header.pack(fill="x", padx=10, pady=(8, 0))
        tk.Label(stats_header, text="Сводка", bg=self.surface, fg=self.text, font=("Arial", 11, "bold")).pack(side="left")
        self._make_action_button(stats_header, "Обновить", self.refresh_stats).pack(side="right")
        self.stats_label = tk.Label(stats_frame, text="Загрузка статистики", bg=self.surface, fg=self.muted, font=("Arial", 10))
        self.stats_label.pack(side="left", padx=(10, 14), pady=(8, 8))
        self.stats_canvas = tk.Canvas(stats_frame, width=420, height=46, highlightthickness=0, bg="#1d1428")
        self.stats_canvas.pack(side="left", fill="x", expand=True, padx=(0, 10), pady=(8, 6))

        middle = tk.Frame(root, bg=self.bg)
        middle.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        middle.grid_rowconfigure(0, weight=2)
        middle.grid_rowconfigure(1, weight=3)
        middle.grid_columnconfigure(0, weight=1)

        table_frame = tk.Frame(middle, bg=self.surface, highlightthickness=1, highlightbackground=self.border)
        table_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 8))

        columns = ("seq", "timestamp", "event_type", "severity", "user_id", "source", "entry_id")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=16, style="Audit.Treeview")
        for col, label, width in [
            ("seq", "#", 70),
            ("timestamp", "Время", 180),
            ("event_type", "Событие", 220),
            ("severity", "Уровень", 90),
            ("user_id", "Пользователь", 100),
            ("source", "Источник", 120),
            ("entry_id", "Запись", 90),
        ]:
            self.tree.heading(col, text=label, command=lambda c=col: self.sort_by(c))
            self.tree.column(col, width=width, anchor="w")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", style="Audit.Vertical.TScrollbar", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)
        scrollbar.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.show_selected_details)
        self.tree.bind("<Double-1>", self.open_context_target)
        self.tree.bind("<Button-3>", self.show_context_menu)

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Подсветить запись в хранилище", command=self.highlight_vault_entry)
        self.context_menu.add_command(label="Показать детали события", command=self.show_selected_details)
        self.context_menu.add_command(label="Копировать номер записи", command=self.copy_selected_sequence)

        details_frame = tk.Frame(middle, bg=self.surface, highlightthickness=1, highlightbackground=self.border)
        details_frame.grid(row=1, column=0, sticky="nsew")
        details_frame.grid_rowconfigure(1, weight=1)
        details_frame.grid_columnconfigure(0, weight=1)

        tk.Label(details_frame, textvariable=self.status_var, bg=self.surface, fg=self.muted, font=("Arial", 10)).pack(anchor="w", padx=10, pady=(8, 6))
        details_body = tk.Frame(details_frame, bg=self.surface)
        details_body.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        details_body.grid_rowconfigure(0, weight=1)
        details_body.grid_columnconfigure(0, weight=1)
        self.details = tk.Text(details_body, height=10, wrap="word", bg=self.surface_2, fg=self.text, insertbackground=self.text, relief="flat")
        self.details.grid(row=0, column=0, sticky="nsew")
        details_scroll = ttk.Scrollbar(details_body, orient="vertical", style="Audit.Vertical.TScrollbar", command=self.details.yview)
        details_scroll.grid(row=0, column=1, sticky="ns")
        self.details.configure(yscrollcommand=details_scroll.set)

        bottom = tk.Frame(root, bg=self.bg)
        bottom.pack(fill="x", padx=8, pady=(0, 8))
        self._make_action_button(bottom, "Назад", self.previous_page).pack(side="left")
        self.page_label = tk.Label(bottom, text="Страница 1", bg=self.bg, fg=self.muted, font=("Arial", 10))
        self.page_label.pack(side="left", padx=10)
        self._make_action_button(bottom, "Вперёд", self.next_page).pack(side="left")
        self._make_action_button(bottom, "PDF", lambda: self.export("pdf")).pack(side="right")
        self._make_action_button(bottom, "Закрыть", self.destroy).pack(side="right", padx=(0, 8))

    def _make_action_button(self, parent, text, command):
        button = tk.Label(
            parent,
            text=text,
            bg=self.surface_2,
            fg=self.text,
            font=("Arial", 10, "bold"),
            padx=12,
            pady=7,
            cursor="hand2",
        )
        button.bind("<Button-1>", lambda _event: command())
        button.bind("<Enter>", lambda _event: button.configure(bg=self.purple_hover))
        button.bind("<Leave>", lambda _event: button.configure(bg=self.surface_2))
        return button

    def _query(self, limit: int | None = None, offset: int = 0):
        if not self._ensure_access():
            return []
        if self.db is None:
            return []

        where = []
        params = []
        if self.event_type_var.get().strip():
            where.append("event_type LIKE ?")
            params.append(f"%{self.event_type_var.get().strip()}%")
        if self.severity_var.get().strip():
            where.append("severity = ?")
            params.append(self.severity_var.get().strip())
        if self.user_var.get().strip():
            where.append("user_id LIKE ?")
            params.append(f"%{self.user_var.get().strip()}%")
        if self.date_from_var.get().strip():
            where.append("timestamp >= ?")
            params.append(self._normalize_date_filter(self.date_from_var.get().strip(), end=False))
        if self.date_to_var.get().strip():
            where.append("timestamp <= ?")
            params.append(self._normalize_date_filter(self.date_to_var.get().strip(), end=True))
        if self.search_var.get().strip():
            where.append("(event_type LIKE ? OR source LIKE ? OR CAST(entry_data AS TEXT) LIKE ?)")
            term = f"%{self.search_var.get().strip()}%"
            params.extend([term, term, term])

        sql = "SELECT * FROM audit_log"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY sequence_number DESC"
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])

        with self.db.connection() as conn:
            return conn.execute(sql, params).fetchall()

    def refresh(self) -> None:
        self.rows = self._query(self.PAGE_SIZE, self.page * self.PAGE_SIZE)
        self.tree.delete(*self.tree.get_children())
        for row in self.rows:
            self.tree.insert(
                "",
                "end",
                iid=str(row["sequence_number"]),
                values=(
                    row["sequence_number"],
                    row["timestamp"],
                    row["event_type"],
                    row["severity"],
                    row["user_id"],
                    row["source"],
                    row["entry_id"] if row["entry_id"] is not None else "",
                ),
            )
        self.page_label.config(text=f"Страница {self.page + 1}")
        self.refresh_stats()

    def sort_by(self, column: str) -> None:
        items = list(self.tree.get_children(""))
        index = list(self.tree["columns"]).index(column)
        items.sort(key=lambda item: self.tree.item(item, "values")[index])
        for pos, item in enumerate(items):
            self.tree.move(item, "", pos)

    def show_selected_details(self, _event=None) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        seq = int(selected[0])
        row = next((item for item in self.rows if int(item["sequence_number"]) == seq), None)
        if row is None:
            return

        try:
            entry = json.loads(bytes(row["entry_data"]).decode("utf-8"))
        except Exception:
            entry = {"raw": str(row["entry_data"])}

        payload = {
            "verification": {
                "entry_hash": row["entry_hash"],
                "previous_hash": row["previous_hash"],
                "signature_algorithm": row["signature_algorithm"],
                "signature": row["signature"],
                "status": self.verify_row(row),
                "hash_chain": self.hash_chain_view(row),
            },
            "entry": entry,
        }
        self.details.delete("1.0", "end")
        self.details.insert("1.0", json.dumps(payload, indent=2, ensure_ascii=False))

    def verify(self) -> None:
        if not self._ensure_access():
            return
        if self.signer is None:
            self.status_var.set("Целостность: проверка подписи недоступна в этом окне")
            return

        result = self.master.audit_logger.verify_integrity() if hasattr(self.master, "audit_logger") else None
        if result is None:
            from src.core.audit.log_verifier import AuditLogVerifier

            result = AuditLogVerifier(self.db, self.signer).verify_range().to_dict()
        status = "валидно" if result["verified"] else "обнаружено изменение"
        self.last_verification_report = {
            "metadata": {
                "report_type": "cryptosafe.audit.verification.v1",
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "scope": "full",
            },
            "result": result,
        }
        self.status_var.set(
            f"Целостность: {status}, валидных записей {result['valid_entries']}/{result['total_entries']}"
        )
        self.details.delete("1.0", "end")
        self.details.insert("1.0", json.dumps(self.last_verification_report, indent=2, ensure_ascii=False))
        if not result["verified"]:
            if hasattr(self.master, "audit_logger"):
                self.master.audit_logger.handle_verification_result(
                    result,
                    source="manual",
                )
            messagebox.showwarning("Целостность аудита", "Проверка целостности журнала аудита не пройдена.", parent=self)

    def export_verification_report(self) -> None:
        if not self._ensure_access():
            return
        if not self.confirm_export_password():
            return

        if self.last_verification_report is None:
            self.verify()
            if self.last_verification_report is None:
                return

        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
        )
        if not path:
            return

        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self.last_verification_report, handle, indent=2, ensure_ascii=False)
        self.log_export_operation("verification_report", 1, False)

    def verify_row(self, row) -> dict:
        entry_data = bytes(row["entry_data"])
        computed_hash = hashlib.sha256(entry_data).hexdigest()
        signature_valid = False
        if self.signer is not None:
            try:
                signature_valid = self.signer.verify(entry_data, bytes.fromhex(row["signature"]))
            except Exception:
                signature_valid = False

        previous_status = "genesis_or_archive_boundary"
        with self.db.connection() as conn:
            previous = conn.execute(
                """
                SELECT entry_hash
                FROM audit_log
                WHERE sequence_number < ?
                ORDER BY sequence_number DESC
                LIMIT 1
                """,
                (row["sequence_number"],),
            ).fetchone()
        if previous is not None:
            previous_status = "linked" if row["previous_hash"] == previous["entry_hash"] else "broken"

        return {
            "signature_valid": signature_valid,
            "hash_valid": computed_hash == row["entry_hash"],
            "chain_status": previous_status,
        }

    def hash_chain_view(self, row) -> dict:
        return {
            "previous": f"{row['previous_hash'][:12]}...",
            "current": f"{row['entry_hash'][:12]}...",
            "visual": f"{row['previous_hash'][:12]} -> {row['entry_hash'][:12]}",
        }

    def refresh_stats(self) -> None:
        if self.db is None or not hasattr(self, "stats_label"):
            return

        try:
            days = int(self.stats_window_var.get() or "30")
        except ValueError:
            days = 30
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")

        with self.db.connection() as conn:
            total = conn.execute("SELECT COUNT(*) AS count FROM audit_log").fetchone()["count"]
            failed = conn.execute(
                "SELECT COUNT(*) AS count FROM audit_log WHERE event_type = 'AUTH_LOGIN_FAILURE' AND timestamp >= ?",
                (cutoff,),
            ).fetchone()["count"]
            suspicious = conn.execute(
                "SELECT COUNT(*) AS count FROM audit_log WHERE event_type LIKE 'SECURITY_%' AND timestamp >= ?",
                (cutoff,),
            ).fetchone()["count"]
            rows = conn.execute(
                """
                SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS count
                FROM audit_log
                WHERE timestamp >= ?
                GROUP BY substr(timestamp, 1, 10)
                ORDER BY day
                """,
                (cutoff,),
            ).fetchall()

        integrity = getattr(self.master, "audit_integrity_status", "not checked")
        self.stats_label.config(
            text=f"Всего: {total} | Неудачных входов: {failed} | Событий безопасности: {suspicious} | Целостность: {integrity}"
        )
        self._draw_frequency_graph(rows)

    def _draw_frequency_graph(self, rows) -> None:
        canvas = self.stats_canvas
        canvas.delete("all")
        width = max(int(canvas.winfo_width() or 420), 120)
        height = 54
        counts = [int(row["count"]) for row in rows] or [0]
        max_count = max(max(counts), 1)
        bar_count = max(len(counts), 1)
        bar_width = max(4, width // bar_count)
        for index, count in enumerate(counts):
            x0 = index * bar_width
            x1 = min(x0 + bar_width - 2, width)
            y0 = height - int((count / max_count) * (height - 8))
            canvas.create_rectangle(x0, y0, x1, height, fill="#4f46e5", outline="")

    def show_context_menu(self, event) -> None:
        item_id = self.tree.identify_row(event.y)
        if item_id:
            self.tree.selection_set(item_id)
            self.tree.focus(item_id)
            self.context_menu.tk_popup(event.x_root, event.y_root)

    def selected_row(self):
        selected = self.tree.selection()
        if not selected:
            return None
        seq = int(selected[0])
        return next((item for item in self.rows if int(item["sequence_number"]) == seq), None)

    def open_context_target(self, _event=None) -> None:
        row = self.selected_row()
        if row is None:
            return
        if row["entry_id"] is not None and str(row["event_type"]).startswith("VAULT_"):
            self.highlight_vault_entry()
            return
        if row["event_type"] == "AUTH_LOGIN_FAILURE":
            self.show_failed_login_details(row)

    def highlight_vault_entry(self) -> None:
        row = self.selected_row()
        if row is None or row["entry_id"] is None:
            return
        if hasattr(self.master, "_select_table_entry"):
            self.master._select_table_entry(int(row["entry_id"]))
            if hasattr(self.master, "set_status"):
                self.master.set_status(f"Подсвечена запись хранилища {row['entry_id']}")

    def show_failed_login_details(self, row) -> None:
        try:
            entry = json.loads(bytes(row["entry_data"]).decode("utf-8"))
            details = entry.get("details", {})
        except Exception:
            details = {}
        ip = details.get("ip_address", "unknown")
        messagebox.showinfo(
            "Неудачный вход",
            f"Время: {row['timestamp']}\nПользователь: {row['user_id']}\nIP: {ip}",
            parent=self,
        )

    def copy_selected_sequence(self) -> None:
        row = self.selected_row()
        if row is None:
            return
        self.clipboard_clear()
        self.clipboard_append(str(row["sequence_number"]))

    @staticmethod
    def _normalize_date_filter(value: str, end: bool) -> str:
        if "T" in value:
            return value
        suffix = "T23:59:59+00:00" if end else "T00:00:00+00:00"
        return value + suffix

    def export(self, kind: str) -> None:
        if not self._ensure_access():
            return
        if not self.confirm_export_password():
            return

        rows = self._query()
        public_key = self.export_manager._public_key()
        date_range = {
            "from": self.date_from_var.get().strip() or None,
            "to": self.date_to_var.get().strip() or None,
        }
        if kind == "json":
            path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
            if not path:
                return
            payload, encrypted = self.export_manager.build_export(
                rows,
                "json",
                public_key,
                exporter="local",
                date_range=date_range,
            )
            if encrypted and not path.endswith(".enc"):
                path += ".enc"
            with open(path, "wb") as handle:
                handle.write(payload)
        elif kind == "csv":
            path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
            if not path:
                return
            payload, encrypted = self.export_manager.build_export(
                rows,
                "csv",
                public_key,
                exporter="local",
                date_range=date_range,
            )
            if encrypted and not path.endswith(".enc"):
                path += ".enc"
            with open(path, "wb") as handle:
                handle.write(payload)
        else:
            path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
            if not path:
                return
            payload, encrypted = self.export_manager.build_export(
                rows,
                "pdf",
                public_key,
                exporter="local",
                date_range=date_range,
            )
            if encrypted and not path.endswith(".enc"):
                path += ".enc"
            with open(path, "wb") as handle:
                handle.write(payload)
        self.log_export_operation(kind, len(rows), encrypted)

    def confirm_export_password(self) -> bool:
        auth_service = getattr(self.master, "auth_service", None)
        if auth_service is None or not auth_service.is_unlocked():
            messagebox.showerror("Экспорт заблокирован", "Подтверждение мастер-пароля недоступно.", parent=self)
            return False

        dialog = LoginDialog(self, auth_service)
        dialog.title("Подтверждение экспорта")
        self.wait_window(dialog)
        return bool(getattr(dialog, "result", False))

    def log_export_operation(self, kind: str, count: int, encrypted: bool) -> None:
        audit_logger = getattr(self.master, "audit_logger", None)
        if audit_logger is None:
            return
        audit_logger.log_event(
            "AUDIT_LOG_EXPORTED",
            "INFO",
            "audit_export",
            {
                "format": kind,
                "entry_count": count,
                "encrypted": encrypted,
                "range": {
                    "from": self.date_from_var.get().strip() or None,
                    "to": self.date_to_var.get().strip() or None,
                },
            },
            user_id="local",
        )

    def _ensure_access(self, parent=None) -> bool:
        auth_service = getattr(self.master, "auth_service", None) if self.master is not None else None
        if auth_service is None:
            return False
        try:
            return bool(auth_service.is_unlocked())
        except Exception:
            return False

    def previous_page(self) -> None:
        if self.page > 0:
            self.page -= 1
            self.refresh()

    def next_page(self) -> None:
        if len(self.rows) == self.PAGE_SIZE:
            self.page += 1
            self.refresh()
