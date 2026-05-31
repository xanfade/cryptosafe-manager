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
        style.configure("Audit.Treeview", background="#1d1428", fieldbackground="#1d1428", foreground="#f7f2ff", rowheight=34)
        style.configure("Audit.Treeview.Heading", background="#2b1b3d", foreground="#cdb8ff")
        style.map("Audit.Treeview", background=[("selected", "#7c3aed")], foreground=[("selected", "#ffffff")])
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")

        ttk.Label(top, text="Event").pack(side="left")
        ttk.Entry(top, textvariable=self.event_type_var, width=18).pack(side="left", padx=(4, 10))

        ttk.Label(top, text="Severity").pack(side="left")
        severity = ttk.Combobox(
            top,
            textvariable=self.severity_var,
            values=["", "INFO", "WARN", "ERROR", "CRITICAL"],
            width=12,
            state="readonly",
        )
        severity.pack(side="left", padx=(4, 10))

        ttk.Label(top, text="User").pack(side="left")
        ttk.Entry(top, textvariable=self.user_var, width=12).pack(side="left", padx=(4, 10))

        ttk.Label(top, text="Search").pack(side="left")
        ttk.Entry(top, textvariable=self.search_var, width=20).pack(side="left", padx=(4, 10))

        filters = ttk.Frame(self, padding=(8, 0, 8, 8))
        filters.pack(fill="x")
        ttk.Label(filters, text="From").pack(side="left")
        ttk.Entry(filters, textvariable=self.date_from_var, width=18).pack(side="left", padx=(4, 10))
        ttk.Label(filters, text="To").pack(side="left")
        ttk.Entry(filters, textvariable=self.date_to_var, width=18).pack(side="left", padx=(4, 10))
        ttk.Label(filters, text="Stats").pack(side="left")
        ttk.Combobox(
            filters,
            textvariable=self.stats_window_var,
            values=["7", "30", "90"],
            width=5,
            state="readonly",
        ).pack(side="left", padx=(4, 10))

        ttk.Button(top, text="Apply", command=self.refresh).pack(side="left")
        ttk.Button(top, text="Verify", command=self.verify).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="Export Report", command=self.export_verification_report).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="Export JSON", command=lambda: self.export("json")).pack(side="right")
        ttk.Button(top, text="Export CSV", command=lambda: self.export("csv")).pack(side="right", padx=(0, 8))
        ttk.Button(top, text="Export PDF", command=lambda: self.export("pdf")).pack(side="right", padx=(0, 8))

        stats_frame = ttk.LabelFrame(self, text="Dashboard", padding=8)
        stats_frame.pack(fill="x", padx=8, pady=(0, 8))
        self.stats_label = ttk.Label(stats_frame, text="Loading statistics")
        self.stats_label.pack(side="left", padx=(0, 14))
        self.stats_canvas = tk.Canvas(stats_frame, width=420, height=54, highlightthickness=0, bg="#f3f4f6")
        self.stats_canvas.pack(side="left", fill="x", expand=True)
        ttk.Button(stats_frame, text="Refresh", command=self.refresh_stats).pack(side="right")

        middle = ttk.PanedWindow(self, orient="vertical")
        middle.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        table_frame = ttk.Frame(middle)
        middle.add(table_frame, weight=3)

        columns = ("seq", "timestamp", "event_type", "severity", "user_id", "source", "entry_id")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=16, style="Audit.Treeview")
        for col, label, width in [
            ("seq", "#", 70),
            ("timestamp", "Timestamp", 180),
            ("event_type", "Event", 220),
            ("severity", "Severity", 90),
            ("user_id", "User", 100),
            ("source", "Source", 120),
            ("entry_id", "Entry", 90),
        ]:
            self.tree.heading(col, text=label, command=lambda c=col: self.sort_by(c))
            self.tree.column(col, width=width, anchor="w")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.show_selected_details)
        self.tree.bind("<Double-1>", self.open_context_target)
        self.tree.bind("<Button-3>", self.show_context_menu)

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Highlight vault entry", command=self.highlight_vault_entry)
        self.context_menu.add_command(label="Show event details", command=self.show_selected_details)
        self.context_menu.add_command(label="Copy sequence number", command=self.copy_selected_sequence)

        details_frame = ttk.Frame(middle)
        middle.add(details_frame, weight=2)

        ttk.Label(details_frame, textvariable=self.status_var).pack(anchor="w")
        self.details = tk.Text(details_frame, height=10, wrap="word")
        self.details.pack(fill="both", expand=True)

        bottom = ttk.Frame(self, padding=(8, 0, 8, 8))
        bottom.pack(fill="x")
        ttk.Button(bottom, text="Previous", command=self.previous_page).pack(side="left")
        self.page_label = ttk.Label(bottom, text="Page 1")
        self.page_label.pack(side="left", padx=10)
        ttk.Button(bottom, text="Next", command=self.next_page).pack(side="left")
        ttk.Button(bottom, text="Close", command=self.destroy).pack(side="right")

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
        self.page_label.config(text=f"Page {self.page + 1}")
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
            self.status_var.set("Integrity: signer unavailable in this view")
            return

        result = self.master.audit_logger.verify_integrity() if hasattr(self.master, "audit_logger") else None
        if result is None:
            from src.core.audit.log_verifier import AuditLogVerifier

            result = AuditLogVerifier(self.db, self.signer).verify_range().to_dict()
        status = "valid" if result["verified"] else "tampering detected"
        self.last_verification_report = {
            "metadata": {
                "report_type": "cryptosafe.audit.verification.v1",
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "scope": "full",
            },
            "result": result,
        }
        self.status_var.set(
            f"Integrity: {status}, {result['valid_entries']}/{result['total_entries']} entries valid"
        )
        self.details.delete("1.0", "end")
        self.details.insert("1.0", json.dumps(self.last_verification_report, indent=2, ensure_ascii=False))
        if not result["verified"]:
            if hasattr(self.master, "audit_logger"):
                self.master.audit_logger.handle_verification_result(
                    result,
                    source="manual",
                )
            messagebox.showwarning("Audit integrity", "Audit log integrity verification failed.", parent=self)

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
            text=f"Total: {total} | Failed logins: {failed} | Security: {suspicious} | Integrity: {integrity}"
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
                self.master.set_status(f"Highlighted vault entry {row['entry_id']}")

    def show_failed_login_details(self, row) -> None:
        try:
            entry = json.loads(bytes(row["entry_data"]).decode("utf-8"))
            details = entry.get("details", {})
        except Exception:
            details = {}
        ip = details.get("ip_address", "unknown")
        messagebox.showinfo(
            "Failed login",
            f"Time: {row['timestamp']}\nUser: {row['user_id']}\nIP: {ip}",
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
            messagebox.showerror("Export blocked", "Master password confirmation is unavailable.", parent=self)
            return False

        dialog = LoginDialog(self, auth_service)
        dialog.title("Confirm export")
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
