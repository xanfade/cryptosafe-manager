import tkinter as tk
import difflib
import hashlib
import shlex
import time
import webbrowser
import subprocess
import logging
import platform
from tkinter import ttk, messagebox

from src.gui.password_change_dialog import PasswordChangeDialog
from src.gui.widgets.audit_log_viewer import AuditLogViewer
from src.gui.widgets.import_export_dialog import ImportExportDialog
from src.gui.widgets.qr_exchange_window import QrExchangeWindow
from src.gui.login_dialog import LoginDialog
from src.core.services.vault_service import VaultService
from src.gui.widgets.secure_table import SecureTable
from src.gui.entry_dialog import EntryDialog
from src.core.clipboard import ClipboardService, ClipboardMonitor
from src.core.clipboard.platform_adapter import get_platform_clipboard_adapter
from dataclasses import dataclass
from tkinter import messagebox, simpledialog
from src.gui.theme import apply_theme, COLORS, FONTS
from src.core.clipboard.clipboard_settings import ClipboardSettingsRepository
from src.core.events import AppShutdown, VaultUnlocked
from src.core.events import VaultSearchPerformed
from src.gui.widgets.clipboard_settings_dialog import ClipboardSettingsDialog
from src.gui.tray_manager import TrayController

logger = logging.getLogger(__name__)

@dataclass
class ClipboardPreview:
    data_type: str
    source: str
    value: str

class MainWindow(tk.Tk):
    def __init__(
        self,
        db=None,
        key_manager=None,
        auth_service=None,
        event_bus=None,
        audit_logger=None,
        start_minimized_to_tray: bool = False,
    ):
        super().__init__()

        apply_theme(self)
        self.configure(bg=COLORS["bg"])

        self.event_bus = event_bus
        self.db = db
        self.key_manager = key_manager
        self.auth_service = auth_service
        self.audit_logger = audit_logger
        self.start_minimized_to_tray = bool(start_minimized_to_tray)
        self._pre_minimize_geometry = None
        self._pre_minimize_state = "normal"
        self._is_tray_hidden = False

        self.clipboard_settings_repository = ClipboardSettingsRepository(
            db=self.db,
            key_manager=self.key_manager,
        )

        self.vault_service = VaultService(
            db=self.db,
            key_manager=self.key_manager,
            event_bus=self.event_bus,
        )

        self.clipboard_service = ClipboardService(
            adapter=get_platform_clipboard_adapter(self),
            event_bus=self.event_bus,
            clear_after_seconds=None,
            is_unlocked_callback=lambda: (
                    self.auth_service is not None
                    and self.auth_service.is_unlocked()
                    and not self.locked
            )
        )
        clipboard_settings = self.clipboard_settings_repository.get()
        self.clipboard_service.apply_settings(clipboard_settings)
        self.clipboard_service.subscribe(self._on_clipboard_state_changed)
        if self.event_bus is not None:
            self.clipboard_service.bind_panic_mode(self.event_bus)

        self.clipboard_monitor = ClipboardMonitor(self.clipboard_service)
        self.clipboard_monitor.start()

        self._clipboard_countdown_job = None
        self._clipboard_remaining = 0
        self._clipboard_warned = False
        self.clipboard_preview = None

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
        self._audit_verification_job = None
        self._lock_overlay = None
        self._panic_snapshot = None
        self._shake_points = []
        self._panic_in_progress = False
        self._lazy_load_job = None
        self._lazy_offset = 0
        self._lazy_chunk_size = 120
        self._lazy_total = 0
        self.audit_integrity_status = "not checked"

        self.title("CryptoSafe Manager")
        self.geometry("1450x850")
        self.minsize(1150, 680)
        self.configure(bg=COLORS["bg"])

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self.setup_styles()
        self.create_menu()
        self.create_layout()
        self.create_sidebar()
        self.create_header()
        self.create_toolbar()
        self.create_table_container()
        self.create_table()
        self.create_statusbar()
        self._setup_tray()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self._bind_auth_integration()
        self._bind_global_shortcuts()
        self.after(1000, self._poll_session_state)
        self._schedule_periodic_audit_verification(initial_delay_ms=2000)

        if self.auth_service and not self.auth_service.is_unlocked():
            self.apply_locked_state()
        else:
            self.apply_unlocked_state()

        if self.start_minimized_to_tray and self.tray and self.tray.enabled:
            self.after(200, self.hide_to_tray)

    def _setup_tray(self):
        self.tray = TrayController(
            title="CryptoSafe Manager",
            run_on_ui=lambda fn: self.after(0, fn),
            on_show=self.show_from_tray,
            on_lock=self.lock_vault,
            on_unlock=self.unlock_vault,
            on_quick_search=self.quick_search_from_tray,
            on_clear_clipboard=self.clear_clipboard_from_tray,
            on_panic_mode=self.activate_panic_from_tray,
            on_settings=self.open_clipboard_settings,
            on_exit=self.on_close,
        )
        self.tray.start()

    def hide_to_tray(self):
        self.update_idletasks()
        self._pre_minimize_geometry = self.geometry()
        self._pre_minimize_state = self.state()
        self.withdraw()
        self._is_tray_hidden = True
        if self.tray and self.tray.enabled:
            self.tray.notify("CryptoSafe", "Application is running in tray")

    def show_from_tray(self):
        self.deiconify()
        if self._pre_minimize_geometry:
            self.geometry(self._pre_minimize_geometry)
        try:
            self.state(self._pre_minimize_state or "normal")
        except Exception:
            self.state("normal")
        self.lift()
        self.focus_force()
        self._is_tray_hidden = False

    def quick_search_from_tray(self):
        self.show_from_tray()
        query = simpledialog.askstring("Quick Search", "Find entry:", parent=self)
        if not query:
            return
        self.search_var.set(query)
        if self.filtered_rows:
            self._select_table_entry(int(self.filtered_rows[0].id))
            self.set_status(f"Найдено записей: {len(self.filtered_rows)}")
        else:
            self.set_status("Совпадений не найдено")

    def clear_clipboard_from_tray(self):
        if hasattr(self, "clipboard_service"):
            self.clipboard_service.clear()
        if self.tray and self.tray.enabled:
            self.tray.set_clipboard_active(False)
            self.tray.notify("CryptoSafe", "Буфер обмена очищен")
        messagebox.showinfo("Буфер обмена", "Буфер обмена очищен.", parent=self)

    def activate_panic_from_tray(self):
        self.activate_panic_mode("tray")

    def activate_panic_mode(self, reason: str = "manual"):
        if self._panic_in_progress:
            return
        self._panic_in_progress = True
        try:
            self._panic_snapshot = {
                "search_query": self.search_var.get() if hasattr(self, "search_var") else "",
                "geometry": self.geometry(),
                "state": self.state(),
            }
            close_app = str(self.db.get_setting("security.hardening.panic_mode.close_app", "false")).lower() in {"1", "true", "yes", "on"}
            fake_error = str(self.db.get_setting("security.hardening.panic_mode.stealth.fake_error", "false")).lower() in {"1", "true", "yes", "on"}
            decoy_command = str(self.db.get_setting("security.hardening.panic_mode.stealth.decoy_command", "") or "")
            redirect_url = str(self.db.get_setting("security.hardening.panic_mode.stealth.redirect_url", "") or "")

            if self.auth_service and self.auth_service.panic_mode:
                self.auth_service.panic_mode.close_app_on_activate = close_app
                self.auth_service.panic_mode.stealth_fake_error = fake_error
                self.auth_service.panic_mode.stealth_decoy_command = decoy_command
                self.auth_service.panic_mode.stealth_redirect_url = redirect_url

            activated = False
            if self.auth_service:
                activated = self.auth_service.activate_panic_mode(
                    clear_clipboard_callback=lambda: self.clipboard_service.clear() if hasattr(self, "clipboard_service") else None,
                    reason=reason,
                )

            if activated:
                self._close_child_windows()
                self.apply_locked_state()
                self._run_panic_stealth(fake_error=fake_error, decoy_command=decoy_command, redirect_url=redirect_url)
                if close_app:
                    self.on_close()
                elif self.tray and self.tray.enabled:
                    self.tray.notify("CryptoSafe", "Panic mode activated")
        finally:
            self._panic_in_progress = False

    def _close_child_windows(self):
        for child in list(self.winfo_children()):
            if isinstance(child, tk.Toplevel):
                try:
                    child.destroy()
                except Exception:
                    pass

    def _run_panic_stealth(self, fake_error: bool, decoy_command: str, redirect_url: str):
        if fake_error:
            try:
                messagebox.showerror("System Error", "Unexpected application error occurred.")
            except Exception:
                pass
        if decoy_command:
            try:
                subprocess.Popen(decoy_command, shell=True)
            except Exception:
                pass
        if redirect_url:
            try:
                webbrowser.open(redirect_url)
            except Exception:
                pass

    def update_window_title(self):
        if self.locked:
            state_text = "Хранилище заблокировано"
        else:
            state_text = "Хранилище открыто"

        self.title(f"CryptoSafe Manager — {state_text}")

        if hasattr(self, "storage_state_label"):
            if self.locked:
                self.storage_state_label.config(
                    text="Хранилище заблокировано",
                    fg="#ef4444"
                )
            else:
                self.storage_state_label.config(
                    text="Хранилище разблокировано",
                    fg="#22c55e"
                )

    def setup_styles(self):
        style = ttk.Style(self)

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Treeview",
            background="#1c1c1e",
            foreground="#f5f5f7",
            fieldbackground="#1c1c1e",
            rowheight=38,
            borderwidth=0,
            relief="flat",
            font=("Arial", 10)
        )

        style.map(
            "Treeview",
            background=[("selected", "#7c3aed")],
            foreground=[("selected", "#ffffff")]
        )

        style.configure(
            "Treeview.Heading",
            background="#242426",
            foreground="#a1a1aa",
            font=("Arial", 10, "bold"),
            relief="flat",
            borderwidth=0,
            padding=(10, 9)
        )

        style.map(
            "Treeview.Heading",
            background=[("active", "#2d2d30")]
        )

        style.configure(
            "Vertical.TScrollbar",
            background="#242426",
            troughcolor="#121212",
            bordercolor="#121212",
            arrowcolor="#a1a1aa",
            relief="flat",
            borderwidth=0,
        )

    def create_layout(self):
        self.sidebar = tk.Frame(
            self,
            bg="#171719",
            width=245
        )
        self.sidebar.grid(row=0, column=0, sticky="ns")
        self.sidebar.grid_propagate(False)

        self.main_container = tk.Frame(
            self,
            bg=COLORS["bg"]
        )
        self.main_container.grid(row=0, column=1, sticky="nsew")

        self.main_container.grid_rowconfigure(3, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)

    def create_sidebar(self):
        logo_frame = tk.Frame(self.sidebar, bg="#171719")
        logo_frame.pack(fill="x", padx=22, pady=(26, 30))

        tk.Label(
            logo_frame,
            text="CryptoSafe",
            bg="#171719",
            fg="#ffffff",
            font=("Arial", 22, "bold")
        ).pack(anchor="w")

        tk.Label(
            logo_frame,
            text="Password Manager",
            bg="#171719",
            fg="#8b8b92",
            font=("Arial", 10)
        ).pack(anchor="w", pady=(4, 0))

        nav_frame = tk.Frame(self.sidebar, bg="#171719")
        nav_frame.pack(fill="x", padx=12)

        self.sidebar_vault_btn = self._make_sidebar_canvas_button(
            nav_frame,
            "🔐  Хранилище",
            lambda: self.table.tree.focus_set() if hasattr(self, "table") else None
        )
        self.sidebar_vault_btn.pack(fill="x", pady=3)

        self.sidebar_add_btn = self._make_sidebar_canvas_button(
            nav_frame,
            "➕  Добавить запись",
            self.add_record
        )
        self.sidebar_add_btn.pack(fill="x", pady=3)

        self.sidebar_clipboard_btn = self._make_sidebar_canvas_button(
            nav_frame,
            "📋  Буфер обмена",
            self.show_clipboard_preview
        )
        self.sidebar_clipboard_btn.pack(fill="x", pady=3)

        self.sidebar_logs_btn = self._make_sidebar_canvas_button(
            nav_frame,
            "📑  Журнал событий",
            lambda: AuditLogViewer(self, db=self.db, signer=getattr(self.audit_logger, "signer", None))
        )
        self.sidebar_logs_btn.pack(fill="x", pady=3)

        self.sidebar_qr_btn = self._make_sidebar_canvas_button(
            nav_frame,
            "📷  QR Exchange",
            self.open_qr_exchange
        )
        self.sidebar_qr_btn.pack(fill="x", pady=3)

        self.sidebar_import_export_btn = self._make_sidebar_canvas_button(
            nav_frame,
            "⇄  Import / Export",
            self.open_import_export_dialog
        )
        self.sidebar_import_export_btn.pack(fill="x", pady=3)

        bottom_frame = tk.Frame(self.sidebar, bg="#171719")
        bottom_frame.pack(side="bottom", fill="x", padx=12, pady=18)

        self.sidebar_lock_btn = self._make_sidebar_canvas_button(
            bottom_frame,
            "🔒  Заблокировать",
            self.toggle_lock_state
        )
        self.sidebar_lock_btn.pack(fill="x", pady=3)

        self.sidebar_unlock_btn = self._make_sidebar_canvas_button(
            bottom_frame,
            "🔓  Разблокировать",
            self.unlock_vault
        )
        self.sidebar_unlock_btn.pack(fill="x", pady=3)
        self.sidebar_unlock_btn.pack_forget()

    def _make_sidebar_canvas_button(self, parent, text, command, width=205, height=46):
        normal_bg = "#171719"
        hover_bg = "#252529"
        disabled_bg = "#171719"

        normal_fg = "#d4d4d8"
        disabled_fg = "#5f5f66"

        canvas = tk.Canvas(
            parent,
            width=width,
            height=height,
            bg="#171719",
            highlightthickness=0,
            bd=0,
            cursor="hand2"
        )

        rect = canvas.create_rectangle(
            0,
            0,
            width,
            height,
            fill=normal_bg,
            outline=normal_bg
        )

        label = canvas.create_text(
            18,
            height // 2,
            text=text,
            fill=normal_fg,
            font=("Arial", 11),
            anchor="w"
        )

        canvas._custom_canvas_button = True
        canvas._enabled = True
        canvas._command = command
        canvas._rect = rect
        canvas._label = label
        canvas._normal_bg = normal_bg
        canvas._hover_bg = hover_bg
        canvas._disabled_bg = disabled_bg
        canvas._normal_fg = normal_fg
        canvas._disabled_fg = disabled_fg

        def set_bg(color):
            canvas.itemconfig(rect, fill=color, outline=color)

        def set_fg(color):
            canvas.itemconfig(label, fill=color)

        def on_click(event):
            if getattr(canvas, "_enabled", True):
                canvas._command()

        def on_enter(event):
            if getattr(canvas, "_enabled", True):
                set_bg(canvas._hover_bg)
                set_fg("#ffffff")

        def on_leave(event):
            if getattr(canvas, "_enabled", True):
                set_bg(canvas._normal_bg)
                set_fg(canvas._normal_fg)

        canvas.bind("<Button-1>", on_click)
        canvas.bind("<Enter>", on_enter)
        canvas.bind("<Leave>", on_leave)

        canvas._set_bg = set_bg
        canvas._set_fg = set_fg

        return canvas

    def set_custom_button_enabled(self, button, enabled: bool):
        if not button:
            return

        button._enabled = enabled

        if getattr(button, "_custom_canvas_button", False):
            if enabled:
                button._set_bg(button._normal_bg)
                button._set_fg(button._normal_fg)
                button.config(cursor="hand2")
            else:
                button._set_bg(button._disabled_bg)
                button._set_fg(button._disabled_fg)
                button.config(cursor="arrow")
            return

        if enabled:
            button.config(
                bg=getattr(button, "_normal_bg", "#242426"),
                fg=getattr(button, "_normal_fg", "#ffffff"),
                cursor="hand2",
                state="normal"
            )
        else:
            button.config(
                bg=getattr(button, "_disabled_bg", "#1a1a1c"),
                fg=getattr(button, "_disabled_fg", "#66666d"),
                cursor="arrow",
                state="normal"
            )

    def create_header(self):
        self.header = tk.Frame(
            self.main_container,
            bg=COLORS["bg"],
            height=92
        )
        self.header.grid(row=0, column=0, sticky="ew")
        self.header.grid_propagate(False)

        title_block = tk.Frame(self.header, bg=COLORS["bg"])
        title_block.pack(side="left", padx=30, pady=20)

        tk.Label(
            title_block,
            text="Хранилище",
            bg=COLORS["bg"],
            fg="#ffffff",
            font=("Arial", 24, "bold")
        ).pack(anchor="w")

        self.storage_state_label = tk.Label(
            title_block,
            text="Хранилище разблокировано",
            bg=COLORS["bg"],
            fg="#22c55e",
            font=("Arial", 10)
        )
        self.storage_state_label.pack(anchor="w", pady=(5, 0))

        search_panel = tk.Frame(
            self.header,
            bg="#1c1c1e",
            highlightthickness=1,
            highlightbackground="#2d2d30"
        )
        search_panel.pack(side="right", padx=30, pady=26)

        tk.Label(
            search_panel,
            text="⌕",
            bg="#1c1c1e",
            fg="#a1a1aa",
            font=("Arial", 13)
        ).pack(side="left", padx=(12, 6))

        self.search_entry = tk.Entry(
            search_panel,
            textvariable=self.search_var,
            bg="#1c1c1e",
            fg="#ffffff",
            insertbackground="#ffffff",
            relief="flat",
            bd=0,
            font=("Arial", 11),
            width=32
        )
        self.search_entry.pack(side="left", ipady=9, padx=(0, 12))
        self.search_entry.configure(takefocus=True)

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
        file_menu.add_command(label="Import / Export", command=self.open_import_export_dialog)
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
        security_menu.add_command(
            label="Настройки буфера обмена",
            command=self.open_clipboard_settings,
        )

        security_menu.add_separator()

        security_menu.add_command(
            label="Сменить мастер-пароль",
            command=self.open_password_change_dialog,
        )
        menubar.add_cascade(label="Security", menu=security_menu)

        view_menu = tk.Menu(
            menubar, tearoff=0,
            bg="#2b2b2b", fg="#ffffff",
            activebackground="#3a3a3a", activeforeground="#ffffff"
        )
        view_menu.add_command(
            label="Logs",
            command=lambda: AuditLogViewer(self, db=self.db, signer=getattr(self.audit_logger, "signer", None)),
        )
        view_menu.add_command(
            label="QR Exchange",
            command=self.open_qr_exchange,
        )
        view_menu.add_command(
            label="Import / Export",
            command=self.open_import_export_dialog,
        )
        view_menu.add_command(
            label="Диагностика ошибок",
            command=self.show_security_diagnostics,
        )
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
        self.toolbar = tk.Frame(
            self.main_container,
            bg=COLORS["bg"],
            height=62
        )
        self.toolbar.grid(row=1, column=0, sticky="ew")
        self.toolbar.grid_propagate(False)

        left = tk.Frame(self.toolbar, bg=COLORS["bg"])
        left.pack(side="left", padx=30, pady=10)

        self.btn_add = self._make_canvas_button(
            left,
            "Добавить",
            self.add_record,
            accent=True,
            width=120,
            height=38
        )
        self.btn_add.pack(side="left", padx=(0, 10))

        self.btn_edit = self._make_canvas_button(
            left,
            "Изменить",
            self.edit_record,
            width=120,
            height=38
        )
        self.btn_edit.pack(side="left", padx=(0, 10))

        self.btn_delete = self._make_canvas_button(
            left,
            "Удалить",
            self.delete_record,
            width=110,
            height=38
        )
        self.btn_delete.pack(side="left", padx=(0, 10))

        self.btn_toggle_passwords = self._make_canvas_button(
            left,
            "Показать пароли",
            self.toggle_passwords_visibility,
            width=155,
            height=38
        )
        self.btn_toggle_passwords.pack(side="left", padx=(0, 10))

        right = tk.Frame(self.toolbar, bg=COLORS["bg"])
        right.pack(side="right", padx=30, pady=10)

        self.btn_clear_search = self._make_canvas_button(
            right,
            "Сброс поиска",
            self.clear_search,
            width=135,
            height=38
        )
        self.btn_clear_search.pack(side="right")

        self.btn_lock = self._make_canvas_button(
            right,
            "Заблокировать",
            self.toggle_lock_state,
            width=145,
            height=38
        )
        self.btn_lock.pack(side="right", padx=(0, 10))

        self.btn_unlock = self._make_canvas_button(
            right,
            "Разблокировать",
            self.unlock_vault,
            width=145,
            height=38
        )
        self.btn_unlock.pack(side="right", padx=(0, 10))
        self.btn_unlock.pack_forget()

    def _make_sidebar_canvas_button(self, parent, text, command, width=205, height=46):
        normal_bg = "#171719"
        hover_bg = "#252529"
        disabled_bg = "#171719"

        normal_fg = "#d4d4d8"
        disabled_fg = "#5f5f66"

        canvas = tk.Canvas(
            parent,
            width=width,
            height=height,
            bg="#171719",
            highlightthickness=0,
            bd=0,
            cursor="hand2"
        )

        rect = canvas.create_rectangle(
            0,
            0,
            width,
            height,
            fill=normal_bg,
            outline=normal_bg
        )

        label = canvas.create_text(
            18,
            height // 2,
            text=text,
            fill=normal_fg,
            font=("Arial", 11),
            anchor="w"
        )

        canvas._custom_canvas_button = True
        canvas._enabled = True
        canvas._command = command
        canvas._rect = rect
        canvas._label = label
        canvas._normal_bg = normal_bg
        canvas._hover_bg = hover_bg
        canvas._disabled_bg = disabled_bg
        canvas._normal_fg = normal_fg
        canvas._disabled_fg = disabled_fg

        def set_bg(color):
            canvas.itemconfig(rect, fill=color, outline=color)

        def set_fg(color):
            canvas.itemconfig(label, fill=color)

        def on_click(event):
            if getattr(canvas, "_enabled", True):
                canvas._command()

        def on_enter(event):
            if getattr(canvas, "_enabled", True):
                set_bg(canvas._hover_bg)
                set_fg("#ffffff")

        def on_leave(event):
            if getattr(canvas, "_enabled", True):
                set_bg(canvas._normal_bg)
                set_fg(canvas._normal_fg)

        canvas.bind("<Button-1>", on_click)
        canvas.bind("<Enter>", on_enter)
        canvas.bind("<Leave>", on_leave)

        canvas._set_bg = set_bg
        canvas._set_fg = set_fg

        return canvas

    def create_table_container(self):
        self.table_outer = tk.Frame(
            self.main_container,
            bg=COLORS["bg"]
        )
        self.table_outer.grid(
            row=3,
            column=0,
            sticky="nsew",
            padx=30,
            pady=(8, 18)
        )

        self.table_outer.grid_rowconfigure(0, weight=1)
        self.table_outer.grid_columnconfigure(0, weight=1)

        self.table_card = tk.Frame(
            self.table_outer,
            bg="#1c1c1e",
            highlightthickness=1,
            highlightbackground="#2d2d30"
        )
        self.table_card.grid(row=0, column=0, sticky="nsew")

        self.table_card.grid_rowconfigure(0, weight=1)
        self.table_card.grid_columnconfigure(0, weight=1)

    def create_table(self):
        self.table = SecureTable(self.table_card)
        self.table.grid(row=0, column=0, sticky="nsew", padx=1, pady=1)

        self.table.bind_actions(
            on_edit=self._edit_entry_from_table,
            on_delete=self._delete_entries_from_table,
            on_copy_username=self._copy_username_from_table,
            on_copy_password=self._copy_password_from_table,
            on_copy_all=self._copy_all_from_table,
            on_open_url=self._open_url_from_table,
            on_selection_changed=self._on_table_selection_changed,
        )

        self.table.tree.bind("<Double-1>", lambda event: self.edit_record(), add="+")

    def create_statusbar(self):
        self.statusbar = tk.Frame(
            self.main_container,
            bg="#171719",
            height=36
        )
        self.statusbar.grid(row=4, column=0, sticky="ew")
        self.statusbar.grid_propagate(False)

        self.status = tk.StringVar(value="Готово")

        self.status_label = tk.Label(
            self.statusbar,
            textvariable=self.status,
            anchor="w",
            bg="#171719",
            fg="#cfcfcf",
            font=("Arial", 10),
            padx=30,
            pady=7
        )
        self.status_label.pack(side="left", fill="x", expand=True)

        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress = ttk.Progressbar(
            self.statusbar,
            orient="horizontal",
            mode="determinate",
            maximum=100.0,
            variable=self.progress_var,
            length=180,
        )
        self.progress.pack(side="left", padx=(8, 0), pady=8)
        self.progress.pack_forget()

        self.audit_status_label = tk.Label(
            self.statusbar,
            text="Audit: not checked",
            bg="#171719",
            fg="#a1a1aa",
            font=("Arial", 10),
            padx=12,
            pady=7,
        )
        self.audit_status_label.pack(side="right", pady=4)

        self.clipboard_preview_button = self._make_canvas_button(
            self.statusbar,
            "📋 Буфер",
            self.show_clipboard_preview,
            width=120,
            height=28,
            canvas_bg="#171719"
        )
        self.clipboard_preview_button.pack(side="right", padx=30, pady=4)

    def _make_canvas_button(
            self,
            parent,
            text,
            command,
            accent=False,
            width=130,
            height=38,
            canvas_bg=None
    ):
        normal_bg = "#7c3aed" if accent else "#242426"
        hover_bg = "#8b5cf6" if accent else "#2d2d30"
        disabled_bg = "#1b1b1d"

        normal_fg = "#ffffff"
        disabled_fg = "#6f6f76"

        if canvas_bg is None:
            canvas_bg = parent.cget("bg")

        canvas = tk.Canvas(
            parent,
            width=width,
            height=height,
            bg=canvas_bg,
            highlightthickness=0,
            bd=0,
            cursor="hand2"
        )

        rect = canvas.create_rectangle(
            0,
            0,
            width,
            height,
            fill=normal_bg,
            outline=normal_bg
        )

        label = canvas.create_text(
            width // 2,
            height // 2,
            text=text,
            fill=normal_fg,
            font=("Arial", 10)
        )

        canvas._custom_canvas_button = True
        canvas._enabled = True
        canvas._command = command
        canvas._rect = rect
        canvas._label = label
        canvas._normal_bg = normal_bg
        canvas._hover_bg = hover_bg
        canvas._disabled_bg = disabled_bg
        canvas._normal_fg = normal_fg
        canvas._disabled_fg = disabled_fg

        def set_bg(color):
            canvas.itemconfig(rect, fill=color, outline=color)

        def set_fg(color):
            canvas.itemconfig(label, fill=color)

        def on_click(event):
            if getattr(canvas, "_enabled", True):
                canvas._command()

        def on_enter(event):
            if getattr(canvas, "_enabled", True):
                set_bg(canvas._hover_bg)
                set_fg("#ffffff")

        def on_leave(event):
            if getattr(canvas, "_enabled", True):
                set_bg(canvas._normal_bg)
                set_fg(canvas._normal_fg)

        canvas.bind("<Button-1>", on_click)
        canvas.bind("<Enter>", on_enter)
        canvas.bind("<Leave>", on_leave)

        canvas._set_bg = set_bg
        canvas._set_fg = set_fg

        return canvas

    def set_status(self, text):
        self.status.set(text)

    def show_progress(self, message: str, percent: float = 0.0):
        self.set_status(message)
        self.progress_var.set(max(0.0, min(100.0, float(percent))))
        self.progress.pack(side="left", padx=(8, 0), pady=8)

    def hide_progress(self):
        self.progress_var.set(0.0)
        self.progress.pack_forget()

    def run_user_action(self, action, error_title: str, hint: str):
        try:
            return action()
        except Exception as exc:
            logger.exception("User action failed: %s", error_title)
            messagebox.showerror(
                error_title,
                f"{hint}\n\nDetails: {type(exc).__name__}",
                parent=self,
            )
            return None

    def _clear_table(self):
        if not hasattr(self, "table"):
            return
        self.table.clear()

    def load_entries(self):
        if self._lazy_load_job is not None:
            self.after_cancel(self._lazy_load_job)
            self._lazy_load_job = None

        if getattr(self, "locked", False):
            self.rows = []
            self.all_rows = []
            self.filtered_rows = []
            self._clear_table()
            self.hide_progress()
            return

        if not self.db:
            self.rows = []
            self.all_rows = []
            self.filtered_rows = []
            self._clear_table()
            self.hide_progress()
            return

        total = self.vault_service.count_entries()
        if total >= 300:
            self.all_rows = []
            self.filtered_rows = []
            self.rows = []
            self._clear_table()
            self._lazy_total = total
            self._lazy_offset = 0
            self.show_progress("Loading vault entries...", 0.0)
            self._load_entries_chunk()
            return

        self.all_rows = self.vault_service.list_entries()
        self.apply_search()
        self.hide_progress()

    def _load_entries_chunk(self):
        page = self.vault_service.get_entries_page(limit=self._lazy_chunk_size, offset=self._lazy_offset)
        if not page:
            self.apply_search()
            self.hide_progress()
            return
        self.all_rows.extend(page)
        self._lazy_offset += len(page)
        self.apply_search()
        percent = (self._lazy_offset / max(1, self._lazy_total)) * 100.0
        self.show_progress(f"Loading vault entries... {self._lazy_offset}/{self._lazy_total}", percent)
        if self._lazy_offset < self._lazy_total:
            self._lazy_load_job = self.after(1, self._load_entries_chunk)
        else:
            self._lazy_load_job = None
            self.hide_progress()

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
        self._publish_search_audit(query, len(self.filtered_rows))

        total = len(self.all_rows)
        shown = len(self.filtered_rows)

        if query:
            self.set_status(f"Найдено записей: {shown} из {total}")
        else:
            self.set_status(f"Записей: {shown}")

    def _publish_search_audit(self, query: str, result_count: int) -> None:
        if not query or not self.event_bus:
            return

        query_hash = hashlib.sha256(query.encode("utf-8")).hexdigest()[:16]
        self.event_bus.publish(
            VaultSearchPerformed(
                query_hash=query_hash,
                result_count=result_count,
            )
        )

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

    def open_clipboard_settings(self):
        if self.locked:
            messagebox.showwarning(
                "Хранилище заблокировано",
                "Сначала разблокируй хранилище, чтобы изменить защищённые настройки.",
                parent=self,
            )
            return

        dialog = ClipboardSettingsDialog(
            self,
            repository=self.clipboard_settings_repository,
            clipboard_service=self.clipboard_service,
        )

        self.wait_window(dialog)

        if dialog.result:
            timeout = dialog.result.auto_clear_timeout_sec

            if timeout is None:
                self.set_status("Настройки буфера сохранены: автоочистка отключена")
            else:
                self.set_status(f"Настройки буфера сохранены: автоочистка {timeout} сек.")

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
        if self._panic_snapshot:
            try:
                if self._panic_snapshot.get("geometry"):
                    self.geometry(self._panic_snapshot["geometry"])
                self.search_var.set(self._panic_snapshot.get("search_query", ""))
            except Exception:
                pass
            self._panic_snapshot = None
        self.set_status("Записи удалены")

    def _copy_username_from_table(self, entry_id: str):
        row = self.vault_service.get_entry(int(entry_id))
        if not row:
            return

        value = row.username or ""

        self.clipboard_preview = ClipboardPreview(
            data_type="Логин",
            source=row.title,
            value=value,
        )

        self.clipboard_service.copy_secret(value=value, entry_id=row.id)

        self.table.set_clipboard_entry(row.id)
        self.show_toast("Логин скопирован")
        self.set_status(f"Логин скопирован. {self.get_clipboard_timeout_text()}")

    def _copy_password_from_table(self, entry_id: str):
        try:
            entry_id_int = int(entry_id)

            # Берём запись заново из VaultService,
            # а VaultService внутри использует EntryManager
            entry = self.vault_service.get_entry(entry_id_int)

            if entry is None:
                self.show_toast("Запись не найдена")
                self.set_status("Ошибка: запись не найдена.")
                return

            # Проверка запрета копирования для конкретной записи
            if getattr(entry, "never_copy_to_clipboard", False):
                self.clipboard_service.publish_copy_blocked(
                    entry_id=entry_id_int,
                    reason="Entry is marked as never copy to clipboard",
                )
                self.show_toast("Копирование запрещено")
                self.set_status("Копирование запрещено настройками записи.")
                return

            value = entry.password or ""

            if not value:
                self.show_toast("Пароль пустой")
                self.set_status("Пароль отсутствует.")
                return

            self.clipboard_preview = ClipboardPreview(
                data_type="Пароль",
                source=entry.title,
                value=value,
            )

            self.clipboard_service.copy_secret(
                value=value,
                entry_id=entry_id_int,
            )

            self.table.set_clipboard_entry(entry_id_int)
            self.show_toast("Пароль скопирован")
            self.set_status("Пароль скопирован. Буфер очистится автоматически.")

        except Exception as exc:
            self.show_toast("Ошибка копирования")
            self.set_status(f"Ошибка копирования пароля: {exc}")

    def _copy_all_from_table(self, entry_id: str):
        row = self.get_row_by_id(int(entry_id))
        if not row:
            return

        value = (
            f"Title: {row.title}\n"
            f"Username: {row.username or ''}\n"
            f"Password: {row.password or ''}\n"
            f"URL: {row.url or ''}"
        )

        self.clipboard_preview = ClipboardPreview(
            data_type="Полная запись",
            source=row.title,
            value=value,
        )

        self.clipboard_service.copy_secret(value=value, entry_id=int(entry_id))

        self.table.set_clipboard_entry(int(entry_id))
        self.show_toast("Данные записи скопированы")
        self.set_status(f"Данные записи скопированы. {self.get_clipboard_timeout_text()}")


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
            self.btn_toggle_passwords.itemconfig(
                self.btn_toggle_passwords._label,
                text="Скрыть пароли"
            )
            self.set_status("Пароли показаны")
        else:
            self.btn_toggle_passwords.itemconfig(
                self.btn_toggle_passwords._label,
                text="Показать пароли"
            )
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

    def apply_locked_state(self):
        self.locked = True

        if hasattr(self, "clipboard_service"):
            self.clipboard_service.clear()
        self.clipboard_preview = None
        self._show_lock_overlay()
        self._hide_sensitive_windows()

        self.rows = []
        self._clear_table()
        self.all_rows = []
        self.filtered_rows = []
        self.search_var.set("")

        self.set_custom_button_enabled(self.btn_lock, True)
        if hasattr(self, "btn_lock"):
            self.btn_lock._command = self.toggle_lock_state
            self.btn_lock.itemconfig(self.btn_lock._label, text="Разблокировать")
        if hasattr(self, "btn_unlock"):
            self.set_custom_button_enabled(self.btn_unlock, False)
        self.set_custom_button_enabled(self.btn_add, False)
        self.set_custom_button_enabled(self.btn_edit, False)
        self.set_custom_button_enabled(self.btn_delete, False)
        self.set_custom_button_enabled(self.btn_toggle_passwords, False)

        if hasattr(self, "sidebar_add_btn"):
            self.set_custom_button_enabled(self.sidebar_add_btn, False)

        if hasattr(self, "sidebar_lock_btn"):
            self.set_custom_button_enabled(self.sidebar_lock_btn, True)
            self.sidebar_lock_btn._command = self.toggle_lock_state
            self.sidebar_lock_btn.itemconfig(self.sidebar_lock_btn._label, text="🔓  Разблокировать")

        if hasattr(self, "sidebar_unlock_btn"):
            self.set_custom_button_enabled(self.sidebar_unlock_btn, True)

        self.set_status("Хранилище заблокировано")
        self.update_window_title()
        if self.tray and self.tray.enabled:
            self.tray.set_locked(True)
            self.tray.set_crypto_busy(False)
            self.tray.set_clipboard_active(False)
            self.tray.notify("CryptoSafe", "Vault locked")

    def apply_unlocked_state(self):
        self.locked = False
        self._hide_lock_overlay()
        if self.event_bus:
            self.event_bus.publish(VaultUnlocked(user="local"))

        self.set_custom_button_enabled(self.btn_lock, True)
        if hasattr(self, "btn_lock"):
            self.btn_lock._command = self.toggle_lock_state
            self.btn_lock.itemconfig(self.btn_lock._label, text="Заблокировать")
        if hasattr(self, "btn_unlock"):
            self.set_custom_button_enabled(self.btn_unlock, False)
        self.set_custom_button_enabled(self.btn_add, True)
        self.set_custom_button_enabled(self.btn_edit, True)
        self.set_custom_button_enabled(self.btn_delete, True)
        self.set_custom_button_enabled(self.btn_toggle_passwords, True)

        if hasattr(self, "sidebar_add_btn"):
            self.set_custom_button_enabled(self.sidebar_add_btn, True)

        if hasattr(self, "sidebar_lock_btn"):
            self.set_custom_button_enabled(self.sidebar_lock_btn, True)
            self.sidebar_lock_btn._command = self.toggle_lock_state
            self.sidebar_lock_btn.itemconfig(self.sidebar_lock_btn._label, text="🔒  Заблокировать")

        if hasattr(self, "sidebar_unlock_btn"):
            self.set_custom_button_enabled(self.sidebar_unlock_btn, False)

        self.load_entries()
        self.set_status("Хранилище разблокировано")
        self.update_window_title()
        if self.tray and self.tray.enabled:
            self.tray.set_locked(False)
            self.tray.set_crypto_busy(False)
            self.tray.notify("CryptoSafe", "Vault unlocked")

    def toggle_lock_state(self):
        if self.locked:
            self.unlock_vault()
        else:
            self.lock_vault()

    def lock_vault(self):
        if self.tray and self.tray.enabled:
            self.tray.set_crypto_busy(True)
        if self.auth_service:
            try:
                self.auth_service.logout()
            except Exception:
                pass
        self._lock_and_scrub(reason="manual")

    def unlock_vault(self):
        if self.tray and self.tray.enabled:
            self.tray.set_crypto_busy(True)
        if not self.auth_service:
            messagebox.showerror("Ошибка", "Сервис аутентификации не подключён", parent=self)
            return

        dlg = LoginDialog(self, self.auth_service)
        self.wait_window(dlg)

        if getattr(dlg, "result", False):
            if hasattr(self.auth_service, "verify_session_integrity") and not self.auth_service.verify_session_integrity():
                messagebox.showerror(
                    "Session error",
                    "Session integrity check failed. Please log in again.",
                    parent=self,
                )
                self._lock_and_scrub(reason="session_integrity_failed")
                return
            self.apply_unlocked_state()
        else:
            self.apply_locked_state()

    def _lock_and_scrub(self, reason: str = "lock"):
        if self.tray and self.tray.enabled:
            self.tray.set_crypto_busy(True)
        if self.auth_service:
            try:
                self.auth_service.auto_lock(reason)
            except Exception:
                pass
        self.apply_locked_state()

    def _show_lock_overlay(self):
        return

    def _hide_lock_overlay(self):
        if self._lock_overlay is None:
            return
        try:
            self._lock_overlay.destroy()
        finally:
            self._lock_overlay = None

    def _hide_sensitive_windows(self):
        return

    def _bind_auth_integration(self):
        if not self.auth_service:
            return

        self.bind_all("<Any-KeyPress>", self._mark_activity, add="+")
        self.bind_all("<Any-ButtonPress>", self._mark_activity, add="+")
        self.bind_all("<Motion>", self._mark_mouse_activity, add="+")
        self.bind("<FocusIn>", self._on_focus_in, add="+")
        self.bind("<FocusOut>", self._on_focus_out, add="+")
        self.bind("<Unmap>", self._on_unmap, add="+")
        self.bind("<Map>", self._on_map, add="+")
        self.bind_all("<Control-Shift-P>", lambda event: self.toggle_passwords_visibility(), add="+")
        self.bind_all("<Control-Shift-Escape>", lambda event: self.activate_panic_mode("hotkey"), add="+")

    def _bind_global_shortcuts(self):
        self.bind_all("<Control-f>", lambda event: self.search_entry.focus_set(), add="+")
        self.bind_all("<Control-n>", lambda event: self.add_record(), add="+")
        self.bind_all("<Control-e>", lambda event: self.edit_record(), add="+")
        self.bind_all("<Delete>", lambda event: self.delete_record(), add="+")
        self.bind_all("<Control-l>", lambda event: self.lock_vault(), add="+")
        self.bind_all("<Return>", lambda event: self.edit_record(), add="+")

    def _mark_activity(self, event=None):
        if self.auth_service and self.auth_service.is_unlocked():
            self.auth_service.touch()

    def _mark_mouse_activity(self, event=None):
        if self.auth_service and self.auth_service.is_unlocked():
            self.auth_service.touch()
            self._track_shake_gesture(event)

    def _track_shake_gesture(self, event=None):
        if event is None or not self.auth_service or not self.auth_service.is_unlocked():
            return
        now = time.time()
        self._shake_points.append((now, int(getattr(event, "x_root", 0))))
        self._shake_points = [point for point in self._shake_points if now - point[0] <= 1.0]
        if len(self._shake_points) < 6:
            return
        xs = [point[1] for point in self._shake_points]
        amplitude = max(xs) - min(xs)
        if amplitude < 180:
            return
        direction_changes = 0
        last_dir = 0
        for i in range(1, len(xs)):
            delta = xs[i] - xs[i - 1]
            direction = 1 if delta > 0 else (-1 if delta < 0 else 0)
            if direction != 0 and last_dir != 0 and direction != last_dir:
                direction_changes += 1
            if direction != 0:
                last_dir = direction
        if direction_changes >= 4:
            self._shake_points = []
            self.activate_panic_mode("shake_gesture")

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
            self._lock_and_scrub(reason="focus_lost")

    def _on_focus_in(self, event=None):
        if not self._has_focus:
            self._has_focus = True
            if self.auth_service:
                self.auth_service.on_app_focus_gained()
                self.auth_service.touch()

    def _on_unmap(self, event=None):
        if self.state() == "iconic" and not self._is_minimized:
            self._is_minimized = True
            if self.tray and self.tray.enabled:
                self.hide_to_tray()
                return

        if self.auth_service and self.auth_service.is_unlocked():
            self.auth_service.on_app_minimized()
            self._lock_and_scrub(reason="minimized")

    def _on_map(self, event=None):
        if self._is_minimized:
            self._is_minimized = False

            if self.auth_service:
                self.auth_service.on_app_restored()
                self.auth_service.touch()

    def _poll_session_state(self):
        try:
            if self.tray and self.tray.enabled and hasattr(self, "clipboard_service"):
                self.tray.set_clipboard_active(self.clipboard_service.has_active_secret())
            if self.auth_service and self.auth_service.check_auto_lock():
                self.apply_locked_state()
                return
        finally:
            self.after(1000, self._poll_session_state)

    def on_close(self):
        if self._audit_verification_job is not None:
            self.after_cancel(self._audit_verification_job)
            self._audit_verification_job = None

        if self.event_bus:
            self.event_bus.publish(AppShutdown(reason="user_exit"))

        if hasattr(self, "clipboard_monitor"):
            self.clipboard_monitor.stop()

        if hasattr(self, "clipboard_service"):
            self.clipboard_service.clear()

        if self.auth_service:
            try:
                self.auth_service.logout()
            except Exception:
                pass

        if hasattr(self.db, "close_thread_connection"):
            self.db.close_thread_connection()

        if hasattr(self, "tray") and self.tray:
            self.tray.stop()

        self.destroy()

    def _on_clipboard_state_changed(self, state: str):
        if state == "copied":
            self.start_clipboard_countdown()

        elif state == "cleared":
            self.stop_clipboard_countdown()
            self.table.set_clipboard_entry(None)
            self.show_toast("Буфер обмена очищен")
            self.set_status("Буфер обмена очищен.")

        elif state == "suspicious":
            self.stop_clipboard_countdown()
            self.table.set_clipboard_entry(None)
            self.clipboard_preview = None
            self.show_toast("Буфер изменён вне приложения. Данные очищены.")
            self.set_status("Подозрительное изменение буфера. Буфер очищен.")

    def show_toast(self, message: str, duration_ms: int = 2500):
        if not self.notifications_enabled():
            return
        if platform.system() == "Darwin":
            try:
                safe_message = message.replace("\\", "\\\\").replace('"', '\\"')
                subprocess.run(
                    ["osascript", "-e", f'display notification "{safe_message}" with title "CryptoSafe"'],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return
            except Exception:
                pass

        toast = tk.Toplevel(self)
        toast.overrideredirect(True)
        toast.configure(bg="#2d2d30")
        toast.attributes("-topmost", True)

        label = tk.Label(
            toast,
            text=message,
            bg="#2d2d30",
            fg="#ffffff",
            font=("Arial", 10),
            padx=18,
            pady=10
        )
        label.pack()

        self.update_idletasks()

        x = self.winfo_x() + self.winfo_width() - 300
        y = self.winfo_y() + self.winfo_height() - 100

        toast.geometry(f"+{x}+{y}")
        toast.after(duration_ms, toast.destroy)

    def start_clipboard_countdown(self):
        if self._clipboard_countdown_job:
            self.after_cancel(self._clipboard_countdown_job)
            self._clipboard_countdown_job = None

        timeout = self.clipboard_service.clear_after_seconds

        if timeout is None:
            self._clipboard_remaining = 0
            self._clipboard_warned = False
            self.set_status("Буфер скопирован. Автоочистка отключена.")
            return

        self._clipboard_remaining = timeout
        self._clipboard_warned = False
        self._tick_clipboard_countdown()

    def _tick_clipboard_countdown(self):
        if self._clipboard_remaining <= 0:
            self.clipboard_preview = None
            self.table.set_clipboard_entry(None)
            self.set_status("Буфер обмена очищен.")
            return

        self.set_status(f"Буфер очистится через {self._clipboard_remaining} сек.")

        if self._clipboard_remaining == 5 and not self._clipboard_warned:
            self._clipboard_warned = True
            self.show_toast("Буфер обмена очистится через 5 секунд")

        self._clipboard_remaining -= 1
        self._clipboard_countdown_job = self.after(1000, self._tick_clipboard_countdown)

    def stop_clipboard_countdown(self):
        if self._clipboard_countdown_job:
            self.after_cancel(self._clipboard_countdown_job)
            self._clipboard_countdown_job = None

        self._clipboard_remaining = 0
        self._clipboard_warned = False

    def mask_clipboard_value(self, value: str) -> str:
        if not value:
            return ""

        if len(value) <= 3:
            return "•" * len(value)

        visible = value[:3]
        hidden = "•" * min(len(value) - 3, 8)

        return visible + hidden

    def show_clipboard_preview(self):
        if not self.clipboard_preview:
            messagebox.showinfo("Буфер обмена", "Буфер обмена пуст или уже очищен.")
            return

        preview = self.clipboard_preview

        dialog = tk.Toplevel(self)
        dialog.title("Clipboard Preview")
        dialog.resizable(False, False)
        dialog.configure(bg="#1f1f1f")
        dialog.transient(self)
        dialog.grab_set()

        width = 420
        height = 270
        x = self.winfo_x() + self.winfo_width() // 2 - width // 2
        y = self.winfo_y() + self.winfo_height() // 2 - height // 2
        dialog.geometry(f"{width}x{height}+{x}+{y}")

        container = tk.Frame(dialog, bg="#1f1f1f", padx=22, pady=22)
        container.pack(fill="both", expand=True)

        tk.Label(
            container,
            text="Предпросмотр буфера",
            bg="#1f1f1f",
            fg="#ffffff",
            font=("Arial", 14, "bold"),
        ).pack(anchor="w", pady=(0, 14))

        tk.Label(
            container,
            text=f"Тип данных: {preview.data_type}",
            bg="#1f1f1f",
            fg="#d0d0d0",
            font=("Arial", 10),
        ).pack(anchor="w", pady=3)

        tk.Label(
            container,
            text=f"Источник: {preview.source}",
            bg="#1f1f1f",
            fg="#d0d0d0",
            font=("Arial", 10),
        ).pack(anchor="w", pady=3)

        value_var = tk.StringVar(value=self.mask_clipboard_value(preview.value))

        value_label = tk.Label(
            container,
            textvariable=value_var,
            bg="#2b2b2b",
            fg="#ffffff",
            font=("Consolas", 11),
            padx=12,
            pady=10,
            anchor="w",
            justify="left",
            wraplength=360,
        )
        value_label.pack(fill="x", pady=(14, 12))

        def reveal():
            if not self.verify_master_password_for_preview():
                messagebox.showerror("Ошибка", "Неверный мастер-пароль.")
                return

            value_var.set(preview.value)

        buttons = tk.Frame(container, bg="#1f1f1f")
        buttons.pack(fill="x", pady=(8, 0))

        show_btn = self._make_canvas_button(
            buttons,
            "Показать",
            reveal,
            accent=True,
            width=120,
            height=34,
            canvas_bg="#1f1f1f"
        )
        show_btn.pack(side="left")

        close_btn = self._make_canvas_button(
            buttons,
            "Закрыть",
            dialog.destroy,
            width=120,
            height=34,
            canvas_bg="#1f1f1f"
        )
        close_btn.pack(side="right")

    def verify_master_password_for_preview(self) -> bool:
        if not self.auth_service:
            return False

        dialog = LoginDialog(self, self.auth_service)
        dialog.title("Подтверждение мастер-пароля")
        self.wait_window(dialog)

        return bool(getattr(dialog, "result", False))

    def open_qr_exchange(self):
        if self.locked:
            messagebox.showwarning("Хранилище заблокировано", "Сначала разблокируй хранилище", parent=self)
            return

        QrExchangeWindow(
            self,
            db=self.db,
            vault_service=self.vault_service,
            key_manager=self.key_manager,
        )

    def open_import_export_dialog(self):
        if self.locked:
            messagebox.showwarning("Хранилище заблокировано", "Сначала разблокируй хранилище", parent=self)
            return

        ImportExportDialog(
            self,
            db=self.db,
            vault_service=self.vault_service,
            key_manager=self.key_manager,
            event_bus=self.event_bus,
        )

    def show_security_diagnostics(self):
        lines = []
        try:
            lines.append(f"Хранилище: {'заблокировано' if self.locked else 'разблокировано'}")
            if self.auth_service:
                lines.append(f"Сессия: {'целая' if self.auth_service.verify_session_integrity() else 'ошибка целостности'}")
                lines.append(f"Кэш ключа: {'есть' if self.key_manager and self.key_manager.has_cached_key() else 'пуст'}")
            if self.clipboard_service:
                lines.append(f"Буфер: {'активен' if self.clipboard_service.has_active_secret() else 'пуст'}")
                lines.append(f"Автоочистка: {self.get_clipboard_timeout_text()}")
            if self.audit_logger:
                result = self.audit_logger.verify_recent()
                lines.append(f"Аудит: {'валиден' if result.get('verified') else 'ошибка'}")
                lines.append(f"Проверено записей: {result.get('valid_entries', 0)}/{result.get('total_entries', 0)}")
            else:
                lines.append("Аудит: логгер недоступен")
        except Exception as exc:
            lines.append(f"Ошибка диагностики: {exc}")
        messagebox.showinfo("Диагностика", "\n".join(lines), parent=self)

    def get_clipboard_timeout_text(self):
        timeout = self.clipboard_service.clear_after_seconds

        if timeout is None:
            return "автоочистка отключена"

        if timeout < 60:
            return f"буфер очистится через {timeout} сек."

        minutes = timeout // 60
        seconds = timeout % 60

        if seconds == 0:
            return f"буфер очистится через {minutes} мин."

        return f"буфер очистится через {minutes} мин. {seconds} сек."

    def notifications_enabled(self) -> bool:
        try:
            settings = self.clipboard_settings_repository.get()
            return bool(settings.notifications_enabled)
        except Exception:
            return True

    def _schedule_periodic_audit_verification(self, initial_delay_ms: int | None = None):
        if not self.audit_logger:
            return

        try:
            interval_hours = max(
                1,
                int(self.db.get_setting("audit.verification.interval_hours", "24")),
            )
        except Exception:
            interval_hours = 24

        delay_ms = initial_delay_ms if initial_delay_ms is not None else interval_hours * 60 * 60 * 1000
        self._audit_verification_job = self.after(delay_ms, self._run_periodic_audit_verification)

    def _run_periodic_audit_verification(self):
        self._audit_verification_job = None
        try:
            result = self.audit_logger.verify_recent()
            self._update_audit_integrity_status(result)
            self.audit_logger.handle_verification_result(
                result,
                source="periodic",
                notify_callback=lambda _result: messagebox.showwarning(
                    "Audit integrity",
                    "Audit log integrity verification failed.",
                    parent=self,
                ),
                lock_callback=self.apply_locked_state,
            )
        finally:
            self._schedule_periodic_audit_verification()

    def _update_audit_integrity_status(self, result):
        if result.get("verified"):
            text = f"Audit: valid ({result.get('valid_entries', 0)} checked)"
            color = "#22c55e"
        else:
            text = "Audit: tampering detected"
            color = "#ef4444"

        self.audit_integrity_status = text
        if hasattr(self, "audit_status_label"):
            self.audit_status_label.config(text=text, fg=color)


if __name__ == "__main__":
    MainWindow().mainloop()
