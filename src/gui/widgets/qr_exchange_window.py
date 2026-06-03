from __future__ import annotations

import io
import json
import tempfile
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import numpy as np
from PIL import ImageGrab, ImageTk

from src.core.import_export import KeyExchangeService, SecureSharingService, VaultExporter, VaultImporter
from src.core.import_export.qr_service import QrPayloadService
from src.core.events import ClipboardImageScanned
from src.gui.theme import COLORS, FONTS


class QrExchangeWindow(tk.Toplevel):
    def __init__(self, master, db, vault_service, key_manager, initial_payload_type: str | None = None, initial_payload: bytes | None = None):
        super().__init__(master)
        self.db = db
        self.vault_service = vault_service
        self.key_manager = key_manager
        self.key_exchange = KeyExchangeService.from_database(db, algorithm="p256")
        self.importer = VaultImporter(vault_service, key_manager, key_exchange=self.key_exchange)
        self.exporter = VaultExporter(vault_service, key_manager)
        self.sharing = SecureSharingService(self.exporter, importer=self.importer, key_exchange=self.key_exchange)
        self.qr = QrPayloadService()
        self.qr_images = []
        self.qr_photo = None
        self.scan_camera = None
        self._refresh_job = None
        self._current_qr_payload_type = None
        self._current_qr_payload = None
        self._current_qr_seconds_left = 0

        self.title("Обмен QR-code")
        self.geometry("1040x760")
        self.configure(bg=COLORS["bg"])
        self.transient(master)

        self._setup_styles()
        self._build_ui()
        self._load_entry_options()
        self._load_contacts()
        self._refresh_identity()
        if initial_payload_type and initial_payload is not None:
            self.show_payload(initial_payload_type, initial_payload)

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
        style.configure("Vault.Treeview.Heading", background=COLORS["surface_2"], foreground=COLORS["text"])
        style.map("Vault.Treeview", background=[("selected", "#7c3aed")], foreground=[("selected", "#ffffff")])

    def _build_ui(self):
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
        notebook.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        wrapper.columnconfigure(0, weight=1)
        wrapper.rowconfigure(0, weight=1)

        self.generate_tab = tk.Frame(notebook, bg=COLORS["bg"])
        self.scan_tab = tk.Frame(notebook, bg=COLORS["bg"])
        self.contacts_tab = tk.Frame(notebook, bg=COLORS["bg"])
        notebook.add(self.generate_tab, text="Генерация")
        notebook.add(self.scan_tab, text="Сканирование")
        notebook.add(self.contacts_tab, text="Контакты")

        self._build_generate_tab()
        self._build_scan_tab()
        self._build_contacts_tab()

    def _build_generate_tab(self):
        left = tk.Frame(self.generate_tab, bg=COLORS["bg"])
        left.pack(side="left", fill="y", padx=(0, 12), pady=8)
        right = tk.Frame(self.generate_tab, bg=COLORS["surface"])
        right.pack(side="right", fill="both", expand=True, pady=8)

        self.payload_kind = tk.StringVar(value="public_key")
        self.share_method = tk.StringVar(value="public_key")
        self.recipient_name = tk.StringVar()
        self.expiration_days = tk.IntVar(value=5)
        self.permission = tk.StringVar(value="read-only")
        self.share_password = tk.StringVar()
        self.link_base = tk.StringVar(value="https://shares.local")

        tk.Label(left, text="Полезная нагрузка", bg=COLORS["bg"], fg=COLORS["text"], font=FONTS["subtitle"]).pack(anchor="w")
        for label, value in [
            ("Публичный ключ", "public_key"),
            ("Зашифрованная запись", "encrypted_entry"),
            ("Ссылка для обмена", "share_link"),
        ]:
            tk.Radiobutton(
                left, text=label, value=value, variable=self.payload_kind,
                bg=COLORS["bg"], fg=COLORS["text"], selectcolor=COLORS["surface_2"],
                activebackground=COLORS["bg"], activeforeground=COLORS["text"],
                command=self._update_generate_state,
            ).pack(anchor="w", pady=2)

        self.selected_entry_var = tk.StringVar()
        tk.Label(left, text="Запись", bg=COLORS["bg"], fg=COLORS["muted"], font=FONTS["small"]).pack(anchor="w", pady=(12, 2))
        self.entry_combo = ttk.Combobox(left, textvariable=self.selected_entry_var, state="readonly", width=28)
        self.entry_combo.pack(fill="x")

        tk.Label(left, text="Получатель", bg=COLORS["bg"], fg=COLORS["muted"], font=FONTS["small"]).pack(anchor="w", pady=(12, 2))
        self.recipient_combo = ttk.Combobox(left, textvariable=self.recipient_name, state="readonly", width=28)
        self.recipient_combo.pack(fill="x")

        tk.Label(left, text="Метод", bg=COLORS["bg"], fg=COLORS["muted"], font=FONTS["small"]).pack(anchor="w", pady=(12, 2))
        ttk.Combobox(left, textvariable=self.share_method, state="readonly", values=["public_key", "password"], width=28).pack(fill="x")

        tk.Label(left, text="Пароль", bg=COLORS["bg"], fg=COLORS["muted"], font=FONTS["small"]).pack(anchor="w", pady=(12, 2))
        self.password_entry = tk.Entry(left, textvariable=self.share_password, show="*", bg=COLORS["surface"], fg=COLORS["text"], insertbackground=COLORS["text"])
        self.password_entry.pack(fill="x")

        tk.Label(left, text="Срок действия (дни)", bg=COLORS["bg"], fg=COLORS["muted"], font=FONTS["small"]).pack(anchor="w", pady=(12, 2))
        tk.Spinbox(left, from_=1, to=30, textvariable=self.expiration_days, bg=COLORS["surface"], fg=COLORS["text"], buttonbackground=COLORS["surface_2"]).pack(fill="x")

        tk.Label(left, text="Права", bg=COLORS["bg"], fg=COLORS["muted"], font=FONTS["small"]).pack(anchor="w", pady=(12, 2))
        ttk.Combobox(left, textvariable=self.permission, state="readonly", values=["read-only", "editable"], width=28).pack(fill="x")

        tk.Label(left, text="Базовый URL для ссылки", bg=COLORS["bg"], fg=COLORS["muted"], font=FONTS["small"]).pack(anchor="w", pady=(12, 2))
        self.link_entry = tk.Entry(left, textvariable=self.link_base, bg=COLORS["surface"], fg=COLORS["text"], insertbackground=COLORS["text"])
        self.link_entry.pack(fill="x")

        ttk.Button(left, text="Сгенерировать QR-code", command=self._generate_qr).pack(fill="x", pady=(16, 0))
        ttk.Button(left, text="Скопировать данные", command=self._copy_payload).pack(fill="x", pady=(8, 0))
        ttk.Button(left, text="Сохранить текущий PNG", command=self._save_current_qr).pack(fill="x", pady=(8, 0))

        self.qr_label = tk.Label(right, bg=COLORS["surface"])
        self.qr_label.pack(pady=18)
        self.qr_status = tk.Label(right, text="QR-code ещё не сгенерирован", bg=COLORS["surface"], fg=COLORS["muted"], font=FONTS["body"])
        self.qr_status.pack(anchor="center", pady=(0, 12))
        payload_wrap = tk.Frame(right, bg=COLORS["surface"])
        payload_wrap.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        payload_wrap.grid_rowconfigure(0, weight=1)
        payload_wrap.grid_columnconfigure(0, weight=1)
        self.payload_preview = tk.Text(payload_wrap, height=14, bg=COLORS["surface_2"], fg=COLORS["text"], insertbackground=COLORS["text"], wrap="word")
        self.payload_preview.grid(row=0, column=0, sticky="nsew")
        payload_scroll = ttk.Scrollbar(payload_wrap, orient="vertical", style="Vertical.TScrollbar", command=self.payload_preview.yview)
        payload_scroll.grid(row=0, column=1, sticky="ns")
        self.payload_preview.configure(yscrollcommand=payload_scroll.set)
        self._update_generate_state()

    def _build_scan_tab(self):
        top = tk.Frame(self.scan_tab, bg=COLORS["bg"])
        top.pack(fill="x", padx=8, pady=8)
        for i in range(5):
            top.grid_columnconfigure(i, weight=1, uniform="scan_btn")
        ttk.Button(top, text="Сканировать файл", command=self._scan_image_file).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ttk.Button(top, text="Сканировать буфер", command=self._scan_clipboard_image).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(top, text="Сканировать камеру", command=self._scan_camera_once).grid(row=0, column=2, sticky="ew", padx=6)
        ttk.Button(top, text="Предпросмотр", command=self._preview_scanned_payload).grid(row=0, column=3, sticky="ew", padx=6)
        ttk.Button(top, text="Сохранить в хранилище", command=self._save_scanned_payload).grid(row=0, column=4, sticky="ew", padx=(6, 0))

        self.scan_status = tk.Label(self.scan_tab, text="Данные ещё не отсканированы", bg=COLORS["bg"], fg=COLORS["muted"], font=FONTS["body"])
        self.scan_status.pack(anchor="w", padx=8)
        scan_wrap = tk.Frame(self.scan_tab, bg=COLORS["bg"])
        scan_wrap.pack(fill="both", expand=True, padx=8, pady=8)
        scan_wrap.grid_rowconfigure(0, weight=1)
        scan_wrap.grid_columnconfigure(0, weight=1)
        self.scan_text = tk.Text(scan_wrap, bg=COLORS["surface"], fg=COLORS["text"], insertbackground=COLORS["text"], wrap="word")
        self.scan_text.grid(row=0, column=0, sticky="nsew")
        scan_scroll = ttk.Scrollbar(scan_wrap, orient="vertical", style="Vertical.TScrollbar", command=self.scan_text.yview)
        scan_scroll.grid(row=0, column=1, sticky="ns")
        self.scan_text.configure(yscrollcommand=scan_scroll.set)
        self.scanned_payload = None
        self.scanned_type = None

    def _build_contacts_tab(self):
        top = tk.Frame(self.contacts_tab, bg=COLORS["bg"])
        top.pack(fill="x", padx=8, pady=8)
        self.identity_label = tk.Label(top, text="", bg=COLORS["bg"], fg=COLORS["text"], font=FONTS["body"], justify="left")
        self.identity_label.pack(anchor="w")
        ttk.Button(top, text="Ротация ключа P-256", command=self._rotate_identity).pack(anchor="w", pady=(8, 0))

        form = tk.Frame(self.contacts_tab, bg=COLORS["bg"])
        form.pack(fill="x", padx=8, pady=8)
        self.contact_name = tk.StringVar()
        self.contact_fingerprint = tk.StringVar()
        tk.Label(form, text="Имя контакта", bg=COLORS["bg"], fg=COLORS["muted"]).grid(row=0, column=0, sticky="w")
        tk.Entry(form, textvariable=self.contact_name, bg=COLORS["surface"], fg=COLORS["text"], insertbackground=COLORS["text"]).grid(row=1, column=0, sticky="ew", padx=(0, 8))
        tk.Label(form, text="Ожидаемый отпечаток", bg=COLORS["bg"], fg=COLORS["muted"]).grid(row=0, column=1, sticky="w")
        tk.Entry(form, textvariable=self.contact_fingerprint, bg=COLORS["surface"], fg=COLORS["text"], insertbackground=COLORS["text"]).grid(row=1, column=1, sticky="ew")
        form.columnconfigure(0, weight=1)
        form.columnconfigure(1, weight=1)

        buttons = tk.Frame(self.contacts_tab, bg=COLORS["bg"])
        buttons.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(buttons, text="Импорт контакта из QR/изображения", command=self._import_contact_qr).pack(side="left")
        ttk.Button(buttons, text="Проверить отпечаток", command=self._verify_contact).pack(side="left", padx=(8, 0))
        ttk.Button(buttons, text="Отозвать контакт", command=self._revoke_contact).pack(side="left", padx=(8, 0))

        contacts_wrap = tk.Frame(self.contacts_tab, bg=COLORS["bg"])
        contacts_wrap.pack(fill="both", expand=True, padx=8, pady=8)
        contacts_wrap.grid_rowconfigure(0, weight=1)
        contacts_wrap.grid_columnconfigure(0, weight=1)
        self.contacts_tree = ttk.Treeview(contacts_wrap, columns=("algorithm", "fingerprint", "verified", "revoked"), show="headings", height=12, style="Vault.Treeview")
        for column, title, width in [
            ("algorithm", "Алгоритм", 120),
            ("fingerprint", "Отпечаток", 260),
            ("verified", "Проверен", 80),
            ("revoked", "Отозван", 80),
        ]:
            self.contacts_tree.heading(column, text=title)
            self.contacts_tree.column(column, width=width, anchor="w")
        self.contacts_tree.grid(row=0, column=0, sticky="nsew")
        contacts_scroll = ttk.Scrollbar(contacts_wrap, orient="vertical", style="Vertical.TScrollbar", command=self.contacts_tree.yview)
        contacts_scroll.grid(row=0, column=1, sticky="ns")
        self.contacts_tree.configure(yscrollcommand=contacts_scroll.set)

    def _update_generate_state(self):
        kind = self.payload_kind.get()
        state = "normal" if kind != "public_key" else "disabled"
        self.entry_combo.config(state="readonly" if state == "normal" else "disabled")
        self.recipient_combo.config(state="readonly" if kind != "public_key" else "disabled")
        self.password_entry.config(state="normal" if self.share_method.get() == "password" and kind != "public_key" else "disabled")
        self.link_entry.config(state="normal" if kind == "share_link" else "disabled")

    def _generate_qr(self):
        try:
            kind = self.payload_kind.get()
            if kind == "public_key":
                payload = json.dumps(self.key_exchange.export_public_bundle(owner="local"), ensure_ascii=False).encode("utf-8")
                payload_type = "public_key"
            else:
                entry_value = self.selected_entry_var.get().strip()
                if not entry_value:
                    raise ValueError("запись не выбрана")
                entry_id = int(entry_value.split("|", 1)[0].strip())
                recipient_name = self.recipient_name.get().strip()
                if not recipient_name:
                    raise ValueError("recipient is required")
                contacts = self.key_exchange.list_contacts()
                contact = contacts.get(recipient_name)
                if not contact:
                    raise ValueError("recipient contact not found")
                method = self.share_method.get()
                if method == "password":
                    payload = self.sharing.share_entry_with_password(
                        entry_id,
                        export_password=self.share_password.get().strip(),
                        sharer="local",
                        recipient=recipient_name,
                        expires_in_days=int(self.expiration_days.get()),
                        permission=self.permission.get(),
                    )
                else:
                    payload = self.sharing.share_entry_with_public_key(
                        entry_id,
                        bytes.fromhex(contact["public_key"]),
                        sharer="local",
                        recipient=recipient_name,
                        expires_in_days=int(self.expiration_days.get()),
                        permission=self.permission.get(),
                    )
                payload_type = "share_link" if kind == "share_link" else "encrypted_entry"
                if kind == "share_link":
                    link = self.sharing.generate_share_link(payload, self.link_base.get().strip(), int(self.expiration_days.get()))
                    payload = link.encode("utf-8")

            chunks = self.qr.build_chunks(payload_type, payload)
            self.show_payload(payload_type, payload, chunks=chunks)
        except Exception as exc:
            messagebox.showerror("Генерация QR-code", str(exc), parent=self)

    def show_payload(self, payload_type: str, payload: bytes, chunks: list[dict] | None = None):
        self._current_qr_payload_type = payload_type
        self._current_qr_payload = payload
        chunks = chunks or self.qr.build_chunks(payload_type, payload)
        self.qr_images = self.qr.render_qr_images(chunks)
        self._show_qr_image(0)
        self.payload_preview.delete("1.0", "end")
        self.payload_preview.insert("1.0", payload.decode("utf-8", errors="replace")[:5000])
        self._current_qr_seconds_left = self.qr.validity_seconds
        self._update_qr_status(len(chunks))
        self._schedule_refresh()

    def _update_qr_status(self, chunk_count: int):
        minutes, seconds = divmod(max(self._current_qr_seconds_left, 0), 60)
        self.qr_status.config(
            text=f"{self._current_qr_payload_type} | частей: {chunk_count} | обновление через {minutes:02d}:{seconds:02d}"
        )

    def _schedule_refresh(self):
        if self._refresh_job is not None:
            self.after_cancel(self._refresh_job)
        self._refresh_job = self.after(1000, self._tick_refresh)

    def _tick_refresh(self):
        if not self._current_qr_payload:
            self._refresh_job = None
            return
        self._current_qr_seconds_left -= 1
        if self._current_qr_seconds_left <= 0:
            chunks = self.qr.build_chunks(self._current_qr_payload_type, self._current_qr_payload)
            self.qr_images = self.qr.render_qr_images(chunks)
            self._show_qr_image(0)
            self._current_qr_seconds_left = self.qr.validity_seconds
            self._update_qr_status(len(chunks))
        else:
            self._update_qr_status(len(self.qr_images) or 1)
        self._schedule_refresh()

    def _copy_payload(self):
        if not self._current_qr_payload:
            return
        payload_text = self._current_qr_payload.decode("utf-8", errors="replace")
        clipboard_service = getattr(self.master, "clipboard_service", None)
        if clipboard_service is not None:
            clipboard_service.copy_text(payload_text)
        else:
            self.clipboard_clear()
            self.clipboard_append(payload_text)
        self.qr_status.config(text="Данные скопированы в буфер обмена")

    def _show_qr_image(self, index: int):
        if not self.qr_images:
            return
        image = self.qr_images[index].resize((380, 380))
        self.qr_photo = ImageTk.PhotoImage(image)
        self.qr_label.config(image=self.qr_photo)

    def _save_current_qr(self):
        if not self.qr_images:
            return
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".png", filetypes=[("PNG", "*.png")])
        if not path:
            return
        self.qr.save_qr_images([self.qr_images[0]], [path])
        self.qr_status.config(text=f"Сохранено: {path}")

    def _scan_image_file(self):
        paths = filedialog.askopenfilenames(parent=self, filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp")])
        if not paths:
            return
        try:
            payload_type, payload = self.qr.decode_qr_images(list(paths))
            self._set_scanned_payload(payload_type, payload)
        except Exception as exc:
            messagebox.showerror("Сканирование QR-code", str(exc), parent=self)

    def _scan_clipboard_image(self):
        try:
            image = ImageGrab.grabclipboard()
            if image is None or not hasattr(image, "convert"):
                raise ValueError("в буфере обмена нет изображения")
            rgb = image.convert("RGB")
            frame = np.array(rgb)
            values = self.qr.decode_frame(frame)
            if not values:
                raise ValueError("QR-code на изображении из буфера не найден")
            payload_type, payload = self.qr.reassemble_chunks([json.loads(item) for item in values])
            self._set_scanned_payload(payload_type, payload)
            if hasattr(self.master, "event_bus") and self.master.event_bus is not None:
                self.master.event_bus.publish(ClipboardImageScanned(source="clipboard"))
        except Exception as exc:
            messagebox.showerror("Сканирование QR-code", str(exc), parent=self)

    def _scan_camera_once(self):
        try:
            import imageio.v3 as iio
        except Exception:
            messagebox.showwarning("Сканирование QR-code", "Модуль камеры не установлен. Добавь imageio для сканирования с камеры.", parent=self)
            return
        try:
            for frame in iio.imiter("<video0>"):
                if frame is None:
                    continue
                values = self.qr.decode_frame(frame)
                if values:
                    payload_type, payload = self.qr.reassemble_chunks([json.loads(values[0])])
                    self._set_scanned_payload(payload_type, payload)
                    return
            messagebox.showinfo("Сканирование QR-code", "QR-code с камеры не обнаружен.", parent=self)
        except Exception as exc:
            messagebox.showerror("Сканирование QR-code", str(exc), parent=self)

    def _set_scanned_payload(self, payload_type: str, payload: bytes):
        self.scanned_type = payload_type
        self.scanned_payload = payload
        self.scan_status.config(text=f"Отсканировано: {payload_type}")
        self.scan_text.delete("1.0", "end")
        self.scan_text.insert("1.0", payload.decode("utf-8", errors="replace")[:8000])

    def _preview_scanned_payload(self):
        if not self.scanned_payload:
            return
        try:
            if self.scanned_type == "public_key":
                bundle = json.loads(self.scanned_payload.decode("utf-8"))
                self.scan_text.delete("1.0", "end")
                self.scan_text.insert("1.0", json.dumps(bundle, ensure_ascii=False, indent=2))
                return
            preview = self.sharing.receive_shared_entry(self.scanned_payload, import_password=self.share_password.get().strip(), save_to_vault=False)
            self.scan_text.delete("1.0", "end")
            self.scan_text.insert("1.0", json.dumps(preview, ensure_ascii=False, indent=2))
        except Exception as exc:
            messagebox.showerror("Предпросмотр QR-code", str(exc), parent=self)

    def _save_scanned_payload(self):
        if not self.scanned_payload:
            return
        try:
            if self.scanned_type == "public_key":
                bundle = json.loads(self.scanned_payload.decode("utf-8"))
                self.key_exchange.store_contact(bundle["owner"], bundle, verified=False)
                self._load_contacts()
                messagebox.showinfo("Импорт QR-code", "Публичный ключ сохранён в контакты.", parent=self)
                return
            result = self.sharing.receive_shared_entry(self.scanned_payload, import_password=self.share_password.get().strip(), save_to_vault=True)
            messagebox.showinfo("Импорт QR-code", f"Сохранено в хранилище: {len(result.imported_ids) + len(result.updated_ids)}", parent=self)
        except Exception as exc:
            messagebox.showerror("Импорт QR-code", str(exc), parent=self)

    def _load_contacts(self):
        contacts = self.key_exchange.list_contacts()
        self.recipient_combo["values"] = sorted(contacts.keys())
        for item in self.contacts_tree.get_children():
            self.contacts_tree.delete(item)
        for name, info in sorted(contacts.items()):
            self.contacts_tree.insert("", "end", iid=name, values=(info["algorithm"], info["fingerprint"], info["verified"], info["revoked"]))

    def _load_entry_options(self):
        values = []
        for entry in self.vault_service.get_all_entries():
            values.append(f"{entry.id} | {entry.title or ''} | {entry.username or ''}")
        self.entry_combo["values"] = values
        if values and not self.selected_entry_var.get():
            self.selected_entry_var.set(values[0])

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

    def _refresh_identity(self):
        bundle = self.key_exchange.export_public_bundle(owner="local")
        self.identity_label.config(
            text=f"Локальная идентичность\nАлгоритм: {bundle['algorithm']}\nОтпечаток: {bundle['fingerprint']}"
        )

    def _rotate_identity(self):
        bundle = self.key_exchange.rotate_identity("p256")
        self._refresh_identity()
        messagebox.showinfo("Идентичность QR-code", f"Идентичность обновлена.\nНовый отпечаток:\n{bundle['fingerprint']}", parent=self)

    def _import_contact_qr(self):
        self._scan_image_file()
        if self.scanned_type == "public_key":
            bundle = json.loads(self.scanned_payload.decode("utf-8"))
            self.contact_name.set(bundle.get("owner", "контакт"))
            self.contact_fingerprint.set(bundle.get("fingerprint", ""))

    def _verify_contact(self):
        name = self.contact_name.get().strip()
        fingerprint = self.contact_fingerprint.get().strip()
        if self.key_exchange.verify_contact_fingerprint(name, fingerprint):
            self._load_contacts()
            messagebox.showinfo("Контакты", "Отпечаток подтверждён.", parent=self)
        else:
            messagebox.showwarning("Контакты", "Отпечаток не совпадает.", parent=self)

    def _revoke_contact(self):
        name = self.contact_name.get().strip()
        if not name:
            return
        self.key_exchange.revoke_contact(name)
        self._load_contacts()

    def destroy(self):
        if hasattr(self, "_mw_bind_ids"):
            for sequence, func_id in self._mw_bind_ids:
                try:
                    self.unbind(sequence, func_id)
                except Exception:
                    pass
            self._mw_bind_ids = []
        if self._refresh_job is not None:
            self.after_cancel(self._refresh_job)
            self._refresh_job = None
        super().destroy()
