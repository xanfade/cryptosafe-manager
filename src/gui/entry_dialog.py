import re
import tkinter as tk
from tkinter import messagebox
from urllib.parse import urlparse

from src.core.validators import clean_url
from src.core.vault.password_generator import PasswordGenerator


class CryptoSafeDialogTheme:
    BG = "#111217"
    CARD = "#191B23"
    CARD_LIGHT = "#20232E"
    INPUT_BG = "#12141B"
    BORDER = "#2C3040"

    TEXT = "#F3F4F8"
    MUTED = "#A6ABBD"
    MUTED_DARK = "#777D91"

    PURPLE = "#8B5CF6"
    PURPLE_HOVER = "#7C3AED"
    PURPLE_DARK = "#5B21B6"

    DANGER = "#EF4444"
    WARNING = "#F59E0B"
    SUCCESS = "#22C55E"

    FONT = "Arial"


class PasswordGeneratorDialog(tk.Toplevel, CryptoSafeDialogTheme):
    def __init__(self, parent):
        super().__init__(parent)

        self.title("Генерация пароля")
        self.geometry("460x520")
        self.resizable(False, False)
        self.configure(bg=self.BG)
        self.transient(parent)
        self.grab_set()

        self.result = None

        self.length = tk.IntVar(value=16)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_upper = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_special = tk.BooleanVar(value=True)

        self._build_ui()
        self._center(parent)
        self.bind("<Escape>", lambda _event: self.destroy())

    def _build_ui(self):
        outer = tk.Frame(self, bg=self.BG, padx=24, pady=24)
        outer.pack(fill="both", expand=True)

        card = tk.Frame(
            outer,
            bg=self.CARD,
            highlightthickness=1,
            highlightbackground=self.BORDER,
            highlightcolor=self.BORDER,
        )
        card.pack(fill="both", expand=True)

        header = tk.Frame(card, bg=self.CARD, padx=24, pady=22)
        header.pack(fill="x")

        tk.Label(
            header,
            text="⚙",
            fg=self.TEXT,
            bg=self.CARD,
            font=(self.FONT, 24),
        ).pack(side="left", padx=(0, 14))

        title_box = tk.Frame(header, bg=self.CARD)
        title_box.pack(side="left", fill="x", expand=True)

        tk.Label(
            title_box,
            text="Генерация пароля",
            fg=self.TEXT,
            bg=self.CARD,
            font=(self.FONT, 18, "bold"),
        ).pack(anchor="w")

        tk.Label(
            title_box,
            text="Настрой длину и набор символов",
            fg=self.MUTED,
            bg=self.CARD,
            font=(self.FONT, 10),
        ).pack(anchor="w", pady=(5, 0))

        tk.Frame(card, bg=self.BORDER, height=1).pack(fill="x")

        body = tk.Frame(card, bg=self.CARD, padx=24, pady=22)
        body.pack(fill="both", expand=True)

        length_row = tk.Frame(body, bg=self.CARD)
        length_row.pack(fill="x", pady=(0, 10))

        tk.Label(
            length_row,
            text="Длина пароля",
            fg=self.TEXT,
            bg=self.CARD,
            font=(self.FONT, 11, "bold"),
        ).pack(side="left")

        self.length_value_label = tk.Label(
            length_row,
            textvariable=self.length,
            fg=self.PURPLE,
            bg=self.CARD,
            font=(self.FONT, 12, "bold"),
        )
        self.length_value_label.pack(side="right")

        self.length_scale = tk.Scale(
            body,
            from_=8,
            to=64,
            orient="horizontal",
            variable=self.length,
            bg=self.CARD,
            fg=self.TEXT,
            highlightthickness=0,
            troughcolor=self.CARD_LIGHT,
            activebackground=self.PURPLE,
            bd=0,
            sliderrelief="flat",
            showvalue=False,
            cursor="hand2",
        )
        self.length_scale.pack(fill="x", pady=(0, 20))

        options = tk.Frame(
            body,
            bg=self.CARD_LIGHT,
            highlightthickness=1,
            highlightbackground=self.BORDER,
            highlightcolor=self.BORDER,
            padx=14,
            pady=12,
        )
        options.pack(fill="x", pady=(0, 18))

        tk.Label(
            options,
            text="Символы в пароле",
            fg=self.TEXT,
            bg=self.CARD_LIGHT,
            font=(self.FONT, 11, "bold"),
        ).pack(anchor="w", pady=(0, 10))

        self._make_check(options, "Строчные a-z", self.use_lower)
        self._make_check(options, "Заглавные A-Z", self.use_upper)
        self._make_check(options, "Цифры 0-9", self.use_digits)
        self._make_check(options, "Спецсимволы !@#$%^&*", self.use_special)

        self.status_label = tk.Label(
            body,
            text="Выбери параметры и нажми сгенерировать",
            fg=self.MUTED,
            bg=self.CARD,
            font=(self.FONT, 10),
            anchor="w",
        )
        self.status_label.pack(fill="x", pady=(0, 18))

        buttons = tk.Frame(body, bg=self.CARD)
        buttons.pack(fill="x")

        self.cancel_btn = self._button(
            buttons,
            text="Отмена",
            command=self.destroy,
            bg="#242733",
            hover="#303443",
            width=12,
        )
        self.cancel_btn.pack(side="left")

        self.generate_btn = self._button(
            buttons,
            text="Сгенерировать",
            command=self.generate,
            bg=self.PURPLE,
            hover=self.PURPLE_HOVER,
            width=18,
            bold=True,
        )
        self.generate_btn.pack(side="right")

    def _make_check(self, parent, text, variable):
        row = tk.Frame(parent, bg=self.CARD_LIGHT)
        row.pack(fill="x", pady=4)

        check = tk.Checkbutton(
            row,
            text=text,
            variable=variable,
            bg=self.CARD_LIGHT,
            fg=self.TEXT,
            selectcolor=self.INPUT_BG,
            activebackground=self.CARD_LIGHT,
            activeforeground=self.TEXT,
            font=(self.FONT, 10),
            anchor="w",
            relief="flat",
            bd=0,
            cursor="hand2",
        )
        check.pack(anchor="w")
        return check

    def _button(self, parent, text, command, bg, hover, width=12, bold=False):
        btn = tk.Label(
            parent,
            text=text,
            font=(self.FONT, 11, "bold" if bold else "normal"),
            bg=bg,
            fg=self.TEXT,
            width=width,
            pady=12,
            cursor="hand2",
            anchor="center",
        )
        btn.default_bg = bg
        btn.hover_bg = hover
        btn.command = command
        btn.is_disabled = False

        btn.bind("<Button-1>", lambda _event: None if btn.is_disabled else btn.command())
        btn.bind("<Enter>", lambda _event: None if btn.is_disabled else btn.config(bg=btn.hover_bg))
        btn.bind("<Leave>", lambda _event: None if btn.is_disabled else btn.config(bg=btn.default_bg))

        return btn

    def _center(self, parent):
        self.update_idletasks()
        parent_width = max(parent.winfo_width(), 1)
        parent_height = max(parent.winfo_height(), 1)
        x = parent.winfo_rootx() + (parent_width // 2) - (self.winfo_width() // 2)
        y = parent.winfo_rooty() + (parent_height // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{x}+{y}")

    def generate(self):
        selected_sets = sum([
            self.use_lower.get(),
            self.use_upper.get(),
            self.use_digits.get(),
            self.use_special.get(),
        ])

        if selected_sets == 0:
            messagebox.showerror(
                "Ошибка генерации",
                "Выбери хотя бы один набор символов.",
                parent=self,
            )
            return

        if self.length.get() < max(8, selected_sets):
            messagebox.showerror(
                "Ошибка генерации",
                "Слишком маленькая длина для выбранных параметров.",
                parent=self,
            )
            return

        try:
            gen = PasswordGenerator()
            self.result = gen.generate(
                length=self.length.get(),
                use_lowercase=self.use_lower.get(),
                use_uppercase=self.use_upper.get(),
                use_digits=self.use_digits.get(),
                use_special=self.use_special.get(),
            )
            self.destroy()
        except RuntimeError:
            messagebox.showerror(
                "Ошибка генерации",
                "Не удалось сгенерировать пароль с текущими настройками.\n"
                "Увеличь длину или включи больше наборов символов.",
                parent=self,
            )
        except Exception as e:
            messagebox.showerror("Ошибка генерации", str(e), parent=self)


class EntryDialog(tk.Toplevel, CryptoSafeDialogTheme):
    def __init__(self, parent, title="Добавить запись", data=None):
        super().__init__(parent)

        self.dialog_title = title
        self.title(title)
        self.geometry("820x700")
        self.resizable(False, False)
        self.configure(bg=self.BG)
        self.transient(parent)
        self.grab_set()

        self.result = None
        self.password_visible = False

        initial = data or {
            "title": "",
            "username": "",
            "password": "",
            "url": "",
            "category": "",
            "notes": "",
        }

        self.title_var = tk.StringVar(value=initial.get("title", ""))
        self.username_var = tk.StringVar(value=initial.get("username", ""))
        self.password_var = tk.StringVar(value=initial.get("password", ""))
        self.url_var = tk.StringVar(value=initial.get("url", ""))
        self.category_var = tk.StringVar(value=initial.get("category", ""))

        self._build_ui()

        self.notes_text.insert("1.0", initial.get("notes", ""))

        self.password_var.trace_add("write", self.update_strength)
        self.update_strength()

        self._center(parent)
        self.title_entry.focus_set()
        self.bind("<Escape>", lambda _event: self.destroy())

    def _build_ui(self):
        outer = tk.Frame(self, bg=self.BG, padx=24, pady=24)
        outer.pack(fill="both", expand=True)

        card = tk.Frame(
            outer,
            bg=self.CARD,
            highlightthickness=1,
            highlightbackground=self.BORDER,
            highlightcolor=self.BORDER,
        )
        card.pack(fill="both", expand=True)

        header = tk.Frame(card, bg=self.CARD, padx=26, pady=22)
        header.pack(fill="x")

        tk.Label(
            header,
            text="🗝",
            fg=self.TEXT,
            bg=self.CARD,
            font=(self.FONT, 24),
        ).pack(side="left", padx=(0, 14))

        title_box = tk.Frame(header, bg=self.CARD)
        title_box.pack(side="left", fill="x", expand=True)

        tk.Label(
            title_box,
            text=self.dialog_title,
            fg=self.TEXT,
            bg=self.CARD,
            font=(self.FONT, 20, "bold"),
        ).pack(anchor="w")

        tk.Label(
            title_box,
            text="Сохрани логин, пароль, ссылку и заметки в защищённом хранилище",
            fg=self.MUTED,
            bg=self.CARD,
            font=(self.FONT, 10),
        ).pack(anchor="w", pady=(5, 0))

        tk.Frame(card, bg=self.BORDER, height=1).pack(fill="x")

        container = tk.Frame(card, bg=self.CARD, padx=26, pady=24)
        container.pack(fill="both", expand=True)

        container.columnconfigure(0, weight=0, minsize=135)
        container.columnconfigure(1, weight=1)

        self._make_label(container, "Название *", 0)
        self.title_entry = self._make_entry(container, self.title_var, 0)

        self._make_label(container, "Логин", 1)
        self.username_entry = self._make_entry(container, self.username_var, 1)

        self._make_label(container, "Пароль *", 2)
        self._build_password_row(container, 2)

        self.strength_label = tk.Label(
            container,
            text="",
            fg=self.MUTED,
            bg=self.CARD,
            font=(self.FONT, 10),
            anchor="w",
        )
        self.strength_label.grid(row=3, column=1, sticky="w", pady=(0, 16))

        self._make_label(container, "URL", 4)
        self.url_entry = self._make_entry(container, self.url_var, 4)

        self._make_label(container, "Категория", 5)
        self.category_entry = self._make_entry(container, self.category_var, 5)

        self._make_label(container, "Заметки", 6)
        self.notes_text = tk.Text(
            container,
            height=7,
            font=(self.FONT, 12),
            bg=self.INPUT_BG,
            fg=self.TEXT,
            insertbackground=self.TEXT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=self.BORDER,
            highlightcolor=self.PURPLE,
            wrap="word",
        )
        self.notes_text.grid(row=6, column=1, sticky="ew", pady=(0, 24))
        self.notes_text.bind("<FocusIn>", lambda _event: self.notes_text.config(highlightbackground=self.PURPLE))
        self.notes_text.bind("<FocusOut>", lambda _event: self.notes_text.config(highlightbackground=self.BORDER))

        btn_wrap = tk.Frame(container, bg=self.CARD)
        btn_wrap.grid(row=7, column=0, columnspan=2, sticky="e")

        self.cancel_btn = self._button(
            btn_wrap,
            text="Отмена",
            command=self.destroy,
            bg="#242733",
            hover="#303443",
            width=12,
        )
        self.cancel_btn.pack(side="left", padx=(0, 10))

        self.save_btn = self._button(
            btn_wrap,
            text="Сохранить",
            command=self.on_save,
            bg=self.PURPLE,
            hover=self.PURPLE_HOVER,
            width=14,
            bold=True,
        )
        self.save_btn.pack(side="left")

    def _build_password_row(self, parent, row):
        password_wrap = tk.Frame(parent, bg=self.CARD)
        password_wrap.grid(row=row, column=1, sticky="ew", pady=(0, 6))
        password_wrap.columnconfigure(0, weight=1)
        password_wrap.columnconfigure(1, weight=0)
        password_wrap.columnconfigure(2, weight=0)

        self.password_entry = tk.Entry(
            password_wrap,
            textvariable=self.password_var,
            font=(self.FONT, 12),
            bg=self.INPUT_BG,
            fg=self.TEXT,
            insertbackground=self.TEXT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=self.BORDER,
            highlightcolor=self.PURPLE,
            show="*",
        )
        self.password_entry.grid(row=0, column=0, sticky="ew", ipady=11)
        self.password_entry.bind("<FocusIn>", lambda _event: self.password_entry.config(highlightbackground=self.PURPLE))
        self.password_entry.bind("<FocusOut>", lambda _event: self.password_entry.config(highlightbackground=self.BORDER))

        self.show_btn = self._icon_button(
            password_wrap,
            text="👁",
            command=self.toggle_password,
        )
        self.show_btn.grid(row=0, column=1, padx=(8, 6), sticky="ns")

        self.generate_btn = self._icon_button(
            password_wrap,
            text="⚙",
            command=self.open_generator,
        )
        self.generate_btn.grid(row=0, column=2, sticky="ns")

    def _make_label(self, parent, text, row):
        lbl = tk.Label(
            parent,
            text=text,
            fg=self.TEXT,
            bg=self.CARD,
            font=(self.FONT, 11, "bold"),
            anchor="w",
        )
        lbl.grid(row=row, column=0, sticky="w", padx=(0, 24), pady=(0, 16))
        return lbl

    def _make_entry(self, parent, var, row):
        ent = tk.Entry(
            parent,
            textvariable=var,
            font=(self.FONT, 12),
            bg=self.INPUT_BG,
            fg=self.TEXT,
            insertbackground=self.TEXT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=self.BORDER,
            highlightcolor=self.PURPLE,
        )
        ent.grid(row=row, column=1, sticky="ew", pady=(0, 16), ipady=11)
        ent.bind("<FocusIn>", lambda _event: ent.config(highlightbackground=self.PURPLE))
        ent.bind("<FocusOut>", lambda _event: ent.config(highlightbackground=self.BORDER))
        return ent

    def _button(self, parent, text, command, bg, hover, width=12, bold=False):
        btn = tk.Label(
            parent,
            text=text,
            font=(self.FONT, 11, "bold" if bold else "normal"),
            bg=bg,
            fg=self.TEXT,
            width=width,
            pady=12,
            cursor="hand2",
            anchor="center",
        )
        btn.default_bg = bg
        btn.hover_bg = hover
        btn.command = command
        btn.is_disabled = False

        btn.bind("<Button-1>", lambda _event: None if btn.is_disabled else btn.command())
        btn.bind("<Enter>", lambda _event: None if btn.is_disabled else btn.config(bg=btn.hover_bg))
        btn.bind("<Leave>", lambda _event: None if btn.is_disabled else btn.config(bg=btn.default_bg))
        return btn

    def _icon_button(self, parent, text, command):
        btn = tk.Label(
            parent,
            text=text,
            font=(self.FONT, 12),
            bg=self.CARD_LIGHT,
            fg=self.TEXT,
            width=4,
            cursor="hand2",
            anchor="center",
        )
        btn.default_bg = self.CARD_LIGHT
        btn.hover_bg = "#2A2E3D"
        btn.command = command
        btn.is_disabled = False

        btn.bind("<Button-1>", lambda _event: None if btn.is_disabled else btn.command())
        btn.bind("<Enter>", lambda _event: None if btn.is_disabled else btn.config(bg=btn.hover_bg))
        btn.bind("<Leave>", lambda _event: None if btn.is_disabled else btn.config(bg=btn.default_bg))
        return btn

    def _center(self, parent):
        self.update_idletasks()
        parent_width = max(parent.winfo_width(), 1)
        parent_height = max(parent.winfo_height(), 1)
        x = parent.winfo_rootx() + (parent_width // 2) - (self.winfo_width() // 2)
        y = parent.winfo_rooty() + (parent_height // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{x}+{y}")

    def toggle_password(self):
        self.password_visible = not self.password_visible
        self.password_entry.config(show="" if self.password_visible else "*")
        self.show_btn.config(text="🙈" if self.password_visible else "👁")

    def open_generator(self):
        dlg = PasswordGeneratorDialog(self)
        self.wait_window(dlg)
        if dlg.result:
            self.password_var.set(dlg.result)

    def update_strength(self, *args):
        password = self.password_var.get()
        score = 0

        if len(password) >= 8:
            score += 1
        if re.search(r"[a-z]", password):
            score += 1
        if re.search(r"[A-Z]", password):
            score += 1
        if re.search(r"\d", password):
            score += 1
        if re.search(r"[!@#$%^&*()_+\-=\[\]{};:,.<>?/\\|]", password):
            score += 1

        if not password:
            self.strength_label.config(text="")
        elif score <= 2:
            self.strength_label.config(text="Надёжность: слабый", fg=self.DANGER)
        elif score <= 4:
            self.strength_label.config(text="Надёжность: средний", fg=self.WARNING)
        else:
            self.strength_label.config(text="Надёжность: сильный", fg=self.SUCCESS)

    def is_password_strong(self, password: str) -> bool:
        score = 0
        if len(password) >= 8:
            score += 1
        if re.search(r"[a-z]", password):
            score += 1
        if re.search(r"[A-Z]", password):
            score += 1
        if re.search(r"\d", password):
            score += 1
        if re.search(r"[!@#$%^&*()_+\-=\[\]{};:,.<>?/\\|]", password):
            score += 1
        return score >= 4

    def validate_url(self, url: str) -> bool:
        if not url:
            return True
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)

    def normalize_url_for_favicon(self, url: str) -> str:
        url = url.strip()
        if not url:
            return ""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url

    def on_save(self):
        title = self.title_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        url = self.url_var.get().strip()
        category = self.category_var.get().strip()
        notes = self.notes_text.get("1.0", "end").strip()

        if not title:
            messagebox.showerror("Ошибка", "Введите название записи", parent=self)
            self.title_entry.focus_set()
            return

        if not password:
            messagebox.showerror("Ошибка", "Введите пароль", parent=self)
            self.password_entry.focus_set()
            return

        if not self.is_password_strong(password):
            messagebox.showerror("Ошибка", "Пароль слишком слабый", parent=self)
            self.password_entry.focus_set()
            return

        if url:
            normalized_url = self.normalize_url_for_favicon(url)
            if not self.validate_url(normalized_url):
                messagebox.showerror(
                    "Ошибка",
                    "URL должен начинаться с http:// или https:// и содержать домен",
                    parent=self,
                )
                self.url_entry.focus_set()
                return
            url = normalized_url

        try:
            url = clean_url(url) if url else ""
        except Exception:
            messagebox.showerror("Ошибка", "Некорректный URL", parent=self)
            self.url_entry.focus_set()
            return

        self.result = {
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "category": category,
            "notes": notes,
        }
        self.destroy()
