import re
import tkinter as tk
from tkinter import messagebox
from urllib.parse import urlparse

from src.core.validators import clean_url
from src.core.vault.password_generator import PasswordGenerator


class PasswordGeneratorDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Генерация пароля")
        self.geometry("360x360")
        self.resizable(False, False)
        self.configure(bg="#1e1e1e")
        self.transient(parent)
        self.grab_set()

        self.result = None

        self.length = tk.IntVar(value=16)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_upper = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_special = tk.BooleanVar(value=True)

        frame = tk.Frame(self, bg="#1e1e1e", padx=20, pady=20)
        frame.pack(fill="both", expand=True)

        tk.Label(
            frame,
            text="Настройки генерации",
            fg="white",
            bg="#1e1e1e",
            font=("Arial", 14, "bold")
        ).pack(anchor="w", pady=(0, 15))

        tk.Label(
            frame,
            text="Длина пароля",
            fg="white",
            bg="#1e1e1e",
            font=("Arial", 11)
        ).pack(anchor="w")

        tk.Scale(
            frame,
            from_=8,
            to=64,
            orient="horizontal",
            variable=self.length,
            bg="#1e1e1e",
            fg="white",
            highlightthickness=0,
            troughcolor="#2a2a2a",
            activebackground="#2a2a2a",
        ).pack(fill="x", pady=(4, 16))

        self._make_check(frame, "Строчные a-z", self.use_lower)
        self._make_check(frame, "Заглавные A-Z", self.use_upper)
        self._make_check(frame, "Цифры 0-9", self.use_digits)
        self._make_check(frame, "Спецсимволы !@#$%^&*", self.use_special)

        buttons = tk.Frame(frame, bg="#1e1e1e")
        buttons.pack(fill="x", pady=(24, 0))

        tk.Button(
            buttons,
            text="Отмена",
            command=self.destroy,
            bg="#2a2a2a",
            fg="white",
            relief="flat",
            bd=0,
            activebackground="#353535",
            activeforeground="white",
            padx=18,
            pady=10,
            cursor="hand2",
        ).pack(side="left")

        tk.Button(
            buttons,
            text="Сгенерировать",
            command=self.generate,
            bg="#2f2f2f",
            fg="white",
            relief="flat",
            bd=0,
            activebackground="#404040",
            activeforeground="white",
            padx=18,
            pady=10,
            cursor="hand2",
        ).pack(side="right")

    def _make_check(self, parent, text, variable):
        tk.Checkbutton(
            parent,
            text=text,
            variable=variable,
            bg="#1e1e1e",
            fg="white",
            selectcolor="#2a2a2a",
            activebackground="#1e1e1e",
            activeforeground="white",
            font=("Arial", 10),
            anchor="w",
        ).pack(anchor="w", pady=3)

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


class EntryDialog(tk.Toplevel):
    def __init__(self, parent, title="Добавить запись", data=None):
        super().__init__(parent)
        self.title(title)
        self.geometry("760x620")
        self.resizable(False, False)
        self.configure(bg="#1e1e1e")
        self.transient(parent)
        self.grab_set()

        self.result = None
        self.password_visible = False
        # self.favicon_image = None

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
        # self.url_entry.bind("<FocusOut>", self.on_url_focus_out)

        self.update_strength()

        # if self.url_var.get().strip():
        #     self.after(150, self.try_load_favicon)

    def _build_ui(self):
        container = tk.Frame(self, bg="#1e1e1e", padx=30, pady=24)
        container.pack(fill="both", expand=True)

        container.columnconfigure(0, weight=0, minsize=130)
        container.columnconfigure(1, weight=1)

        label_font = ("Arial", 12, "bold")
        entry_font = ("Arial", 12)

        def make_label(text, row):
            lbl = tk.Label(
                container,
                text=text,
                fg="white",
                bg="#1e1e1e",
                font=label_font,
                anchor="w",
            )
            lbl.grid(row=row, column=0, sticky="w", padx=(0, 24), pady=(0, 16))
            return lbl

        def make_entry(var, row):
            ent = tk.Entry(
                container,
                textvariable=var,
                font=entry_font,
                bg="#2a2a2a",
                fg="white",
                insertbackground="white",
                relief="flat",
                bd=0,
                highlightthickness=1,
                highlightbackground="#3a3a3a",
                highlightcolor="#5a5a5a",
            )
            ent.grid(row=row, column=1, sticky="ew", pady=(0, 16), ipady=11)
            return ent

        make_label("Название *", 0)
        self.title_entry = make_entry(self.title_var, 0)

        make_label("Логин", 1)
        self.username_entry = make_entry(self.username_var, 1)

        make_label("Пароль *", 2)

        password_wrap = tk.Frame(container, bg="#1e1e1e")
        password_wrap.grid(row=2, column=1, sticky="ew", pady=(0, 6))
        password_wrap.columnconfigure(0, weight=1)
        password_wrap.columnconfigure(1, weight=0)
        password_wrap.columnconfigure(2, weight=0)

        self.password_entry = tk.Entry(
            password_wrap,
            textvariable=self.password_var,
            font=entry_font,
            bg="#2a2a2a",
            fg="white",
            insertbackground="white",
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground="#3a3a3a",
            highlightcolor="#5a5a5a",
            show="*",
        )
        self.password_entry.grid(row=0, column=0, sticky="ew", ipady=11)

        self.show_btn = tk.Button(
            password_wrap,
            text="👁",
            command=self.toggle_password,
            width=3,
            bg="#2a2a2a",
            fg="white",
            relief="flat",
            bd=0,
            font=("Arial", 11),
            activebackground="#353535",
            activeforeground="white",
            cursor="hand2",
        )
        self.show_btn.grid(row=0, column=1, padx=(8, 6), sticky="ns")

        self.generate_btn = tk.Button(
            password_wrap,
            text="⚙",
            command=self.open_generator,
            width=3,
            bg="#2a2a2a",
            fg="white",
            relief="flat",
            bd=0,
            font=("Arial", 11),
            activebackground="#353535",
            activeforeground="white",
            cursor="hand2",
        )
        self.generate_btn.grid(row=0, column=2, sticky="ns")

        self.strength_label = tk.Label(
            container,
            text="",
            fg="#aaaaaa",
            bg="#1e1e1e",
            font=("Arial", 10),
            anchor="w",
        )
        self.strength_label.grid(row=3, column=1, sticky="w", pady=(0, 16))

        make_label("URL", 4)
        self.url_entry = make_entry(self.url_var, 4)

        make_label("Категория", 5)
        self.category_entry = make_entry(self.category_var, 5)

        make_label("Заметки", 6)

        self.notes_text = tk.Text(
            container,
            height=7,
            font=entry_font,
            bg="#2a2a2a",
            fg="white",
            insertbackground="white",
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground="#3a3a3a",
            highlightcolor="#5a5a5a",
            wrap="word",
        )
        self.notes_text.grid(row=6, column=1, sticky="ew", pady=(0, 24))

        btn_wrap = tk.Frame(container, bg="#1e1e1e")
        btn_wrap.grid(row=7, column=0, columnspan=2, sticky="e")

        self.save_btn = tk.Button(
            btn_wrap,
            text="Сохранить",
            command=self.on_save,
            bg="#2f2f2f",
            fg="white",
            relief="flat",
            bd=0,
            font=("Arial", 12, "bold"),
            activebackground="#404040",
            activeforeground="white",
            cursor="hand2",
            padx=26,
            pady=10,
        )
        self.save_btn.pack()

    def toggle_password(self):
        self.password_visible = not self.password_visible
        self.password_entry.config(show="" if self.password_visible else "*")

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
            self.strength_label.config(text="Надежность: слабый", fg="#ff5f56")
        elif score <= 4:
            self.strength_label.config(text="Надежность: средний", fg="#ffbd2e")
        else:
            self.strength_label.config(text="Надежность: сильный", fg="#27c93f")

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

    # def on_url_focus_out(self, event=None):
    #     self.try_load_favicon()

    # def clear_favicon(self):
    #     self.favicon_image = None

    # def try_load_favicon(self):
    #     pass

    # def load_favicon_from_url(self, favicon_url: str) -> bool:
    #     return False

    def on_save(self):
        title = self.title_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        url = self.url_var.get().strip()
        category = self.category_var.get().strip()
        notes = self.notes_text.get("1.0", "end").strip()

        if not title:
            messagebox.showerror("Ошибка", "Введите название записи")
            self.title_entry.focus_set()
            return

        if not password:
            messagebox.showerror("Ошибка", "Введите пароль")
            self.password_entry.focus_set()
            return

        if not self.is_password_strong(password):
            messagebox.showerror("Ошибка", "Пароль слишком слабый")
            self.password_entry.focus_set()
            return

        if url:
            normalized_url = self.normalize_url_for_favicon(url)
            if not self.validate_url(normalized_url):
                messagebox.showerror(
                    "Ошибка",
                    "URL должен начинаться с http:// или https:// и содержать домен"
                )
                self.url_entry.focus_set()
                return
            url = normalized_url

        try:
            url = clean_url(url) if url else ""
        except Exception:
            messagebox.showerror("Ошибка", "Некорректный URL")
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