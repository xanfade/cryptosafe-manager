import tkinter as tk
from tkinter import filedialog, messagebox


class SetupWizard(tk.Toplevel):
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

    FONT = "Arial"

    def __init__(self, parent):
        super().__init__(parent)

        self.result = None
        self.passwords_visible = False

        self.title("Создание мастер-пароля")
        self.geometry("560x660")
        self.resizable(False, False)
        self.configure(bg=self.BG)

        self.pass1_var = tk.StringVar()
        self.pass2_var = tk.StringVar()
        self.db_path = tk.StringVar(value="app.db")
        self.iterations = tk.StringVar(value="100000")
        self.show_passwords_var = tk.BooleanVar(value=False)

        self._center_window()
        self._build_ui()

        self.grab_set()
        self.lift()
        self.attributes("-topmost", True)
        self.after(100, lambda: self.attributes("-topmost", False))

        self.pass1_entry.focus_set()
        self.bind("<Escape>", lambda _event: self.destroy())
        self.bind("<Return>", lambda _event: self.finish())

    def _center_window(self):
        self.update_idletasks()
        width = 560
        height = 660
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _build_ui(self):
        outer = tk.Frame(self, bg=self.BG, padx=22, pady=22)
        outer.pack(fill="both", expand=True)

        card = tk.Frame(
            outer,
            bg=self.CARD,
            highlightthickness=1,
            highlightbackground=self.BORDER,
            highlightcolor=self.BORDER,
        )
        card.pack(fill="both", expand=True)

        header = tk.Frame(card, bg=self.CARD, padx=26, pady=20)
        header.pack(fill="x")

        tk.Label(
            header,
            text="🔐",
            font=(self.FONT, 24),
            bg=self.CARD,
            fg=self.TEXT,
        ).pack(side="left", padx=(0, 14))

        title_box = tk.Frame(header, bg=self.CARD)
        title_box.pack(side="left", fill="x", expand=True)

        tk.Label(
            title_box,
            text="Настройка хранилища",
            font=(self.FONT, 20, "bold"),
            bg=self.CARD,
            fg=self.TEXT,
        ).pack(anchor="w")

        tk.Label(
            title_box,
            text="Создайте мастер-пароль и выберите параметры базы данных",
            font=(self.FONT, 10),
            bg=self.CARD,
            fg=self.MUTED,
        ).pack(anchor="w", pady=(5, 0))

        tk.Frame(card, bg=self.BORDER, height=1).pack(fill="x")

        content = tk.Frame(card, bg=self.CARD, padx=26, pady=22)
        content.pack(fill="both", expand=True)

        self.pass1_entry = self._add_labeled_entry(
            content,
            "Мастер-пароль",
            self.pass1_var,
            show="*",
        )
        self.pass2_entry = self._add_labeled_entry(
            content,
            "Подтверждение пароля",
            self.pass2_var,
            show="*",
        )

        self._build_password_tools(content)
        self._build_hint_box(content)
        self._build_db_path_block(content)

        self.iter_entry = self._add_labeled_entry(
            content,
            "Итерации KDF",
            self.iterations,
        )

        bottom = tk.Frame(content, bg=self.CARD)
        bottom.pack(fill="x", pady=(14, 0))

        self.create_btn = self._create_custom_button(
            bottom,
            text="Создать хранилище",
            command=self.finish,
            bg=self.PURPLE,
            hover=self.PURPLE_HOVER,
            height=50,
            bold=True,
        )
        self.create_btn.pack(fill="x")

    def _build_password_tools(self, parent):
        row = tk.Frame(parent, bg=self.CARD)
        row.pack(fill="x", pady=(0, 12))

        self.show_passwords_check = tk.Checkbutton(
            row,
            text="Показать пароли",
            variable=self.show_passwords_var,
            command=self._toggle_password_visibility,
            font=(self.FONT, 10),
            bg=self.CARD,
            fg=self.MUTED,
            activebackground=self.CARD,
            activeforeground=self.TEXT,
            selectcolor=self.CARD_LIGHT,
            relief="flat",
            bd=0,
            cursor="hand2",
        )
        self.show_passwords_check.pack(anchor="w")

    def _build_hint_box(self, parent):
        box = tk.Frame(
            parent,
            bg=self.CARD_LIGHT,
            highlightthickness=1,
            highlightbackground=self.BORDER,
            highlightcolor=self.BORDER,
            padx=12,
            pady=10,
        )
        box.pack(fill="x", pady=(0, 16))

        tk.Label(
            box,
            text="Требования к мастер-паролю",
            font=(self.FONT, 10, "bold"),
            bg=self.CARD_LIGHT,
            fg=self.TEXT,
        ).pack(anchor="w")

        tk.Label(
            box,
            text="Минимум 12 символов, заглавная и строчная буква, цифра и спецсимвол",
            font=(self.FONT, 9),
            bg=self.CARD_LIGHT,
            fg=self.MUTED,
            wraplength=450,
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

    def _build_db_path_block(self, parent):
        label = tk.Label(
            parent,
            text="Расположение базы данных",
            font=(self.FONT, 10, "bold"),
            bg=self.CARD,
            fg=self.TEXT,
        )
        label.pack(anchor="w", pady=(0, 7))

        db_row = tk.Frame(parent, bg=self.CARD)
        db_row.pack(fill="x", pady=(0, 14))

        self.db_entry = tk.Entry(
            db_row,
            textvariable=self.db_path,
            font=(self.FONT, 11),
            bg=self.INPUT_BG,
            fg=self.TEXT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=self.BORDER,
            highlightcolor=self.PURPLE,
            insertbackground=self.TEXT,
        )
        self.db_entry.pack(side="left", fill="x", expand=True, ipady=11, padx=(0, 10))
        self.db_entry.bind("<FocusIn>", lambda _event: self.db_entry.config(highlightbackground=self.PURPLE))
        self.db_entry.bind("<FocusOut>", lambda _event: self.db_entry.config(highlightbackground=self.BORDER))

        self.choose_btn = self._create_custom_button(
            db_row,
            text="Выбрать",
            command=self.choose_db,
            bg=self.CARD_LIGHT,
            hover="#2A2E3D",
            width=100,
            height=43,
        )
        self.choose_btn.pack(side="right")

    def _add_labeled_entry(self, parent, text, variable, show=None):
        label = tk.Label(
            parent,
            text=text,
            font=(self.FONT, 10, "bold"),
            bg=self.CARD,
            fg=self.TEXT,
        )
        label.pack(anchor="w", pady=(0, 7))

        entry = tk.Entry(
            parent,
            textvariable=variable,
            show=show,
            font=(self.FONT, 11),
            bg=self.INPUT_BG,
            fg=self.TEXT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=self.BORDER,
            highlightcolor=self.PURPLE,
            insertbackground=self.TEXT,
        )
        entry.pack(fill="x", ipady=11, pady=(0, 14))
        entry.bind("<FocusIn>", lambda _event: entry.config(highlightbackground=self.PURPLE))
        entry.bind("<FocusOut>", lambda _event: entry.config(highlightbackground=self.BORDER))
        return entry

    def _create_custom_button(
        self,
        parent,
        text,
        command,
        bg,
        hover,
        width=None,
        height=46,
        bold=False,
    ):
        outer = tk.Frame(parent, bg=bg, height=height, cursor="hand2")
        if width:
            outer.configure(width=width)
        outer.pack_propagate(False)

        label = tk.Label(
            outer,
            text=text,
            bg=bg,
            fg=self.TEXT,
            font=(self.FONT, 11, "bold" if bold else "normal"),
            cursor="hand2",
        )
        label.pack(expand=True, fill="both")

        outer.default_bg = bg
        outer.hover_bg = hover
        outer.command = command

        def paint(color):
            outer.configure(bg=color)
            label.configure(bg=color)

        def on_enter(_event):
            paint(outer.hover_bg)

        def on_leave(_event):
            paint(outer.default_bg)

        def on_press(_event):
            paint(self.PURPLE_DARK if outer.default_bg == self.PURPLE else "#34394A")

        def on_release(_event):
            if self.winfo_exists():
                paint(outer.hover_bg)
                outer.command()

        for widget in (outer, label):
            widget.bind("<Enter>", on_enter)
            widget.bind("<Leave>", on_leave)
            widget.bind("<ButtonPress-1>", on_press)
            widget.bind("<ButtonRelease-1>", on_release)

        return outer

    def _toggle_password_visibility(self):
        self.passwords_visible = bool(self.show_passwords_var.get())
        show_value = "" if self.passwords_visible else "*"
        self.pass1_entry.config(show=show_value)
        self.pass2_entry.config(show=show_value)

    def choose_db(self):
        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".db",
            filetypes=[("SQLite DB", "*.db")],
        )
        if path:
            self.db_path.set(path)

    def finish(self):
        password = self.pass1_var.get().strip()
        confirm_password = self.pass2_var.get().strip()
        db_path = self.db_path.get().strip()

        if not password or not confirm_password:
            messagebox.showerror("Ошибка", "Заполните оба поля пароля", parent=self)
            return

        if password != confirm_password:
            messagebox.showerror("Ошибка", "Пароли не совпадают", parent=self)
            return

        if not db_path:
            messagebox.showerror("Ошибка", "Укажите путь к базе данных", parent=self)
            return

        try:
            from src.core.crypto.authentication import validate_password_strength
            validate_password_strength(password)
        except Exception as e:
            messagebox.showerror("Ошибка", str(e), parent=self)
            return

        self.result = {
            "db_path": db_path,
            "master_password": password,
        }

        self.destroy()
