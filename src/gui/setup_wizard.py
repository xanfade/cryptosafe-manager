import tkinter as tk
from tkinter import filedialog, messagebox


class SetupWizard(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)

        self.result = None

        self.title("Создание мастер-пароля")
        self.geometry("500x470")
        self.resizable(False, False)
        self.configure(bg="#f3f3f3")

        self.pass1_var = tk.StringVar()
        self.pass2_var = tk.StringVar()
        self.db_path = tk.StringVar(value="app.db")
        self.iterations = tk.StringVar(value="100000")

        self._center_window()
        self._build_ui()

        self.grab_set()
        self.lift()
        self.attributes("-topmost", True)
        self.after(100, lambda: self.attributes("-topmost", False))

    def _center_window(self):
        self.update_idletasks()
        width = 500
        height = 470
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _build_ui(self):
        outer = tk.Frame(self, bg="#f3f3f3")
        outer.pack(fill="both", expand=True, padx=18, pady=18)

        card = tk.Frame(outer, bg="#ffffff", bd=0, highlightthickness=0)
        card.pack(fill="both", expand=True)

        content = tk.Frame(card, bg="#ffffff")
        content.pack(fill="both", expand=True, padx=28, pady=24)

        title = tk.Label(
            content,
            text="Настройка хранилища",
            font=("Arial", 16, "bold"),
            bg="#ffffff",
            fg="#111111"
        )
        title.pack(anchor="w")

        subtitle = tk.Label(
            content,
            text="Создайте мастер-пароль и выберите параметры базы данных",
            font=("Arial", 10),
            bg="#ffffff",
            fg="#666666"
        )
        subtitle.pack(anchor="w", pady=(6, 18))

        self.pass1_entry = self._add_labeled_entry(
            content, "Мастер-пароль", self.pass1_var, show="*"
        )
        self.pass2_entry = self._add_labeled_entry(
            content, "Подтверждение пароля", self.pass2_var, show="*"
        )

        db_label = tk.Label(
            content,
            text="Расположение базы данных",
            font=("Arial", 10),
            bg="#ffffff",
            fg="#111111"
        )
        db_label.pack(anchor="w", pady=(0, 6))

        db_row = tk.Frame(content, bg="#ffffff")
        db_row.pack(fill="x", pady=(0, 14))

        self.db_entry = tk.Entry(
            db_row,
            textvariable=self.db_path,
            font=("Arial", 11),
            bg="#f7f7f7",
            fg="#111111",
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground="#d8d8d8",
            highlightcolor="#d8d8d8",
            insertbackground="#111111"
        )
        self.db_entry.pack(side="left", fill="x", expand=True, ipady=10, padx=(0, 10))

        choose_btn = tk.Button(
            db_row,
            text="Выбрать",
            command=self.choose_db,
            font=("Arial", 10),
            bg="#ebebeb",
            fg="#111111",
            relief="flat",
            bd=0,
            activebackground="#dfdfdf",
            activeforeground="#111111",
            cursor="hand2",
            width=11,
            pady=10
        )
        choose_btn.pack(side="right")

        self.iter_entry = self._add_labeled_entry(content, "Итерации", self.iterations)

        bottom = tk.Frame(content, bg="#ffffff")
        bottom.pack(fill="x", pady=(8, 0))

        create_btn = self._create_modern_button(
            bottom,
            text="Создать",
            command=self.finish
        )
        create_btn.pack(fill="x")

    def _add_labeled_entry(self, parent, text, variable, show=None):
        label = tk.Label(
            parent,
            text=text,
            font=("Arial", 10),
            bg="#ffffff",
            fg="#111111"
        )
        label.pack(anchor="w", pady=(0, 6))

        entry = tk.Entry(
            parent,
            textvariable=variable,
            show=show,
            font=("Arial", 11),
            bg="#f7f7f7",
            fg="#111111",
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground="#d8d8d8",
            highlightcolor="#d8d8d8",
            insertbackground="#111111"
        )
        entry.pack(fill="x", ipady=10, pady=(0, 14))
        return entry

    def _create_modern_button(self, parent, text, command):
        outer = tk.Frame(parent, bg="#111111", height=46, cursor="hand2")
        outer.pack_propagate(False)

        label = tk.Label(
            outer,
            text=text,
            bg="#111111",
            fg="#ffffff",
            font=("Arial", 11, "bold"),
            cursor="hand2"
        )
        label.pack(expand=True, fill="both")

        def on_enter(event):
            outer.configure(bg="#1f1f1f")
            label.configure(bg="#1f1f1f")

        def on_leave(event):
            outer.configure(bg="#111111")
            label.configure(bg="#111111")

        def on_press(event):
            outer.configure(bg="#2a2a2a")
            label.configure(bg="#2a2a2a")

        def on_release(event):
            if self.winfo_exists():
                outer.configure(bg="#1f1f1f")
                label.configure(bg="#1f1f1f")
                command()

        for widget in (outer, label):
            widget.bind("<Enter>", on_enter)
            widget.bind("<Leave>", on_leave)
            widget.bind("<ButtonPress-1>", on_press)
            widget.bind("<ButtonRelease-1>", on_release)

        return outer

    def choose_db(self):
        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".db",
            filetypes=[("SQLite DB", "*.db")]
        )
        if path:
            self.db_path.set(path)

    def finish(self):
        password1 = self.pass1_var.get()
        password2 = self.pass2_var.get()
        db_path = self.db_path.get().strip()
        iterations_text = self.iterations.get().strip()

        if not password1:
            messagebox.showerror("Ошибка", "Введите мастер-пароль", parent=self)
            return

        if password1 != password2:
            messagebox.showerror("Ошибка", "Пароли не совпадают", parent=self)
            return

        if len(password1) < 8:
            messagebox.showerror("Ошибка", "Пароль должен быть не меньше 8 символов", parent=self)
            return

        if not db_path:
            messagebox.showerror("Ошибка", "Укажите путь к базе данных", parent=self)
            return

        try:
            iterations = int(iterations_text)
        except ValueError:
            messagebox.showerror("Ошибка", "Итерации должны быть числом", parent=self)
            return

        if iterations < 10000:
            messagebox.showerror("Ошибка", "Количество итераций должно быть не меньше 10000", parent=self)
            return

        self.result = {
            "master_password": password1,
            "db_path": db_path,
            "iterations": iterations,
        }

        self.destroy()