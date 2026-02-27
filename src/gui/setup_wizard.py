import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


class SetupWizard(tk.Toplevel):
    

    def __init__(self, master=None):
        super().__init__(master)
        self.title("Первоначальная настройка")
        self.geometry("520x340")
        self.resizable(False, False)

        # Результат работы мастера (если None — значит отмена)
        self.result = None

        # Переменные
        self.db_path_var = tk.StringVar(value=os.path.abspath("app.db"))
        self.iter_var = tk.StringVar(value="100000")  # заглушка параметра KDF

        # UI
        wrapper = ttk.Frame(self, padding=16)
        wrapper.pack(fill="both", expand=True)

        ttk.Label(wrapper, text="Мастер первоначальной настройки", font=("Segoe UI", 12, "bold")).pack(anchor="w")

        # --- Путь к БД ---
        ttk.Label(wrapper, text="Расположение базы данных:").pack(anchor="w", pady=(14, 4))
        row_db = ttk.Frame(wrapper)
        row_db.pack(fill="x")

        ttk.Entry(row_db, textvariable=self.db_path_var).pack(side="left", fill="x", expand=True)
        ttk.Button(row_db, text="Выбрать…", command=self.pick_db_path).pack(side="left", padx=(8, 0))

        # --- Пароль ---
        ttk.Label(wrapper, text="Мастер-пароль:").pack(anchor="w", pady=(14, 4))
        self.pass1 = ttk.Entry(wrapper, show="*")
        self.pass1.pack(fill="x")

        ttk.Label(wrapper, text="Подтверждение пароля:").pack(anchor="w", pady=(10, 4))
        self.pass2 = ttk.Entry(wrapper, show="*")
        self.pass2.pack(fill="x")

        # --- Параметры шифрования (заглушка) ---
        ttk.Label(wrapper, text="Настройки шифрования (заглушка):").pack(anchor="w", pady=(14, 4))
        row_kdf = ttk.Frame(wrapper)
        row_kdf.pack(fill="x")
        ttk.Label(row_kdf, text="Iterations:").pack(side="left")
        ttk.Entry(row_kdf, textvariable=self.iter_var, width=12).pack(side="left", padx=(8, 0))

        ttk.Label(
            wrapper,
            text="(здесь будут реальные параметры KDF/шифрования)",
            foreground="gray"
        ).pack(anchor="w", pady=(4, 0))

        # --- Кнопки ---
        btns = ttk.Frame(wrapper)
        btns.pack(fill="x", pady=(18, 0))

        ttk.Button(btns, text="Отмена", command=self.cancel).pack(side="right")
        ttk.Button(btns, text="Создать", command=self.finish).pack(side="right", padx=(0, 8))

        self.protocol("WM_DELETE_WINDOW", self.cancel)

        # Делаем окно модальным
        self.transient(master)
        self.grab_set()

    def pick_db_path(self):
        path = filedialog.asksaveasfilename(
            title="Выбор файла базы данных",
            defaultextension=".db",
            filetypes=[("SQLite DB", "*.db"), ("All files", "*.*")],
            initialfile="app.db",
        )
        if path:
            self.db_path_var.set(path)

    def cancel(self):
        self.result = None
        self.destroy()

    def finish(self):
        # --- Валидация (SEC-2 минимум) ---
        db_path = (self.db_path_var.get() or "").strip()
        p1 = (self.pass1.get() or "").strip()
        p2 = (self.pass2.get() or "").strip()
        it = (self.iter_var.get() or "").strip()

        if not db_path:
            messagebox.showerror("Ошибка", "Укажите путь к базе данных.")
            return

        if not p1 or not p2:
            messagebox.showerror("Ошибка", "Пароль и подтверждение обязательны.")
            return

        if p1 != p2:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            return

        if not it.isdigit() or int(it) <= 0:
            messagebox.showerror("Ошибка", "Iterations должны быть положительным числом.")
            return

        # Готово: возвращаем результат наверх в __main__.py
        self.result = {
            "db_path": db_path,
            "master_password": p1,   # Важно: дальше мы НЕ сохраняем пароль в конфиг!
            "iterations": int(it),
        }
        self.destroy()
