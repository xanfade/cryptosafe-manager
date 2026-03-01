import tkinter as tk
from tkinter import filedialog, messagebox


class SetupWizard(tk.Toplevel):


    def __init__(self, parent):
        super().__init__(parent)

        self.result = None

        self.title("Создание мастер-пароля")
        self.geometry("400x300")
        self.resizable(False, False)

        # Мастер-пароль
        tk.Label(self, text="Мастер-пароль").pack(pady=5)
        self.pass1 = tk.Entry(self, show="*")
        self.pass1.pack(fill="x", padx=20)

        tk.Label(self, text="Подтверждение пароля").pack(pady=5)
        self.pass2 = tk.Entry(self, show="*")
        self.pass2.pack(fill="x", padx=20)

        # Путь ДБ
        tk.Label(self, text="Расположение базы данных").pack(pady=5)

        frame = tk.Frame(self)
        frame.pack(fill="x", padx=20)

        self.db_path = tk.StringVar(value="app.db")
        tk.Entry(frame, textvariable=self.db_path).pack(
            side="left", fill="x", expand=True
        )

        tk.Button(frame, text="Выбрать", command=self.choose_db).pack(side="right")

        # Итерации
        tk.Label(self, text="Итерации").pack(pady=5)
        self.iterations = tk.IntVar(value=100000)
        tk.Entry(self, textvariable=self.iterations).pack(fill="x", padx=20)


        #Создание кнопки
        tk.Button(self, text="Создать", command=self.finish).pack(pady=15)

        self.grab_set()      # блокирует родительское окно
        self.focus_force()

    def choose_db(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".db",
            filetypes=[("SQLite DB", "*.db")]
        )
        if path:
            self.db_path.set(path)

    def finish(self):
        if self.pass1.get() != self.pass2.get():
            messagebox.showerror("Error", "Пароли не совпадают")
            return

        if len(self.pass1.get())<8:
            messagebox.showerror("Error", "Пароль меньше 8 символов")
            return

        if not self.pass1.get():
            messagebox.showerror("Error", "Неверный пароль")
            return

        self.result = {
            "db_path": self.db_path.get(),
            "iterations": self.iterations.get(),
        }

        self.destroy()

