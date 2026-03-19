import tkinter as tk
from tkinter import messagebox


class LoginDialog(tk.Toplevel):
    def __init__(self, parent, auth_service):
        super().__init__(parent)
        self.auth_service = auth_service
        self.result = False

        self.title("Вход в CryptoSafe Manager")
        self.geometry("400x180")
        self.resizable(False, False)

        tk.Label(self, text="Мастер-пароль").pack(pady=(20, 6))
        self.password = tk.Entry(self, show="*")
        self.password.pack(fill="x", padx=20)
        self.password.focus_set()

        tk.Button(self, text="Войти", command=self.do_login).pack(pady=20)

        self.grab_set()
        self.focus_force()

    def do_login(self):
        try:
            self.auth_service.login(self.password.get())
        except Exception as e:
            messagebox.showerror("Ошибка входа", str(e), parent=self)
            return

        self.result = True
        self.destroy()