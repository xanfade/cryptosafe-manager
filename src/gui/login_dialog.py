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
        self.configure(bg="#1e1e1e")

        tk.Label(
            self,
            text="Мастер-пароль",
            bg="#1e1e1e",
            fg="#ffffff",
            font=("Arial", 11)
        ).pack(pady=(20, 6))

        self.password = tk.Entry(
            self,
            show="*",
            bg="#2b2b2b",
            fg="#ffffff",
            insertbackground="#ffffff",
            relief="flat",
            bd=0,
            font=("Arial", 11)
        )
        self.password.pack(fill="x", padx=20, ipady=8)
        self.password.focus_set()

        self.login_btn = tk.Button(
            self,
            text="Войти",
            command=self.do_login,
            bg="#2f6fed",
            fg="#ffffff",
            activebackground="#2559be",
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            font=("Arial", 10, "bold"),
            padx=16,
            pady=8,
        )
        self.login_btn.pack(pady=20)

        self.bind("<Return>", lambda e: self.do_login())
        self.bind("<Escape>", lambda e: self.destroy())

        self.grab_set()
        self.focus_force()

    def do_login(self):
        password = self.password.get()

        self.login_btn.config(state="disabled")
        self.update_idletasks()

        try:
            self.auth_service.login(password)
        except Exception as e:
            messagebox.showerror("Ошибка входа", str(e), parent=self)
            self.login_btn.config(state="normal")
            return

        self.result = True
        self.destroy()