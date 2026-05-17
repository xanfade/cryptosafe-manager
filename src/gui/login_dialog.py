import tkinter as tk
from tkinter import messagebox


class LoginDialog(tk.Toplevel):
    def __init__(self, parent, auth_service):
        super().__init__(parent)
        self.auth_service = auth_service
        self.result = False

        self.title("Вход в CryptoSafe Manager")
        self.geometry("400x230")
        self.resizable(False, False)
        self.configure(bg="#15111f")

        self._center_window(parent)
        self._build_ui()

        self.bind("<Return>", lambda e: self.do_login())
        self.bind("<Escape>", lambda e: self.destroy())

        self.grab_set()
        self.focus_force()
        self.password.focus_set()

    def _center_window(self, parent=None):
        self.update_idletasks()

        width = 400
        height = 230

        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        x = (screen_width - width) // 2
        y = (screen_height - height) // 2

        self.geometry(f"{width}x{height}+{x}+{y}")

    def _build_ui(self):
        container = tk.Frame(
            self,
            bg="#15111f",
            padx=32,
            pady=28
        )
        container.pack(fill="both", expand=True)

        tk.Label(
            container,
            text="CryptoSafe",
            bg="#15111f",
            fg="#ffffff",
            font=("Arial", 22, "bold"),
            anchor="w"
        ).pack(fill="x")

        tk.Label(
            container,
            text="Введите мастер-пароль",
            bg="#15111f",
            fg="#9ca3af",
            font=("Arial", 10),
            anchor="w"
        ).pack(fill="x", pady=(4, 22))

        self.password = tk.Entry(
            container,
            show="*",
            bg="#211a30",
            fg="#ffffff",
            insertbackground="#a855f7",
            relief="flat",
            bd=0,
            font=("Arial", 12),
            selectbackground="#7c3aed",
            selectforeground="#ffffff"
        )
        self.password.pack(fill="x", ipady=10)

        button_row = tk.Frame(container, bg="#15111f")
        button_row.pack(fill="x", pady=(22, 0))

        self.cancel_btn = tk.Label(
            button_row,
            text="Отмена",
            bg="#211a30",
            fg="#c4b5fd",
            font=("Arial", 10),
            padx=16,
            pady=10,
            cursor="hand2"
        )
        self.cancel_btn.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self.login_btn = tk.Label(
            button_row,
            text="Войти",
            bg="#7c3aed",
            fg="#ffffff",
            font=("Arial", 10, "bold"),
            padx=16,
            pady=10,
            cursor="hand2"
        )
        self.login_btn.pack(side="left", fill="x", expand=True, padx=(6, 0))

        self.cancel_btn.bind("<Button-1>", lambda e: self.destroy())
        self.login_btn.bind("<Button-1>", lambda e: self.do_login())

        self._add_hover(self.cancel_btn, "#211a30", "#2d2142")
        self._add_hover(self.login_btn, "#7c3aed", "#8b5cf6")

    def _add_hover(self, widget, normal_bg, hover_bg):
        widget.bind("<Enter>", lambda e: widget.config(bg=hover_bg))
        widget.bind("<Leave>", lambda e: widget.config(bg=normal_bg))

    def do_login(self):
        password = self.password.get()

        self.login_btn.unbind("<Button-1>")
        self.login_btn.config(bg="#4c1d95", fg="#c4b5fd")
        self.update_idletasks()

        try:
            self.auth_service.login(password)
        except Exception as e:
            messagebox.showerror("Ошибка входа", str(e), parent=self)
            self.login_btn.bind("<Button-1>", lambda e: self.do_login())
            self.login_btn.config(bg="#7c3aed", fg="#ffffff")
            return

        self.result = True
        self.destroy()