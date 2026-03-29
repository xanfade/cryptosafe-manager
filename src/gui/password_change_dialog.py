import threading
import tkinter as tk
from tkinter import ttk, messagebox

from src.core.crypto.authentication import validate_password_strength
from src.core.password_rotation import PasswordRotationService


class PasswordChangeDialog(tk.Toplevel):
    def __init__(self, parent, db, key_manager, auth_service):
        super().__init__(parent)

        self.parent = parent
        self.db = db
        self.key_manager = key_manager
        self.auth_service = auth_service

        self.rotation_service = PasswordRotationService(db, key_manager)
        self.worker_thread = None
        self.is_paused = False

        self.title("Смена мастер-пароля")
        self.geometry("520x420")
        self.resizable(False, False)
        self.configure(bg="#1e1e1e")

        self.transient(parent)
        self.grab_set()

        self._build_ui()
        self._center()

    def _build_ui(self):
        wrap = tk.Frame(self, bg="#1e1e1e", padx=24, pady=20)
        wrap.pack(fill="both", expand=True)

        tk.Label(
            wrap,
            text="Смена мастер-пароля",
            font=("Arial", 18, "bold"),
            bg="#1e1e1e",
            fg="#ffffff",
        ).pack(anchor="w", pady=(0, 16))

        self.current_var = tk.StringVar()
        self.new_var = tk.StringVar()
        self.confirm_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Введите данные")
        self.progress_var = tk.DoubleVar(value=0.0)

        self._label(wrap, "Текущий пароль")
        self.current_entry = self._entry(wrap, self.current_var, show="*")

        self._label(wrap, "Новый пароль")
        self.new_entry = self._entry(wrap, self.new_var, show="*")

        self._label(wrap, "Подтверждение нового пароля")
        self.confirm_entry = self._entry(wrap, self.confirm_var, show="*")

        self.hint_label = tk.Label(
            wrap,
            text="Минимум 12 символов, заглавная, строчная, цифра и спецсимвол",
            font=("Arial", 9),
            bg="#1e1e1e",
            fg="#aaaaaa",
        )
        self.hint_label.pack(anchor="w", pady=(2, 12))

        self.progress = ttk.Progressbar(
            wrap,
            orient="horizontal",
            mode="determinate",
            variable=self.progress_var,
            maximum=100,
        )
        self.progress.pack(fill="x", pady=(8, 6))

        self.status_label = tk.Label(
            wrap,
            textvariable=self.status_var,
            font=("Arial", 10),
            bg="#1e1e1e",
            fg="#d7d7d7",
            anchor="w",
        )
        self.status_label.pack(fill="x", pady=(0, 14))

        btns = tk.Frame(wrap, bg="#1e1e1e")
        btns.pack(fill="x")

        self.start_btn = tk.Button(
            btns,
            text="Сменить пароль",
            command=self.start_change,
            font=("Arial", 11, "bold"),
            bg="#2f6fed",
            fg="#ffffff",
            activebackground="#2457bb",
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            width=16,
            pady=10,
            cursor="hand2",
        )
        self.start_btn.pack(side="left")

        self.pause_btn = tk.Button(
            btns,
            text="Пауза",
            command=self.toggle_pause,
            state="disabled",
            font=("Arial", 11),
            bg="#3a3a3a",
            fg="#ffffff",
            activebackground="#4a4a4a",
            activeforeground="#ffffff",
            disabledforeground="#8a8a8a",
            relief="flat",
            bd=0,
            width=12,
            pady=10,
            cursor="hand2",
        )
        self.pause_btn.pack(side="left", padx=10)

        self.close_btn = tk.Button(
            btns,
            text="Закрыть",
            command=self.destroy,
            font=("Arial", 11),
            bg="#2b2b2b",
            fg="#ffffff",
            activebackground="#3a3a3a",
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            width=12,
            pady=10,
            cursor="hand2",
        )
        self.close_btn.pack(side="right")

    def _label(self, parent, text):
        tk.Label(
            parent,
            text=text,
            font=("Arial", 10, "bold"),
            bg="#1e1e1e",
            fg="#d7d7d7",
        ).pack(anchor="w", pady=(0, 6))

    def _entry(self, parent, var, show=None):
        entry = tk.Entry(
            parent,
            textvariable=var,
            show=show,
            font=("Arial", 11),
            bg="#2b2b2b",
            fg="#ffffff",
            insertbackground="#ffffff",
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground="#3a3a3a",
            highlightcolor="#5a5a5a",
        )
        entry.pack(fill="x", ipady=10, pady=(0, 12))
        return entry

    def _center(self):
        self.update_idletasks()
        x = self.parent.winfo_rootx() + (self.parent.winfo_width() // 2) - (self.winfo_width() // 2)
        y = self.parent.winfo_rooty() + (self.parent.winfo_height() // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{x}+{y}")

    def start_change(self):
        current_password = self.current_var.get().strip()
        new_password = self.new_var.get().strip()
        confirm_password = self.confirm_var.get().strip()

        if not current_password:
            messagebox.showwarning("Ошибка", "Введите текущий пароль", parent=self)
            return

        if not new_password:
            messagebox.showwarning("Ошибка", "Введите новый пароль", parent=self)
            return

        if new_password != confirm_password:
            messagebox.showwarning("Ошибка", "Подтверждение пароля не совпадает", parent=self)
            return

        try:
            validate_password_strength(new_password)
        except ValueError as e:
            messagebox.showwarning("Слабый пароль", str(e), parent=self)
            return

        self.start_btn.config(state="disabled")
        self.pause_btn.config(state="normal")
        self.close_btn.config(state="disabled")
        self.status_var.set("Запуск ротации ключей...")
        self.progress_var.set(0)

        self.worker_thread = threading.Thread(
            target=self._run_rotation,
            args=(current_password, new_password),
            daemon=True,
        )
        self.worker_thread.start()

    def _run_rotation(self, current_password, new_password):
        try:
            self.rotation_service.rotate_password(
                current_password=current_password,
                new_password=new_password,
                progress_cb=self._on_progress_from_worker,
            )
            self.after(0, self._on_success)
        except Exception as e:
            error_text = str(e)
            self.after(0, self._on_error, error_text)

    def _on_progress_from_worker(self, progress):
        self.after(0, lambda: self._apply_progress(progress))

    def _apply_progress(self, progress):
        self.progress_var.set(progress.percent)
        self.status_var.set(progress.message)

    def _on_success(self):
        self.progress_var.set(100)
        self.status_var.set("Смена пароля успешно завершена")
        self.pause_btn.config(state="disabled")
        self.close_btn.config(state="normal")
        messagebox.showinfo("Успех", "Мастер-пароль успешно изменён", parent=self)
        self.destroy()

    def _on_error(self, error_text):
        self.pause_btn.config(state="disabled")
        self.start_btn.config(state="normal")
        self.close_btn.config(state="normal")
        self.status_var.set("Ошибка при смене пароля")
        messagebox.showerror("Ошибка", error_text, parent=self)

    def toggle_pause(self):
        if not self.is_paused:
            self.rotation_service.pause()
            self.is_paused = True
            self.pause_btn.config(text="Продолжить")
            self.status_var.set("Процесс приостановлен")
        else:
            self.rotation_service.resume()
            self.is_paused = False
            self.pause_btn.config(text="Пауза")