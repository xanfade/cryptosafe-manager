import threading
import tkinter as tk
from tkinter import ttk, messagebox
import secrets
import string

from src.core.crypto.authentication import validate_password_strength
from src.core.password_rotation import PasswordRotationService


class PasswordChangeDialog(tk.Toplevel):
    """
    Улучшенный GUI диалога смены мастер-пароля.

    Что изменено:
    - единый тёмный стиль CryptoSafe
    - фиолетовый акцент вместо стандартного синего
    - аккуратная карточка внутри окна
    - нормальные отступы и визуальная иерархия
    - стилизованный Progressbar
    - кнопки с hover-эффектом
    - индикатор статуса
    - чекбокс показа паролей

    Логика ротации пароля оставлена прежней.
    """

    BG = "#111217"
    CARD = "#191B23"
    CARD_LIGHT = "#20232E"
    BORDER = "#2C3040"

    TEXT = "#F3F4F8"
    MUTED = "#A6ABBD"
    MUTED_DARK = "#777D91"

    PURPLE = "#8B5CF6"
    PURPLE_HOVER = "#7C3AED"
    PURPLE_DARK = "#5B21B6"

    DANGER = "#EF4444"
    SUCCESS = "#22C55E"
    WARNING = "#F59E0B"

    INPUT_BG = "#12141B"
    INPUT_FOCUS = "#8B5CF6"

    FONT = "Arial"

    def __init__(self, parent, db, key_manager, auth_service):
        super().__init__(parent)

        self.parent = parent
        self.db = db
        self.key_manager = key_manager
        self.auth_service = auth_service

        self.rotation_service = PasswordRotationService(db, key_manager)
        self.worker_thread = None
        self.is_paused = False
        self.passwords_visible = False

        self.title("Смена мастер-пароля")
        self.geometry("560x560")
        self.minsize(580, 700)
        self.resizable(False, False)
        self.configure(bg=self.BG)

        self.transient(parent)
        self.grab_set()

        self._configure_styles()
        self._build_ui()
        self._center()

        self.current_entry.focus_set()
        self.bind("<Escape>", lambda _event: self._safe_close())
        self.protocol("WM_DELETE_WINDOW", self._safe_close)

    def _configure_styles(self):
        style = ttk.Style(self)

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Purple.Horizontal.TProgressbar",
            troughcolor=self.CARD_LIGHT,
            background=self.PURPLE,
            bordercolor=self.CARD_LIGHT,
            lightcolor=self.PURPLE,
            darkcolor=self.PURPLE,
            thickness=10,
        )

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

        icon = tk.Label(
            header,
            text="🔐",
            font=(self.FONT, 24),
            bg=self.CARD,
            fg=self.TEXT,
        )
        icon.pack(side="left", padx=(0, 14))

        title_box = tk.Frame(header, bg=self.CARD)
        title_box.pack(side="left", fill="x", expand=True)

        tk.Label(
            title_box,
            text="Смена мастер-пароля",
            font=(self.FONT, 18, "bold"),
            bg=self.CARD,
            fg=self.TEXT,
        ).pack(anchor="w")

        tk.Label(
            title_box,
            text="Пароль будет обновлён с безопасной ротацией ключей",
            font=(self.FONT, 10),
            bg=self.CARD,
            fg=self.MUTED,
        ).pack(anchor="w", pady=(5, 0))

        divider = tk.Frame(card, bg=self.BORDER, height=1)
        divider.pack(fill="x")

        body = tk.Frame(card, bg=self.CARD, padx=26, pady=22)
        body.pack(fill="both", expand=True)

        self.current_var = tk.StringVar()
        self.new_var = tk.StringVar()
        self.confirm_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Введите текущий и новый мастер-пароль")
        self.progress_var = tk.DoubleVar(value=0.0)
        self.show_passwords_var = tk.BooleanVar(value=False)

        self._field_label(body, "Текущий пароль")
        self.current_entry = self._entry(body, self.current_var, show="*")

        self._field_label(body, "Новый пароль")
        self.new_entry = self._entry(body, self.new_var, show="*")

        self._field_label(body, "Подтверждение нового пароля")
        self.confirm_entry = self._entry(body, self.confirm_var, show="*")

        self._build_hint_box(body)
        self._build_password_tools(body)
        self._build_show_passwords_checkbox(body)
        self._build_progress_block(body)
        self._build_buttons(body)

    def _build_hint_box(self, parent):
        hint = tk.Frame(
            parent,
            bg=self.CARD_LIGHT,
            highlightthickness=1,
            highlightbackground=self.BORDER,
            highlightcolor=self.BORDER,
            padx=12,
            pady=10,
        )
        hint.pack(fill="x", pady=(2, 14))

        tk.Label(
            hint,
            text="Требования к паролю",
            font=(self.FONT, 10, "bold"),
            bg=self.CARD_LIGHT,
            fg=self.TEXT,
        ).pack(anchor="w")

        tk.Label(
            hint,
            text="Минимум 12 символов, заглавная и строчная буква, цифра и спецсимвол",
            font=(self.FONT, 9),
            bg=self.CARD_LIGHT,
            fg=self.MUTED,
            wraplength=450,
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

    def _build_password_tools(self, parent):
        tools = tk.Frame(parent, bg=self.CARD)
        tools.pack(fill="x", pady=(0, 12))

        self.generate_btn = self._button(
            tools,
            text="Сгенерировать",
            command=self._generate_password,
            bg=self.CARD_LIGHT,
            hover="#2A2E3D",
            width=16,
        )
        self.generate_btn.pack(side="left")

        tk.Label(
            tools,
            text="Создаст надёжный пароль и вставит его в оба поля",
            font=(self.FONT, 9),
            bg=self.CARD,
            fg=self.MUTED_DARK,
        ).pack(side="left", padx=(12, 0))

    def _build_show_passwords_checkbox(self, parent):
        row = tk.Frame(parent, bg=self.CARD)
        row.pack(fill="x", pady=(0, 14))

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

    def _build_progress_block(self, parent):
        progress_card = tk.Frame(parent, bg=self.CARD, pady=2)
        progress_card.pack(fill="x", pady=(0, 18))

        self.progress = ttk.Progressbar(
            progress_card,
            orient="horizontal",
            mode="determinate",
            variable=self.progress_var,
            maximum=100,
            style="Purple.Horizontal.TProgressbar",
        )
        self.progress.pack(fill="x", pady=(0, 10))

        status_row = tk.Frame(progress_card, bg=self.CARD)
        status_row.pack(fill="x")

        self.status_dot = tk.Label(
            status_row,
            text="●",
            font=(self.FONT, 11),
            bg=self.CARD,
            fg=self.PURPLE,
        )
        self.status_dot.pack(side="left", padx=(0, 8))

        self.status_label = tk.Label(
            status_row,
            textvariable=self.status_var,
            font=(self.FONT, 10),
            bg=self.CARD,
            fg=self.MUTED,
            anchor="w",
        )
        self.status_label.pack(side="left", fill="x", expand=True)

    def _build_buttons(self, parent):
        btns = tk.Frame(parent, bg=self.CARD)
        btns.pack(fill="x")

        self.start_btn = self._button(
            btns,
            text="Сменить пароль",
            command=self.start_change,
            bg=self.PURPLE,
            hover=self.PURPLE_HOVER,
            width=18,
            bold=True,
        )
        self.start_btn.pack(side="left")

        self.pause_btn = self._button(
            btns,
            text="Пауза",
            command=self.toggle_pause,
            bg=self.CARD_LIGHT,
            hover="#2A2E3D",
            width=12,
        )
        self.pause_btn.config(state="disabled", disabledforeground=self.MUTED_DARK)
        self.pause_btn.pack(side="left", padx=10)

        self.close_btn = self._button(
            btns,
            text="Закрыть",
            command=self._safe_close,
            bg="#242733",
            hover="#303443",
            width=12,
        )
        self.close_btn.pack(side="right")

    def _field_label(self, parent, text):
        tk.Label(
            parent,
            text=text,
            font=(self.FONT, 10, "bold"),
            bg=self.CARD,
            fg=self.TEXT,
        ).pack(anchor="w", pady=(0, 7))

    def _entry(self, parent, var, show=None):
        entry = tk.Entry(
            parent,
            textvariable=var,
            show=show,
            font=(self.FONT, 12),
            bg=self.INPUT_BG,
            fg=self.TEXT,
            insertbackground=self.TEXT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=self.BORDER,
            highlightcolor=self.INPUT_FOCUS,
        )
        entry.pack(fill="x", ipady=11, pady=(0, 14))

        entry.bind("<FocusIn>", lambda _event: entry.config(highlightbackground=self.INPUT_FOCUS))
        entry.bind("<FocusOut>", lambda _event: entry.config(highlightbackground=self.BORDER))

        return entry

    def _button(self, parent, text, command, bg, hover, width=12, bold=False):
        """
        Кастомная кнопка на Label вместо tk.Button.

        На macOS обычный tk.Button часто игнорирует bg/fg и выглядит как
        системная кнопка. Label корректно принимает цвета, поэтому визуально
        кнопки остаются такими, как задумано.
        """
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

        original_config = btn.config

        def custom_config(*args, **kwargs):
            state = kwargs.pop("state", None)
            disabledforeground = kwargs.pop("disabledforeground", None)

            if state is not None:
                btn.is_disabled = str(state) == "disabled"

                if btn.is_disabled:
                    original_config(
                        bg="#252936",
                        fg=disabledforeground or self.MUTED_DARK,
                        cursor="arrow",
                    )
                else:
                    original_config(
                        bg=btn.default_bg,
                        fg=self.TEXT,
                        cursor="hand2",
                    )

            if kwargs:
                original_config(*args, **kwargs)
            elif args:
                original_config(*args)

        btn.config = custom_config
        btn.configure = custom_config

        def on_click(_event=None):
            if btn.is_disabled:
                return
            btn.command()

        btn.bind("<Button-1>", on_click)
        btn.bind("<Enter>", lambda _event: self._on_button_hover(btn, True))
        btn.bind("<Leave>", lambda _event: self._on_button_hover(btn, False))

        return btn

    def _on_button_hover(self, button, is_hover):
        if getattr(button, "is_disabled", False):
            return

        button.config(bg=button.hover_bg if is_hover else button.default_bg)

    def _generate_password(self):
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+="

        while True:
            password = "".join(secrets.choice(alphabet) for _ in range(18))

            if (
                any(ch.islower() for ch in password)
                and any(ch.isupper() for ch in password)
                and any(ch.isdigit() for ch in password)
                and any(ch in "!@#$%^&*()_+=" for ch in password)
            ):
                break

        self.new_var.set(password)
        self.confirm_var.set(password)
        self.status_dot.config(fg=self.PURPLE)
        self.status_var.set("Надёжный пароль сгенерирован")

    def _toggle_password_visibility(self):
        self.passwords_visible = bool(self.show_passwords_var.get())
        show_value = "" if self.passwords_visible else "*"

        self.current_entry.config(show=show_value)
        self.new_entry.config(show=show_value)
        self.confirm_entry.config(show=show_value)

    def _center(self):
        self.update_idletasks()

        parent_width = max(self.parent.winfo_width(), 1)
        parent_height = max(self.parent.winfo_height(), 1)

        x = self.parent.winfo_rootx() + (parent_width // 2) - (self.winfo_width() // 2)
        y = self.parent.winfo_rooty() + (parent_height // 2) - (self.winfo_height() // 2)

        self.geometry(f"+{x}+{y}")

    def _safe_close(self):
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showwarning(
                "Процесс выполняется",
                "Дождитесь завершения смены пароля или поставьте процесс на паузу.",
                parent=self,
            )
            return

        self.destroy()

    def _set_busy_state(self, busy: bool):
        if busy:
            self.start_btn.config(state="disabled")
            self.pause_btn.config(state="normal")
            self.close_btn.config(state="disabled")
            self.current_entry.config(state="disabled")
            self.new_entry.config(state="disabled")
            self.confirm_entry.config(state="disabled")
            self.show_passwords_check.config(state="disabled")
            self.generate_btn.config(state="disabled")
        else:
            self.start_btn.config(state="normal")
            self.pause_btn.config(state="disabled")
            self.close_btn.config(state="normal")
            self.current_entry.config(state="normal")
            self.new_entry.config(state="normal")
            self.confirm_entry.config(state="normal")
            self.show_passwords_check.config(state="normal")
            self.generate_btn.config(state="normal")

    def start_change(self):
        current_password = self.current_var.get().strip()
        new_password = self.new_var.get().strip()
        confirm_password = self.confirm_var.get().strip()

        if not current_password:
            messagebox.showwarning("Ошибка", "Введите текущий пароль", parent=self)
            self.current_entry.focus_set()
            return

        if not new_password:
            messagebox.showwarning("Ошибка", "Введите новый пароль", parent=self)
            self.new_entry.focus_set()
            return

        if new_password != confirm_password:
            messagebox.showwarning("Ошибка", "Подтверждение пароля не совпадает", parent=self)
            self.confirm_entry.focus_set()
            return

        try:
            validate_password_strength(new_password)
        except ValueError as e:
            messagebox.showwarning("Слабый пароль", str(e), parent=self)
            self.new_entry.focus_set()
            return

        self.is_paused = False
        self.pause_btn.config(text="Пауза")
        self._set_busy_state(True)

        self.status_dot.config(fg=self.PURPLE)
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
        self.status_dot.config(fg=self.SUCCESS)
        self.status_var.set("Смена пароля успешно завершена")
        self._set_busy_state(False)
        messagebox.showinfo("Успех", "Мастер-пароль успешно изменён", parent=self)
        self.destroy()

    def _on_error(self, error_text):
        self.status_dot.config(fg=self.DANGER)
        self.status_var.set("Ошибка при смене пароля")
        self._set_busy_state(False)
        messagebox.showerror("Ошибка", error_text, parent=self)

    def toggle_pause(self):
        if not self.is_paused:
            self.rotation_service.pause()
            self.is_paused = True
            self.pause_btn.config(text="Продолжить")
            self.status_dot.config(fg=self.WARNING)
            self.status_var.set("Процесс приостановлен")
        else:
            self.rotation_service.resume()
            self.is_paused = False
            self.pause_btn.config(text="Пауза")
            self.status_dot.config(fg=self.PURPLE)
            self.status_var.set("Процесс продолжен")
