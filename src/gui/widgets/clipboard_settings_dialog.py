from __future__ import annotations

import tkinter as tk
from tkinter import messagebox

from src.core.clipboard.clipboard_settings import ClipboardSettings


class ClipboardSettingsDialog(tk.Toplevel):
    def __init__(self, parent, repository, clipboard_service):
        super().__init__(parent)

        self.parent = parent
        self.repository = repository
        self.clipboard_service = clipboard_service
        self.result = None

        self.bg = "#121212"
        self.card = "#1c1c1e"
        self.card_2 = "#242426"
        self.border = "#33333a"
        self.text = "#ffffff"
        self.muted = "#a1a1aa"
        self.purple = "#7c3aed"
        self.purple_hover = "#8b5cf6"

        self.settings = self.repository.get()

        self.title("Настройки буфера обмена")
        self.geometry("560x620")
        self.minsize(520, 740) #580
        self.configure(bg=self.bg)
        self.transient(parent)
        self.grab_set()

        self._center()
        self._build_ui()
        self._load_values()

    def _center(self):
        self.update_idletasks()

        width = 120#560
        height = 120 #620

        x = self.winfo_screenwidth() // 2 - width // 2
        y = self.winfo_screenheight() // 2 - height // 2

        self.geometry(f"{width}x{height}+{x}+{y}")

    def _build_ui(self):
        wrapper = tk.Frame(self, bg=self.bg)
        wrapper.pack(fill="both", expand=True, padx=24, pady=24)

        tk.Label(
            wrapper,
            text="Clipboard Security",
            bg=self.bg,
            fg=self.text,
            font=("Arial", 24, "bold"),
        ).pack(anchor="w")

        tk.Label(
            wrapper,
            text="Настройка автоочистки, уведомлений и уровня защиты буфера обмена",
            bg=self.bg,
            fg=self.muted,
            font=("Arial", 10),
        ).pack(anchor="w", pady=(6, 22))

        body = tk.Frame(
            wrapper,
            bg=self.card,
            highlightthickness=1,
            highlightbackground=self.border,
        )
        body.pack(fill="both", expand=True)

        content = tk.Frame(body, bg=self.card)
        content.pack(fill="both", expand=True, padx=22, pady=22)

        self.never_var = tk.BooleanVar(value=False)
        self.timeout_var = tk.IntVar(value=30)
        self.notifications_var = tk.BooleanVar(value=True)
        self.security_level_var = tk.StringVar(value="advanced")

        self._section_title(content, "Auto clear timer")

        self.never_check = tk.Checkbutton(
            content,
            text='Never auto clear  не рекомендуется',
            variable=self.never_var,
            command=self._on_never_changed,
            bg=self.card,
            fg=self.text,
            selectcolor=self.card_2,
            activebackground=self.card,
            activeforeground=self.text,
            font=("Arial", 11),
            bd=0,
            highlightthickness=0,
        )
        self.never_check.pack(anchor="w", pady=(0, 10))

        self.timeout_label = tk.Label(
            content,
            text="30 секунд",
            bg=self.card,
            fg=self.purple,
            font=("Arial", 16, "bold"),
        )
        self.timeout_label.pack(anchor="w", pady=(0, 4))

        self.timeout_scale = tk.Scale(
            content,
            from_=5,
            to=300,
            orient="horizontal",
            variable=self.timeout_var,
            command=lambda _value: self._update_timeout_label(),
            bg=self.card,
            fg=self.text,
            troughcolor=self.card_2,
            activebackground=self.purple,
            highlightthickness=0,
            bd=0,
            length=470,
        )
        self.timeout_scale.pack(fill="x")

        self._hint(content, "Диапазон: от 5 секунд до 5 минут. Значение по умолчанию: 30 секунд.")

        self._divider(content)

        self._section_title(content, "Notifications")

        tk.Checkbutton(
            content,
            text="Показывать уведомления о копировании и очистке",
            variable=self.notifications_var,
            bg=self.card,
            fg=self.text,
            selectcolor=self.card_2,
            activebackground=self.card,
            activeforeground=self.text,
            font=("Arial", 11),
            bd=0,
            highlightthickness=0,
        ).pack(anchor="w", pady=(0, 10))

        self._divider(content)

        self._section_title(content, "Security level")

        levels = [
            ("Basic", "basic"),
            ("Advanced", "advanced"),
            ("Paranoid", "paranoid"),
        ]

        level_row = tk.Frame(content, bg=self.card)
        level_row.pack(fill="x", pady=(0, 12))

        for title, value in levels:
            tk.Radiobutton(
                level_row,
                text=title,
                value=value,
                variable=self.security_level_var,
                bg=self.card,
                fg=self.text,
                selectcolor=self.card_2,
                activebackground=self.card,
                activeforeground=self.text,
                font=("Arial", 11),
                bd=0,
                highlightthickness=0,
            ).pack(side="left", padx=(0, 18))

        self._hint(content, "Basic  мягкая очистка. Advanced  стандартная защита. Paranoid  самый строгий режим.")

        self._divider(content)

        self._section_title(content, "Allowed applications whitelist")

        tk.Label(
            content,
            text="Каждое приложение с новой строки",
            bg=self.card,
            fg=self.muted,
            font=("Arial", 10),
        ).pack(anchor="w", pady=(0, 8))

        self.whitelist_text = tk.Text(
            content,
            height=5,
            bg=self.card_2,
            fg=self.text,
            insertbackground=self.text,
            relief="flat",
            bd=0,
            font=("Arial", 11),
            padx=12,
            pady=10,
        )
        self.whitelist_text.pack(fill="x")

        buttons = tk.Frame(wrapper, bg=self.bg)
        buttons.pack(fill="x", pady=(18, 0))

        self._button(
            buttons,
            "Отмена",
            self.destroy,
            bg=self.card_2,
            hover="#2d2d30",
        ).pack(side="right", padx=(10, 0))

        self._button(
            buttons,
            "Сохранить",
            self._save,
            bg=self.purple,
            hover=self.purple_hover,
        ).pack(side="right")

    def _section_title(self, parent, text):
        tk.Label(
            parent,
            text=text,
            bg=self.card,
            fg=self.text,
            font=("Arial", 13, "bold"),
        ).pack(anchor="w", pady=(0, 10))

    def _hint(self, parent, text):
        tk.Label(
            parent,
            text=text,
            bg=self.card,
            fg=self.muted,
            font=("Arial", 9),
            wraplength=470,
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

    def _divider(self, parent):
        tk.Frame(parent, bg=self.border, height=1).pack(fill="x", pady=18)

    def _button(self, parent, text, command, bg, hover):
        button = tk.Label(
            parent,
            text=text,
            bg=bg,
            fg="#ffffff",
            font=("Arial", 11, "bold"),
            padx=24,
            pady=11,
            cursor="hand2",
        )

        button.bind("<Button-1>", lambda _event: command())
        button.bind("<Enter>", lambda _event: button.configure(bg=hover))
        button.bind("<Leave>", lambda _event: button.configure(bg=bg))

        return button

    def _load_values(self):
        timeout = self.settings.auto_clear_timeout_sec

        self.never_var.set(timeout is None)

        if timeout is None:
            self.timeout_var.set(30)
        else:
            self.timeout_var.set(timeout)

        self.notifications_var.set(self.settings.notifications_enabled)
        self.security_level_var.set(self.settings.security_level)

        self.whitelist_text.delete("1.0", "end")
        self.whitelist_text.insert(
            "1.0",
            "\n".join(self.settings.allowed_applications_whitelist),
        )

        self._on_never_changed()
        self._update_timeout_label()

    def _on_never_changed(self):
        is_never = self.never_var.get()

        state = "disabled" if is_never else "normal"
        self.timeout_scale.configure(state=state)

        self._update_timeout_label()

    def _update_timeout_label(self):
        if self.never_var.get():
            self.timeout_label.configure(
                text="Автоочистка отключена",
                fg="#f97316",
            )
            return

        seconds = self.timeout_var.get()

        if seconds < 60:
            text = f"{seconds} секунд"
        else:
            minutes = seconds // 60
            rest = seconds % 60
            text = f"{minutes} мин {rest} сек" if rest else f"{minutes} мин"

        self.timeout_label.configure(text=text, fg=self.purple)

    def _save(self):
        timeout = None if self.never_var.get() else int(self.timeout_var.get())

        whitelist = [
            line.strip()
            for line in self.whitelist_text.get("1.0", "end").splitlines()
            if line.strip()
        ]

        settings = ClipboardSettings(
            auto_clear_timeout_sec=timeout,
            notifications_enabled=self.notifications_var.get(),
            security_level=self.security_level_var.get(),
            allowed_applications_whitelist=whitelist,
        ).normalized()

        try:
            saved = self.repository.save(settings)
            self.clipboard_service.apply_settings(saved)

            if saved.auto_clear_timeout_sec is None:
                messagebox.showwarning(
                    "Auto clear disabled",
                    "Автоочистка буфера отключена. Это не рекомендуется.",
                    parent=self,
                )

            self.result = saved
            self.destroy()

        except Exception as exc:
            messagebox.showerror(
                "Ошибка сохранения",
                f"Не удалось сохранить настройки:\n{exc}",
                parent=self,
            )