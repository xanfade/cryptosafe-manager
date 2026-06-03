from __future__ import annotations

import platform
import subprocess
import tkinter as tk
from tkinter import messagebox

from src.core.clipboard.clipboard_settings import ClipboardSettings
from src.core.events import ConfigurationChanged


class ClipboardSettingsDialog(tk.Toplevel):
    def __init__(self, parent, repository, clipboard_service):
        super().__init__(parent)
        self.parent = parent
        self.repository = repository
        self.clipboard_service = clipboard_service
        self.result = None

        self.bg = "#121014"
        self.card = "#1b1524"
        self.card_2 = "#251d31"
        self.border = "#3a2d4f"
        self.text = "#f7f2ff"
        self.muted = "#b7a7d8"
        self.purple = "#8b5cf6"
        self.purple_hover = "#a78bfa"

        self.settings = self.repository.get()

        self.title("Настройки буфера обмена")
        self.geometry("580x680")
        self.minsize(560, 640)
        self.configure(bg=self.bg)
        self.transient(parent)
        self.grab_set()

        self._center()
        self._build_ui()
        self._load_values()

    def _center(self):
        self.update_idletasks()
        width = 580
        height = 680
        x = self.winfo_screenwidth() // 2 - width // 2
        y = self.winfo_screenheight() // 2 - height // 2
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _build_ui(self):
        canvas = tk.Canvas(self, bg=self.bg, highlightthickness=0, bd=0)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar = tk.Scrollbar(
            self,
            orient="vertical",
            command=canvas.yview,
            bg=self.purple,
            troughcolor="#1b1524",
            activebackground="#8b5cf6",
            highlightthickness=0,
            bd=0,
            relief="flat",
            width=14,
        )
        scrollbar.pack(side="right", fill="y")
        canvas.configure(yscrollcommand=scrollbar.set)

        wrapper = tk.Frame(self, bg=self.bg)
        canvas_window = canvas.create_window((0, 0), window=wrapper, anchor="nw")
        wrapper.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(canvas_window, width=event.width))

        tk.Label(wrapper, text="Буфер обмена", bg=self.bg, fg=self.text, font=("Arial", 24, "bold")).pack(anchor="w")
        tk.Label(
            wrapper,
            text="Автоочистка, уведомления и доверенные приложения",
            bg=self.bg,
            fg=self.muted,
            font=("Arial", 10),
        ).pack(anchor="w", pady=(6, 22))

        body = tk.Frame(wrapper, bg=self.card, highlightthickness=1, highlightbackground=self.border)
        body.pack(fill="both", expand=True)
        content = tk.Frame(body, bg=self.card)
        content.pack(fill="both", expand=True, padx=22, pady=22)

        self.never_var = tk.BooleanVar(value=True)
        self.timeout_var = tk.IntVar(value=30)
        self.notifications_var = tk.BooleanVar(value=True)

        self._section_title(content, "Автоочистка")
        self.never_check = self._check(content, "Не очищать автоматически", self.never_var, self._on_never_changed)
        self.timeout_label = tk.Label(content, text="", bg=self.card, fg=self.purple, font=("Arial", 16, "bold"))
        self.timeout_label.pack(anchor="w", pady=(10, 4))
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
        )
        self.timeout_scale.pack(fill="x")
        self._hint(content, "По умолчанию автоочистка выключена. Если включишь таймер, диапазон 5 секунд - 5 минут.")

        self._divider(content)
        self._section_title(content, "Уведомления")
        self._check(content, "Показывать уведомления о копировании и очистке", self.notifications_var)

        self._divider(content)
        self._section_title(content, "Доверенные приложения")
        self._hint(content, "Каждый процесс с новой строки (точное имя процесса). Можно выбрать из списка ниже.")
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
        self.whitelist_text.pack(fill="x", pady=(8, 0))

        process_tools = tk.Frame(content, bg=self.card)
        process_tools.pack(fill="x", pady=(10, 6))
        self._button(process_tools, "Обновить процессы", self._load_processes, self.card_2, "#312541").pack(side="left")
        self._button(process_tools, "Добавить выбранный", self._add_selected_process, self.purple, self.purple_hover).pack(side="left", padx=(10, 0))

        process_list_wrap = tk.Frame(content, bg=self.card)
        process_list_wrap.pack(fill="x")
        process_scroll = tk.Scrollbar(
            process_list_wrap,
            orient="vertical",
            bg="#7c3aed",
            troughcolor="#1b1524",
            activebackground="#8b5cf6",
            highlightthickness=0,
            bd=0,
            relief="flat",
            width=14,
        )
        process_scroll.pack(side="right", fill="y")
        self.process_listbox = tk.Listbox(
            process_list_wrap,
            height=8,
            bg=self.card_2,
            fg=self.text,
            selectbackground=self.purple,
            selectforeground="#ffffff",
            relief="flat",
            bd=0,
            highlightthickness=0,
            activestyle="none",
            yscrollcommand=process_scroll.set,
        )
        self.process_listbox.pack(side="left", fill="both", expand=True)
        process_scroll.configure(command=self.process_listbox.yview)
        self.process_listbox.bind("<Double-Button-1>", lambda _event: self._add_selected_process())

        buttons = tk.Frame(wrapper, bg=self.bg)
        buttons.pack(fill="x", pady=(18, 0))
        self._button(buttons, "Отмена", self.destroy, self.card_2, "#312541").pack(side="right", padx=(10, 0))
        self._button(buttons, "Сохранить", self._save, self.purple, self.purple_hover).pack(side="right")

    def _check(self, parent, text, variable, command=None):
        check = tk.Checkbutton(
            parent,
            text=text,
            variable=variable,
            command=command,
            bg=self.card,
            fg=self.text,
            selectcolor=self.card_2,
            activebackground=self.card,
            activeforeground=self.text,
            bd=0,
            highlightthickness=0,
            font=("Arial", 11),
        )
        check.pack(anchor="w", pady=(0, 10))
        return check

    def _section_title(self, parent, text):
        tk.Label(parent, text=text, bg=self.card, fg=self.text, font=("Arial", 13, "bold")).pack(anchor="w", pady=(0, 10))

    def _hint(self, parent, text):
        tk.Label(parent, text=text, bg=self.card, fg=self.muted, font=("Arial", 9), wraplength=500, justify="left").pack(anchor="w", pady=(4, 0))

    def _divider(self, parent):
        tk.Frame(parent, bg=self.border, height=1).pack(fill="x", pady=18)

    def _button(self, parent, text, command, bg, hover):
        button = tk.Label(parent, text=text, bg=bg, fg="#ffffff", font=("Arial", 11, "bold"), padx=24, pady=11, cursor="hand2")
        button.bind("<Button-1>", lambda _event: command())
        button.bind("<Enter>", lambda _event: button.configure(bg=hover))
        button.bind("<Leave>", lambda _event: button.configure(bg=bg))
        return button

    def _load_values(self):
        effective_timeout = getattr(self.clipboard_service, "clear_after_seconds", None)
        stored_timeout = self.settings.auto_clear_timeout_sec
        timeout = effective_timeout if effective_timeout is not None or stored_timeout is None else stored_timeout
        self.never_var.set(timeout is None)
        self.timeout_var.set(30 if timeout is None else timeout)
        self.notifications_var.set(self.settings.notifications_enabled)
        self.whitelist_text.delete("1.0", "end")
        self.whitelist_text.insert("1.0", "\n".join(self.settings.allowed_applications_whitelist))
        self._on_never_changed()
        self._update_timeout_label()
        self._load_processes()

    def _load_processes(self):
        names = sorted(self._get_running_process_names())
        self.process_listbox.delete(0, "end")
        for name in names:
            self.process_listbox.insert("end", name)

    def _get_running_process_names(self) -> set[str]:
        system = platform.system()
        try:
            if system == "Windows":
                result = subprocess.run(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                rows = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                names = set()
                for row in rows:
                    if row.startswith('"'):
                        parts = row.split('","')
                        if parts:
                            names.add(parts[0].strip('"').strip())
                return {name for name in names if name}
            result = subprocess.run(
                ["ps", "-A", "-o", "comm="],
                capture_output=True,
                text=True,
                check=False,
            )
            names = set()
            for raw in result.stdout.splitlines():
                value = raw.strip()
                if not value:
                    continue
                names.add(value.split("/")[-1])
            return names
        except Exception:
            return set()

    def _add_selected_process(self):
        selection = self.process_listbox.curselection()
        if not selection:
            return
        process_name = self.process_listbox.get(selection[0]).strip()
        if not process_name:
            return
        existing = {
            line.strip().lower()
            for line in self.whitelist_text.get("1.0", "end").splitlines()
            if line.strip()
        }
        if process_name.lower() in existing:
            return
        current = self.whitelist_text.get("1.0", "end").strip()
        if current:
            self.whitelist_text.insert("end", "\n")
        self.whitelist_text.insert("end", process_name)

    def _on_never_changed(self):
        self.timeout_scale.configure(state="disabled" if self.never_var.get() else "normal")
        self._update_timeout_label()

    def _update_timeout_label(self):
        if self.never_var.get():
            self.timeout_label.configure(text="Автоочистка отключена", fg="#f59e0b")
            return
        seconds = self.timeout_var.get()
        if seconds < 60:
            text = f"{seconds} сек"
        else:
            minutes = seconds // 60
            rest = seconds % 60
            text = f"{minutes} мин {rest} сек" if rest else f"{minutes} мин"
        self.timeout_label.configure(text=text, fg=self.purple)

    def _save(self):
        timeout = None if self.never_var.get() else int(self.timeout_var.get())
        whitelist = [line.strip() for line in self.whitelist_text.get("1.0", "end").splitlines() if line.strip()]
        settings = ClipboardSettings(
            auto_clear_timeout_sec=timeout,
            notifications_enabled=self.notifications_var.get(),
            security_level=self.settings.security_level,
            allowed_applications_whitelist=whitelist,
        ).normalized()
        try:
            saved = self.repository.save(settings)
            self.clipboard_service.apply_settings(saved)
            # Keep legacy timeout setting in sync to avoid UI/runtime drift.
            if hasattr(self.clipboard_service, "save_timeout_to_settings"):
                self.clipboard_service.save_timeout_to_settings(self.repository.db)
            event_bus = getattr(self.parent, "event_bus", None)
            if event_bus:
                event_bus.publish(ConfigurationChanged(setting_key="clipboard", source="clipboard_settings"))
            if saved.auto_clear_timeout_sec is None:
                messagebox.showinfo("Буфер обмена", "Автоочистка буфера отключена.", parent=self)
            self.result = saved
            self.destroy()
        except Exception as exc:
            messagebox.showerror("Ошибка сохранения", f"Не удалось сохранить настройки:\n{exc}", parent=self)
