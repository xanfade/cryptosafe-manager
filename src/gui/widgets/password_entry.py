import tkinter as tk
from tkinter import ttk


class PasswordEntry(ttk.Frame):
    # Поле пароля с кнопкой показать/скрыть
    def __init__(self, master, **kwargs):
        super().__init__(master)

        self._shown = False

        self.var = tk.StringVar()
        self.entry = ttk.Entry(self, textvariable=self.var, show="•", **kwargs)
        self.entry.pack(side="left", fill="x", expand=True)

        self.btn = ttk.Button(self, text="Показать", width=10, command=self.toggle)
        self.btn.pack(side="left", padx=(8, 0))

    def toggle(self):
        self._shown = not self._shown
        self.entry.config(show="" if self._shown else "•")
        self.btn.config(text="Скрыть" if self._shown else "Показать")

    def get(self) -> str:
        return self.var.get()

    def set(self, value: str):
        self.var.set(value)
