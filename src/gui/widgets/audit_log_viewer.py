import tkinter as tk
from tkinter import ttk


class AuditLogViewer(tk.Toplevel):
    # Заглушка окна логов для Спринта 5
    def __init__(self, master=None):
        super().__init__(master)
        self.title("Журнал аудита (Спринт 5)")
        self.geometry("600x400")

        ttk.Label(self, text="Здесь будет просмотр журнала аудита (заглушка).").pack(padx=20, pady=20)
        ttk.Button(self, text="Закрыть", command=self.destroy).pack(pady=10)
