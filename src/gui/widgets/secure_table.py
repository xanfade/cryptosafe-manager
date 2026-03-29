from tkinter import ttk


class SecureTable(ttk.Frame):
    # Таблица записей хранилища (пока с тестовыми данными)
    def __init__(self, master):
        super().__init__(master)

        cols = ("title", "username", "url", "updated")
        self.tree = ttk.Treeview(self, columns=cols, show="headings")

        for c in cols:
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=200)

        self.tree.pack(fill="both", expand=True)

    def set_rows(self, rows):
        # rows: list[tuple]
        for item in self.tree.get_children():
            self.tree.delete(item)
        for r in rows:
            self.tree.insert("", "end", values=r)

    def clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)