import tkinter as tk
from tkinter import ttk


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CryptoSafe Manager")
        self.geometry("900x520")

        # Menu
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New")
        file_menu.add_command(label="Open")
        file_menu.add_command(label="Backup")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Add")
        edit_menu.add_command(label="Edit")
        edit_menu.add_command(label="Delete")
        menubar.add_cascade(label="Edit", menu=edit_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Logs")
        view_menu.add_command(label="Settings")
        menubar.add_cascade(label="View", menu=view_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About")
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

        # Table placeholder
        columns = ("title", "username", "url", "updated")
        table = ttk.Treeview(self, columns=columns, show="headings")
        for c in columns:
            table.heading(c, text=c.capitalize())
            table.column(c, width=200)
        table.pack(fill="both", expand=True, padx=10, pady=10)

        table.insert("", "end", values=("Example", "user", "https://site", "—"))

        # Status bar
        self.status = tk.StringVar(value="Locked | Clipboard: --")
        statusbar = ttk.Label(self, textvariable=self.status, anchor="w")
        statusbar.pack(fill="x", side="bottom")


if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()
