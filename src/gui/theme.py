import tkinter as tk
from tkinter import ttk


COLORS = {
    "bg": "#121212",
    "surface": "#1c1c1e",
    "surface_2": "#242426",
    "surface_3": "#2d2d30",
    "border": "#3a3a3d",
    "text": "#f5f5f7",
    "muted": "#a1a1aa",
    "accent": "#7c3aed",
    "accent_hover": "#8b5cf6",
    "danger": "#ef4444",
    "success": "#22c55e",
    "warning": "#f59e0b",
}


FONTS = {
    "title": ("Arial", 18, "bold"),
    "subtitle": ("Arial", 12, "bold"),
    "body": ("Arial", 10),
    "small": ("Arial", 9),
    "mono": ("Consolas", 10),
}


def apply_theme(root: tk.Tk):
    root.configure(bg=COLORS["bg"])

    style = ttk.Style(root)

    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(
        "App.TFrame",
        background=COLORS["bg"],
    )

    style.configure(
        "Card.TFrame",
        background=COLORS["surface"],
        relief="flat",
        borderwidth=0,
    )

    style.configure(
        "App.TLabel",
        background=COLORS["bg"],
        foreground=COLORS["text"],
        font=FONTS["body"],
    )

    style.configure(
        "Muted.TLabel",
        background=COLORS["bg"],
        foreground=COLORS["muted"],
        font=FONTS["small"],
    )

    style.configure(
        "App.TButton",
        background=COLORS["surface_2"],
        foreground=COLORS["text"],
        borderwidth=0,
        focusthickness=0,
        padding=(12, 7),
        font=FONTS["body"],
    )

    style.map(
        "App.TButton",
        background=[
            ("active", COLORS["surface_3"]),
            ("pressed", COLORS["border"]),
        ],
    )

    style.configure(
        "Accent.TButton",
        background=COLORS["accent"],
        foreground="#ffffff",
        borderwidth=0,
        focusthickness=0,
        padding=(14, 8),
        font=FONTS["body"],
    )

    style.map(
        "Accent.TButton",
        background=[
            ("active", COLORS["accent_hover"]),
            ("pressed", COLORS["accent"]),
        ],
    )

    style.configure(
        "Danger.TButton",
        background=COLORS["danger"],
        foreground="#ffffff",
        borderwidth=0,
        focusthickness=0,
        padding=(12, 7),
        font=FONTS["body"],
    )

    style.configure(
        "Treeview",
        background=COLORS["surface"],
        fieldbackground=COLORS["surface"],
        foreground=COLORS["text"],
        rowheight=36,
        borderwidth=0,
        font=FONTS["body"],
    )

    style.configure(
        "Treeview.Heading",
        background=COLORS["surface_2"],
        foreground=COLORS["muted"],
        borderwidth=0,
        padding=(8, 8),
        font=("Arial", 10, "bold"),
    )

    style.map(
        "Treeview",
        background=[("selected", COLORS["accent"])],
        foreground=[("selected", "#ffffff")],
    )

    style.configure(
        "Vertical.TScrollbar",
        background=COLORS["surface_2"],
        troughcolor=COLORS["bg"],
        bordercolor=COLORS["bg"],
        arrowcolor=COLORS["muted"],
    )