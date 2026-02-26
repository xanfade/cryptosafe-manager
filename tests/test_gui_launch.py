import tkinter as tk
from src.gui.main_window import MainWindow


def test_main_window_constructs():
    app = MainWindow()
    # Важно: закрываем окно, чтобы тесты не висли
    app.destroy()
