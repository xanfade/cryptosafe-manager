from __future__ import annotations

import importlib
import platform
import shutil
import subprocess
from typing import Any


class ClipboardAdapter:
    def set_text(self, value: str) -> None:
        raise NotImplementedError

    def get_text(self) -> str:
        raise NotImplementedError

    def clear(self) -> None:
        raise NotImplementedError


class WindowsClipboardAdapter(ClipboardAdapter):
    """
    Windows adapter.

    Использует pywin32:
    - win32clipboard
    - win32con

    На macOS и Linux этот класс не создаётся.
    """

    def __init__(self) -> None:
        self.win32clipboard: Any = importlib.import_module("win32clipboard")
        self.win32con: Any = importlib.import_module("win32con")

    def set_text(self, value: str) -> None:
        self.win32clipboard.OpenClipboard()
        try:
            self.win32clipboard.EmptyClipboard()
            self.win32clipboard.SetClipboardData(
                self.win32con.CF_UNICODETEXT,
                value,
            )
        finally:
            self.win32clipboard.CloseClipboard()

    def get_text(self) -> str:
        self.win32clipboard.OpenClipboard()
        try:
            if self.win32clipboard.IsClipboardFormatAvailable(
                self.win32con.CF_UNICODETEXT
            ):
                return self.win32clipboard.GetClipboardData(
                    self.win32con.CF_UNICODETEXT
                )
            return ""
        finally:
            self.win32clipboard.CloseClipboard()

    def clear(self) -> None:
        self.win32clipboard.OpenClipboard()
        try:
            self.win32clipboard.EmptyClipboard()
        finally:
            self.win32clipboard.CloseClipboard()


class MacOSClipboardAdapter(ClipboardAdapter):
    """
    macOS adapter.

    Использует pyobjc:
    - AppKit.NSPasteboard
    """

    def __init__(self) -> None:
        appkit: Any = importlib.import_module("AppKit")

        self.NSPasteboard = appkit.NSPasteboard
        self.NSPasteboardNameGeneral = appkit.NSPasteboardNameGeneral
        self.NSPasteboardTypeString = appkit.NSPasteboardTypeString

    def _pasteboard(self):
        return self.NSPasteboard.pasteboardWithName_(
            self.NSPasteboardNameGeneral
        )

    def set_text(self, value: str) -> None:
        pasteboard = self._pasteboard()
        pasteboard.clearContents()
        pasteboard.declareTypes_owner_(
            [self.NSPasteboardTypeString],
            None,
        )
        pasteboard.setString_forType_(
            value,
            self.NSPasteboardTypeString,
        )

    def get_text(self) -> str:
        value = self._pasteboard().stringForType_(
            self.NSPasteboardTypeString
        )
        return value or ""

    def clear(self) -> None:
        self._pasteboard().clearContents()


class LinuxClipboardAdapter(ClipboardAdapter):
    """
    Linux adapter.

    Поддерживает:
    - Wayland через wl-copy / wl-paste
    - X11 через xclip
    - X11 через xsel
    - fallback через pyperclip
    """

    def __init__(self, selection: str = "clipboard") -> None:
        self.selection = selection

    def set_text(self, value: str) -> None:
        if shutil.which("wl-copy"):
            subprocess.run(
                ["wl-copy"],
                input=value.encode("utf-8"),
                check=True,
            )
            return

        if shutil.which("xclip"):
            subprocess.run(
                ["xclip", "-selection", self.selection],
                input=value.encode("utf-8"),
                check=True,
            )
            return

        if shutil.which("xsel"):
            subprocess.run(
                ["xsel", f"--{self.selection}", "--input"],
                input=value.encode("utf-8"),
                check=True,
            )
            return

        PyperclipClipboardAdapter().set_text(value)

    def get_text(self) -> str:
        if shutil.which("wl-paste"):
            result = subprocess.run(
                ["wl-paste"],
                capture_output=True,
                text=True,
                check=False,
            )
            return result.stdout

        if shutil.which("xclip"):
            result = subprocess.run(
                ["xclip", "-selection", self.selection, "-o"],
                capture_output=True,
                text=True,
                check=False,
            )
            return result.stdout

        if shutil.which("xsel"):
            result = subprocess.run(
                ["xsel", f"--{self.selection}", "--output"],
                capture_output=True,
                text=True,
                check=False,
            )
            return result.stdout

        return PyperclipClipboardAdapter().get_text()

    def clear(self) -> None:
        self.set_text("")


class PyperclipClipboardAdapter(ClipboardAdapter):
    """
    Универсальный fallback.
    """

    def set_text(self, value: str) -> None:
        pyperclip: Any = importlib.import_module("pyperclip")
        pyperclip.copy(value)

    def get_text(self) -> str:
        pyperclip: Any = importlib.import_module("pyperclip")
        return pyperclip.paste()

    def clear(self) -> None:
        self.set_text("")


class TkinterClipboardAdapter(ClipboardAdapter):
    """
    Последний fallback через Tkinter root.
    """

    def __init__(self, root) -> None:
        self.root = root

    def set_text(self, value: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.root.update()

    def get_text(self) -> str:
        try:
            return self.root.clipboard_get()
        except Exception:
            return ""

    def clear(self) -> None:
        self.root.clipboard_clear()
        self.root.update()


def get_platform_clipboard_adapter(root=None) -> ClipboardAdapter:
    system = platform.system()

    try:
        if system == "Windows":
            return WindowsClipboardAdapter()

        if system == "Darwin":
            return MacOSClipboardAdapter()

        if system == "Linux":
            return LinuxClipboardAdapter(selection="clipboard")

    except Exception:
        pass

    try:
        return PyperclipClipboardAdapter()
    except Exception:
        if root is not None:
            return TkinterClipboardAdapter(root)

    raise RuntimeError("No clipboard adapter available")