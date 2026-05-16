from __future__ import annotations

import platform
import shutil
import subprocess


class ClipboardAdapter:
    def set_text(self, value: str) -> None:
        raise NotImplementedError

    def get_text(self) -> str:
        raise NotImplementedError

    def clear(self) -> None:
        raise NotImplementedError


class WindowsClipboardAdapter(ClipboardAdapter):
    def set_text(self, value: str) -> None:
        import win32clipboard
        import win32con

        win32clipboard.OpenClipboard()
        try:
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardData(win32con.CF_UNICODETEXT, value)
        finally:
            win32clipboard.CloseClipboard()

    def get_text(self) -> str:
        import win32clipboard
        import win32con

        win32clipboard.OpenClipboard()
        try:
            if win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
                return win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
            return ""
        finally:
            win32clipboard.CloseClipboard()

    def clear(self) -> None:
        import win32clipboard

        win32clipboard.OpenClipboard()
        try:
            win32clipboard.EmptyClipboard()
        finally:
            win32clipboard.CloseClipboard()


class MacOSClipboardAdapter(ClipboardAdapter):
    def __init__(self):
        from AppKit import NSPasteboard, NSPasteboardNameGeneral, NSPasteboardTypeString

        self.NSPasteboard = NSPasteboard
        self.NSPasteboardNameGeneral = NSPasteboardNameGeneral
        self.NSPasteboardTypeString = NSPasteboardTypeString

    def _pasteboard(self):
        return self.NSPasteboard.pasteboardWithName_(self.NSPasteboardNameGeneral)

    def set_text(self, value: str) -> None:
        pasteboard = self._pasteboard()
        pasteboard.clearContents()
        pasteboard.declareTypes_owner_([self.NSPasteboardTypeString], None)
        pasteboard.setString_forType_(value, self.NSPasteboardTypeString)

    def get_text(self) -> str:
        value = self._pasteboard().stringForType_(self.NSPasteboardTypeString)
        return value or ""

    def clear(self) -> None:
        self._pasteboard().clearContents()


class LinuxClipboardAdapter(ClipboardAdapter):
    def __init__(self, selection: str = "clipboard"):
        self.selection = selection

    def set_text(self, value: str) -> None:
        if shutil.which("wl-copy"):
            subprocess.run(["wl-copy"], input=value.encode("utf-8"), check=True)
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
            result = subprocess.run(["wl-paste"], capture_output=True, text=True)
            return result.stdout

        if shutil.which("xclip"):
            result = subprocess.run(
                ["xclip", "-selection", self.selection, "-o"],
                capture_output=True,
                text=True,
            )
            return result.stdout

        if shutil.which("xsel"):
            result = subprocess.run(
                ["xsel", f"--{self.selection}", "--output"],
                capture_output=True,
                text=True,
            )
            return result.stdout

        return PyperclipClipboardAdapter().get_text()

    def clear(self) -> None:
        self.set_text("")


class PyperclipClipboardAdapter(ClipboardAdapter):
    def set_text(self, value: str) -> None:
        import pyperclip

        pyperclip.copy(value)

    def get_text(self) -> str:
        import pyperclip

        return pyperclip.paste()

    def clear(self) -> None:
        self.set_text("")


class TkinterClipboardAdapter(ClipboardAdapter):
    def __init__(self, root):
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