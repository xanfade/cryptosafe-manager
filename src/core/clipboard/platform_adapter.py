class ClipboardAdapter:
    def set_text(self, value: str) -> None:
        raise NotImplementedError

    def get_text(self) -> str:
        raise NotImplementedError

    def clear(self) -> None:
        raise NotImplementedError


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