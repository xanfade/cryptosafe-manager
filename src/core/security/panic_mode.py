from __future__ import annotations

from typing import Callable


class PanicMode:
    def __init__(
        self,
        enabled: bool = True,
        lock_on_activate: bool = True,
        clear_clipboard_on_activate: bool = True,
        close_windows_on_activate: bool = True,
        close_app_on_activate: bool = False,
        stealth_fake_error: bool = False,
        stealth_decoy_command: str = "",
        stealth_redirect_url: str = "",
    ):
        self.enabled = bool(enabled)
        self.lock_on_activate = bool(lock_on_activate)
        self.clear_clipboard_on_activate = bool(clear_clipboard_on_activate)
        self.close_windows_on_activate = bool(close_windows_on_activate)
        self.close_app_on_activate = bool(close_app_on_activate)
        self.stealth_fake_error = bool(stealth_fake_error)
        self.stealth_decoy_command = str(stealth_decoy_command or "").strip()
        self.stealth_redirect_url = str(stealth_redirect_url or "").strip()

    def activate(
        self,
        lock_callback: Callable[[], None] | None = None,
        clear_clipboard_callback: Callable[[], None] | None = None,
        close_windows_callback: Callable[[], None] | None = None,
        close_app_callback: Callable[[], None] | None = None,
        fake_error_callback: Callable[[], None] | None = None,
        launch_decoy_callback: Callable[[str], None] | None = None,
        redirect_callback: Callable[[str], None] | None = None,
    ) -> bool:
        if not self.enabled:
            return False

        if self.clear_clipboard_on_activate and clear_clipboard_callback:
            clear_clipboard_callback()
        if self.close_windows_on_activate and close_windows_callback:
            close_windows_callback()
        if self.lock_on_activate and lock_callback:
            lock_callback()
        if self.stealth_fake_error and fake_error_callback:
            fake_error_callback()
        if self.stealth_decoy_command and launch_decoy_callback:
            launch_decoy_callback(self.stealth_decoy_command)
        if self.stealth_redirect_url and redirect_callback:
            redirect_callback(self.stealth_redirect_url)
        if self.close_app_on_activate and close_app_callback:
            close_app_callback()
        return True
