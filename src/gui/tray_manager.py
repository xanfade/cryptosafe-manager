from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from typing import Callable

try:
    import pystray
    from PIL import Image, ImageDraw
except Exception:  # pragma: no cover
    pystray = None
    Image = None
    ImageDraw = None


@dataclass
class TrayState:
    locked: bool = True
    crypto_busy: bool = False
    clipboard_active: bool = False
    security_level: str = "advanced"


class TrayController:
    def __init__(
        self,
        title: str,
        run_on_ui: Callable[[Callable[[], None]], None],
        on_show: Callable[[], None],
        on_lock: Callable[[], None],
        on_unlock: Callable[[], None],
        on_quick_search: Callable[[], None],
        on_clear_clipboard: Callable[[], None],
        on_panic_mode: Callable[[], None],
        on_settings: Callable[[], None],
        on_exit: Callable[[], None],
    ):
        self._enabled = bool(pystray and Image and ImageDraw)
        self._title = title
        self._run_on_ui = run_on_ui
        self._callbacks = {
            "show": on_show,
            "lock": on_lock,
            "unlock": on_unlock,
            "quick_search": on_quick_search,
            "clear_clipboard": on_clear_clipboard,
            "panic_mode": on_panic_mode,
            "settings": on_settings,
            "exit": on_exit,
        }
        self.state = TrayState()
        self._icon = None
        self._anim_phase = 0
        self._anim_thread = None
        self._anim_running = False

    @property
    def enabled(self) -> bool:
        return self._enabled

    def start(self) -> bool:
        if not self._enabled:
            return False
        if self._icon is not None:
            return True
        self._icon = pystray.Icon(self._title, self._build_icon(), self._title, self._build_menu())
        self._icon.run_detached()
        return True

    def stop(self) -> None:
        self._stop_animation()
        if self._icon is not None:
            try:
                self._icon.stop()
            finally:
                self._icon = None

    def set_locked(self, locked: bool) -> None:
        self.state.locked = bool(locked)
        self._refresh_icon()

    def set_crypto_busy(self, busy: bool) -> None:
        busy = bool(busy)
        if self.state.crypto_busy == busy:
            return
        self.state.crypto_busy = busy
        if busy:
            self._start_animation()
        else:
            self._stop_animation()
        self._refresh_icon()

    def set_clipboard_active(self, active: bool) -> None:
        self.state.clipboard_active = bool(active)
        self._refresh_icon()

    def set_security_level(self, level: str) -> None:
        level = str(level or "advanced").lower()
        if level not in {"basic", "advanced", "paranoid"}:
            level = "advanced"
        self.state.security_level = level
        self._refresh_icon()

    def notify(self, title: str, message: str) -> None:
        if self._icon is None:
            return
        try:
            self._icon.notify(message, title)
        except Exception:
            pass

    def _refresh_icon(self) -> None:
        if self._icon is None:
            return
        self._icon.icon = self._build_icon()
        self._icon.title = self._title_status()
        self._icon.menu = self._build_menu()
        self._icon.update_menu()

    def _build_icon(self):
        image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        if self.state.locked:
            color = (220, 38, 38, 255)
        else:
            if self.state.security_level == "basic":
                color = (34, 197, 94, 255)
            elif self.state.security_level == "advanced":
                color = (59, 130, 246, 255)
            else:
                color = (124, 58, 237, 255)
        if self.state.crypto_busy:
            # Animated yellow ring phase.
            ring = [(6 + self._anim_phase, 6 + self._anim_phase), (58 - self._anim_phase, 58 - self._anim_phase)]
            draw.ellipse(ring, outline=(250, 204, 21, 255), width=4)
        draw.ellipse((12, 12, 52, 52), fill=color)
        return image

    def _title_status(self) -> str:
        state = "Заблокировано" if self.state.locked else "Разблокировано"
        clip = "Буфер: активен" if self.state.clipboard_active else "Буфер: пуст"
        busy = "Крипто: занято" if self.state.crypto_busy else "Крипто: ожидание"
        level_map = {"basic": "Базовый", "advanced": "Продвинутый", "paranoid": "Параноидальный"}
        level = level_map.get(self.state.security_level, "Продвинутый")
        return f"{self._title} | {state} | Уровень: {level} | {clip} | {busy}"

    def _wrap_callback(self, key: str):
        def _handler(icon=None, item=None):
            callback = self._callbacks[key]
            self._run_on_ui(callback)

        return _handler

    def _build_menu(self):
        return pystray.Menu(
            pystray.MenuItem("Показать окно", self._wrap_callback("show")),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Заблокировать хранилище", self._wrap_callback("lock")),
            pystray.MenuItem("Разблокировать хранилище", self._wrap_callback("unlock")),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Быстрый поиск...", self._wrap_callback("quick_search")),
            pystray.MenuItem(
                lambda _item: f"Буфер: {'активен' if self.state.clipboard_active else 'пуст'}",
                lambda icon, item: None,
                enabled=False,
            ),
            pystray.MenuItem(
                lambda _item: f"Уровень безопасности: { {'basic': 'Базовый', 'advanced': 'Продвинутый', 'paranoid': 'Параноидальный'}.get(self.state.security_level, 'Продвинутый') }",
                lambda icon, item: None,
                enabled=False,
            ),
            pystray.MenuItem("Очистить буфер", self._wrap_callback("clear_clipboard")),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Режим паники", self._wrap_callback("panic_mode")),
            pystray.MenuItem("Настройки", self._wrap_callback("settings")),
            pystray.MenuItem("Выход", self._wrap_callback("exit")),
        )

    def _start_animation(self) -> None:
        if self._anim_running:
            return
        self._anim_running = True

        def _loop():
            while self._anim_running:
                self._anim_phase = (self._anim_phase + 1) % 4
                try:
                    self._refresh_icon()
                except Exception:
                    pass
                time.sleep(0.35)

        self._anim_thread = threading.Thread(target=_loop, daemon=True)
        self._anim_thread.start()

    def _stop_animation(self) -> None:
        self._anim_running = False
