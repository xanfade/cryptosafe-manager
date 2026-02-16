from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Type
from concurrent.futures import ThreadPoolExecutor

@dataclass
class EntryAdded: entry_id: int
@dataclass
class EntryUpdated: entry_id: int
@dataclass
class EntryDeleted: entry_id: int
@dataclass
class UserLoggedIn: user: str = "local"
@dataclass
class UserLoggedOut: user: str = "local"
@dataclass
class ClipboardCopied: entry_id: int
@dataclass
class ClipboardCleared: pass

class EventBus:
    def __init__(self):
        self._sync: Dict[Type[Any], List[Callable[[Any], None]]] = {}
        self._async: Dict[Type[Any], List[Callable[[Any], None]]] = {}
        self._pool = ThreadPoolExecutor(max_workers=4)

    def subscribe(self, event_type: Type[Any], handler: Callable[[Any], None], async_: bool = False):
        (self._async if async_ else self._sync).setdefault(event_type, []).append(handler)

    def publish(self, event: Any):
        et = type(event)
        for h in self._sync.get(et, []):
            h(event)
        for h in self._async.get(et, []):
            self._pool.submit(h, event)
