from typing import Any, Callable, Dict, List, Type
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class EntryCreated:
    entry_id: int


@dataclass
class EntryRead:
    entry_id: int
    access_type: str = "single"


@dataclass
class EntryListViewed:
    count: int = 0


@dataclass
class VaultSearchPerformed:
    query_hash: str
    result_count: int = 0


@dataclass
class EntryUpdated:
    entry_id: int


@dataclass
class EntryDeleted:
    entry_id: int


@dataclass
class UserLoggedIn:
    user: str = "local"


@dataclass
class UserLoggedOut:
    user: str = "local"


@dataclass
class PasswordChanged:
    user: str = "local"


@dataclass
class LoginFailed:
    user: str = "local"
    failed_attempts: int = 0
    delay_seconds: int = 0


@dataclass
class ClipboardCopied:
    data_type: str = "text"
    entry_id: int | None = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ClipboardCleared:
    pass


@dataclass
class ClipboardAutoCleared:
    pass


@dataclass
class AppFocusLost:
    pass


@dataclass
class AppFocusGained:
    pass


@dataclass
class AppMinimized:
    pass


@dataclass
class AppRestored:
    pass


@dataclass
class AutoLocked:
    reason: str = "inactivity"


@dataclass
class VaultUnlocked:
    user: str = "local"


@dataclass
class AppShutdown:
    reason: str = "user_exit"


@dataclass
class ConfigurationChanged:
    setting_key: str
    source: str = "settings"


@dataclass
class AuditDataImported:
    format: str = "signed_json"
    entry_count: int = 0


@dataclass
class VaultDataExported:
    format: str = "json"
    entry_count: int = 0
    scope: str = "full"
    encrypted: bool = True
    protection_mode: str = "master"


@dataclass
class VaultDataImported:
    format: str = "json"
    entry_count: int = 0
    imported_count: int = 0
    updated_count: int = 0
    mode: str = "merge"


@dataclass
class EntryShared:
    entry_id: int
    recipient: str
    method: str = "public_key"
    delivery: str = "qr"
    permission: str = "read-only"
    expires_in_days: int = 7


@dataclass
class ClipboardImageScanned:
    source: str = "clipboard"


@dataclass
class CloudSyncRequested:
    provider: str = "future"
    scope: str = "vault_export"


@dataclass
class NetworkShareRequested:
    protocol: str = "future"
    recipient: str = ""


@dataclass
class PanicModeActivated:
    reason: str = "manual"


@dataclass
class TotpAccessed:
    entry_id: int | None = None
    operation: str = "copy"


@dataclass
class ClipboardCopyBlocked:
    entry_id: int | None
    reason: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ClipboardSuspiciousActivity:
    reason: str
    entry_id: int | None = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


class EventBus:
    def __init__(self):
        self._sync: Dict[Type[Any], List[Callable[[Any], None]]] = {}
        self._async: Dict[Type[Any], List[Callable[[Any], None]]] = {}
        self._pool = ThreadPoolExecutor(max_workers=4)
        self._futures: list[Future] = []

    def subscribe(self, event_type: Type[Any], handler: Callable[[Any], None], async_: bool = False):
        (self._async if async_ else self._sync).setdefault(event_type, []).append(handler)

    def publish(self, event: Any):
        event_type = type(event)

        for handler in self._sync.get(event_type, []):
            handler(event)

        for handler in self._async.get(event_type, []):
            self._futures.append(self._pool.submit(handler, event))

    def drain_async(self, timeout: float | None = None) -> None:
        futures = self._futures
        self._futures = []
        for future in futures:
            future.result(timeout=timeout)
