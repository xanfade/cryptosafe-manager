import gc
import time
import tracemalloc

from src.core.crypto.authentication import AuthenticationService
from src.core.key_manager import KeyManager
from src.core.state_manager import StateManager
from src.core.vault.entry_manager import EntryManager


ENTRY_COUNT = 1000

MAX_LOAD_SECONDS = 2.0
MAX_SEARCH_SECONDS = 0.2
MAX_MEMORY_MB = 50.0


def _bootstrap_entry_manager(test_db):
    key_manager = KeyManager(test_db)
    key_manager.initialize_master_password("StrongPass123!")
    auth = AuthenticationService(key_manager, StateManager())
    auth.login("StrongPass123!")
    return EntryManager(test_db, key_manager)


def _make_entry(i: int) -> dict:
    return {
        "title": f"Service {i}",
        "username": f"user{i}@example.com",
        "password": f"Pass{i}!StrongValue",
        "url": f"https://example.com/{i}",
        "notes": f"Notes for service {i}",
        "category": "work" if i % 2 == 0 else "personal",
        "tags": f"tag{i},tag-common",
    }


def _search_entries(entries, query: str):
    q = query.casefold().strip()
    return [
        entry
        for entry in entries
        if q in entry.title.casefold()
        or q in entry.username.casefold()
        or q in entry.url.casefold()
        or q in entry.notes.casefold()
        or q in entry.category.casefold()
        or q in entry.tags.casefold()
    ]


def test_perf_load_1000_entries_under_2_seconds(test_db):
    manager = _bootstrap_entry_manager(test_db)

    for i in range(ENTRY_COUNT):
        manager.create_entry(_make_entry(i))

    # прогрев
    warmup = manager.get_all_entries()
    assert len(warmup) == ENTRY_COUNT

    gc.collect()
    start = time.perf_counter()
    entries = manager.get_all_entries()
    elapsed = time.perf_counter() - start

    assert len(entries) == ENTRY_COUNT
    assert elapsed < MAX_LOAD_SECONDS, (
        f"Загрузка {ENTRY_COUNT} записей заняла {elapsed:.3f} c, "
        f"что превышает лимит {MAX_LOAD_SECONDS:.3f} c"
    )


def test_perf_search_1000_entries_under_200ms(test_db):
    manager = _bootstrap_entry_manager(test_db)

    for i in range(ENTRY_COUNT):
        manager.create_entry(_make_entry(i))

    entries = manager.get_all_entries()
    assert len(entries) == ENTRY_COUNT

    # прогрев
    warmup = _search_entries(entries, "service 99")
    assert warmup

    start = time.perf_counter()
    result = _search_entries(entries, "service 99")
    elapsed = time.perf_counter() - start

    assert result
    assert elapsed < MAX_SEARCH_SECONDS, (
        f"Поиск по {ENTRY_COUNT} записям занял {elapsed:.6f} c, "
        f"что превышает лимит {MAX_SEARCH_SECONDS:.3f} c"
    )


def test_perf_memory_under_50mb_for_1000_loaded_entries(test_db):
    manager = _bootstrap_entry_manager(test_db)

    for i in range(ENTRY_COUNT):
        manager.create_entry(_make_entry(i))

    gc.collect()
    tracemalloc.start()

    entries = manager.get_all_entries()

    current_bytes, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mb = peak_bytes / (1024 * 1024)

    assert len(entries) == ENTRY_COUNT
    assert peak_mb < MAX_MEMORY_MB, (
        f"Пиковое потребление памяти при загрузке {ENTRY_COUNT} записей "
        f"составило {peak_mb:.2f} MB, что превышает лимит {MAX_MEMORY_MB:.2f} MB"
    )