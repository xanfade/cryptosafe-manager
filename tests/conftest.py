import pytest

from src.core.crypto.authentication import AuthenticationService
from src.core.key_manager import KeyManager
from src.core.services.vault_service import VaultService
from src.core.state_manager import StateManager
from src.database.db import Database


MASTER_PASSWORD = "A_StrongPass123!"


@pytest.fixture()
def test_db(tmp_path):
    db_file = tmp_path / "test.db"
    db = Database(str(db_file))
    db.migrate()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def key_manager(test_db):
    km = KeyManager(test_db)
    km.initialize_master_password(MASTER_PASSWORD)
    return km


@pytest.fixture()
def auth_service(key_manager):
    state = StateManager()
    return AuthenticationService(key_manager, state)


@pytest.fixture()
def unlocked_key_manager(key_manager, auth_service):
    auth_service.login(MASTER_PASSWORD)
    return key_manager


@pytest.fixture()
def vault_service(test_db, unlocked_key_manager):
    return VaultService(test_db, unlocked_key_manager)


def make_entry_payload(index: int, **overrides):
    payload = {
        "title": f"Title {index}",
        "username": f"user{index}@example.com",
        "password": f"StrongPass{index}!Aa9",
        "url": f"https://example{index}.com/login",
        "notes": f"Notes for entry {index}",
        "category": "work" if index % 2 == 0 else "personal",
        "tags": "tag1,tag2",
    }
    payload.update(overrides)
    return payload