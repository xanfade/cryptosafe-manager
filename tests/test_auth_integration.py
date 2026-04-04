from src.core.crypto.authentication import AuthenticationService
from src.core.key_manager import KeyManager
from src.core.state_manager import StateManager


def test_login_flow(test_db):
    km = KeyManager(test_db)
    km.initialize_master_password("StrongPass123!")

    state = StateManager()
    auth = AuthenticationService(km, state)

    key = auth.login("StrongPass123!")

    assert isinstance(key, bytes)
    assert len(key) == 32
    assert state.session.unlocked is True
    assert km.get_encryption_key() == key