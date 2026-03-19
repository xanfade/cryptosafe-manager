from src.database.db import Database
from src.core.key_manager import KeyManager
from src.core.crypto.authentication import AuthenticationService

def test_login_flow(test_db):
    km = KeyManager(test_db)
    km.initialize_master_password("StrongPass123!")

    auth = AuthenticationService(km)
    key = auth.login("StrongPass123!")

    assert isinstance(key, bytes)
    assert len(key) == 32
    assert km.get_encryption_key() == key