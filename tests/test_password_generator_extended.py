import pytest

from src.core.crypto.key_storage import OSKeyringStore, SecureKeyCache
from src.core.vault.password_generator import PasswordGenerator


def test_password_generator_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        PasswordGenerator.generate(length=7)

    with pytest.raises(ValueError):
        PasswordGenerator.generate(
            length=12,
            use_uppercase=False,
            use_lowercase=False,
            use_digits=False,
            use_special=False,
        )


def test_password_generator_excludes_ambiguous_and_tracks_history():
    PasswordGenerator.clear_history()
    password = PasswordGenerator.generate(length=20, exclude_ambiguous=True)

    assert not any(ch in PasswordGenerator.AMBIGUOUS_CHARS for ch in password)
    assert PasswordGenerator.get_history_size() == 1
    assert PasswordGenerator._is_recent_duplicate(password) is True


def test_password_generator_strength_helpers_detect_patterns():
    assert PasswordGenerator._has_sequence("abcXYZ123") is True
    assert PasswordGenerator._has_repeated_blocks("abababab") is True
    assert PasswordGenerator.strength_score("aaaa1111") <= 1
    assert PasswordGenerator.strength_score("ValidStrong123!") >= 3


def test_secure_key_cache_focus_and_minimize_clear():
    cache = SecureKeyCache(ttl_seconds=3600, clear_on_focus_loss=True, clear_on_minimize=True)
    cache.put(b"0123456789abcdef")
    assert cache.has_key() is True

    cache.on_app_focus_lost()
    assert cache.has_key() is False

    cache.put(b"fedcba9876543210")
    cache.on_app_minimized()
    assert cache.has_key() is False


def test_os_keyring_store_uses_backend(monkeypatch):
    storage = {}

    class FakeKeyring:
        @staticmethod
        def set_password(service, name, value):
            storage[(service, name)] = value

        @staticmethod
        def get_password(service, name):
            return storage.get((service, name))

        @staticmethod
        def delete_password(service, name):
            storage.pop((service, name), None)

    monkeypatch.setattr("src.core.crypto.key_storage.keyring", FakeKeyring)

    store = OSKeyringStore(service_name="tests")
    assert store.is_available() is True
    store.set_secret("token", "value")
    assert store.get_secret("token") == "value"
    store.delete_secret("token")
    assert store.get_secret("token") is None
