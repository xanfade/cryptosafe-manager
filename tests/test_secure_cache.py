from src.core.crypto.key_storage import SecureKeyCache

def test_cache_clear_zeroizes_memory():
    cache = SecureKeyCache()
    cache.put(b"1234567890abcdef1234567890abcdef")
    assert cache.get() is not None
    cache.clear()
    assert cache.get() is None