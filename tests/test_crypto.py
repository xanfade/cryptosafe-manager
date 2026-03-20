from src.core.crypto.placeholder import AES256Placeholder


class DummyKeyManager:
    def __init__(self, key=b"secret"):
        self._key = key

    def get_encryption_key(self):
        return self._key


def test_encrypt_decrypt_roundtrip():
    svc = AES256Placeholder(DummyKeyManager())
    data = b"hello"
    ct = svc.encrypt(data)
    assert svc.decrypt(ct) == data