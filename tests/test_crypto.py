from src.core.crypto.placeholder import AES256Placeholder


class DummyKeyManager:
    def get_encryption_key(self):
        return b"1" * 32


def test_encrypt_decrypt_roundtrip():
    svc = AES256Placeholder(DummyKeyManager())
    data = b"hello"

    ct = svc.encrypt(data)
    pt = svc.decrypt(ct)

    assert pt == data
    assert ct != data