from src.core.crypto.placeholder import AES256Placeholder


def test_encrypt_decrypt_roundtrip():
    svc = AES256Placeholder()
    key = b"secret"
    data = b"hello"
    ct = svc.encrypt(data, key)
    assert svc.decrypt(ct, key) == data
