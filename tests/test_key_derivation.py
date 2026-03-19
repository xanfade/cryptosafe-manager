from src.core.crypto.key_derivation import (
    Argon2Params,
    PBKDF2Params,
    derive_auth_hash,
    derive_encryption_key,
    verify_auth_hash,
)

def test_argon2_consistency():
    password = "StrongPass123!"
    salt = b"0123456789abcdef"
    params = Argon2Params()

    h1 = derive_auth_hash(password, salt, params)
    h2 = derive_auth_hash(password, salt, params)

    assert h1 == h2
    assert len(h1) == 32

def test_argon2_verify_ok():
    password = "StrongPass123!"
    salt = b"0123456789abcdef"
    params = Argon2Params()
    h = derive_auth_hash(password, salt, params)

    assert verify_auth_hash(password, salt, h, params) is True
    assert verify_auth_hash("WrongPass123!", salt, h, params) is False

def test_pbkdf2_consistency_100_times():
    password = "StrongPass123!"
    salt = b"abcdef0123456789"
    params = PBKDF2Params()

    values = {derive_encryption_key(password, salt, params) for _ in range(100)}
    assert len(values) == 1