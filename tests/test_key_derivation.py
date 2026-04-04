import time
import statistics

from src.core.crypto.key_derivation import (
    Argon2Params,
    PBKDF2Params,
    derive_auth_hash,
    derive_encryption_key,
    verify_auth_hash,
)


def test_argon2_different_valid_params_produce_valid_hashes():
    password = "StrongPass123!"
    salt = b"0123456789abcdef"

    params_list = [
        Argon2Params(time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16),
        Argon2Params(time_cost=4, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16),
        Argon2Params(time_cost=3, memory_cost=131072, parallelism=4, hash_len=32, salt_len=16),
        Argon2Params(time_cost=5, memory_cost=65536, parallelism=2, hash_len=64, salt_len=16),
    ]

    hashes = []
    for params in params_list:
        h = derive_auth_hash(password, salt, params)

        assert isinstance(h, bytes)
        assert len(h) == params.hash_len
        assert verify_auth_hash(password, salt, h, params) is True

        hashes.append(h)

    assert len(set(hashes)) == len(hashes)


def test_pbkdf2_consistency_100_times():
    password = "StrongPass123!"
    salt = b"0123456789abcdef"
    params = PBKDF2Params(iterations=100_000, dklen=32)

    first = derive_encryption_key(password, salt, params)

    for _ in range(100):
        derived = derive_encryption_key(password, salt, params)
        assert derived == first


def test_compare_digest_timing_regression():
    password = "StrongPass123!"
    wrong_password = "WrongPass123!"
    salt = b"0123456789abcdef"
    params = Argon2Params()

    expected_hash = derive_auth_hash(password, salt, params)

    # Небольшой прогрев
    verify_auth_hash(password, salt, expected_hash, params)
    verify_auth_hash(wrong_password, salt, expected_hash, params)

    ok_times = []
    bad_times = []

    for _ in range(12):
        t0 = time.perf_counter()
        assert verify_auth_hash(password, salt, expected_hash, params) is True
        ok_times.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        assert verify_auth_hash(wrong_password, salt, expected_hash, params) is False
        bad_times.append(time.perf_counter() - t0)

    ok_avg = statistics.mean(ok_times)
    bad_avg = statistics.mean(bad_times)

    # Это не математическое доказательство constant-time,
    # а регрессионная проверка без сильного перекоса
    ratio = abs(ok_avg - bad_avg) / max(ok_avg, bad_avg)
    assert ratio < 0.15


def test_secure_cache_clear_zeroizes_underlying_bytearray():
    from src.core.crypto.key_storage import SecureKeyCache

    cache = SecureKeyCache()
    secret = b"1234567890abcdef1234567890abcdef"

    cache.put(secret)
    assert cache._entry is not None

    raw_before_clear = cache._entry.value
    assert isinstance(raw_before_clear, bytearray)
    assert bytes(raw_before_clear) == secret

    cache.clear()

    assert bytes(raw_before_clear) == b"\x00" * len(secret)
    assert cache._entry is None