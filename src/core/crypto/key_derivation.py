from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass, asdict

from argon2.low_level import Type, hash_secret_raw


@dataclass
class Argon2Params:
    time_cost: int = 3
    memory_cost: int = 65536
    parallelism: int = 4
    hash_len: int = 32
    salt_len: int = 16
    type: str = "id"

    def validate(self) -> None:
        if self.time_cost < 3:
            raise ValueError("Argon2 time_cost должен быть >= 3")
        if self.memory_cost < 65536:
            raise ValueError("Argon2 memory_cost должен быть >= 65536 KiB")
        if self.parallelism < 1 or self.parallelism > 8:
            raise ValueError("Argon2 parallelism вне допустимого диапазона")
        if self.hash_len < 16 or self.hash_len > 64:
            raise ValueError("Argon2 hash_len вне допустимого диапазона")
        if self.salt_len < 16:
            raise ValueError("Argon2 salt_len должен быть >= 16")

    def to_json(self) -> bytes:
        return json.dumps(asdict(self), ensure_ascii=False).encode("utf-8")

    @classmethod
    def from_json(cls, raw: bytes) -> "Argon2Params":
        return cls(**json.loads(raw.decode("utf-8")))


@dataclass
class PBKDF2Params:
    iterations: int = 100_000
    salt_len: int = 16
    dklen: int = 32
    hash_name: str = "sha256"

    def validate(self) -> None:
        if self.iterations < 100_000:
            raise ValueError("PBKDF2 iterations должен быть >= 100000")
        if self.salt_len < 16:
            raise ValueError("PBKDF2 salt_len должен быть >= 16")
        if self.dklen != 32:
            raise ValueError("PBKDF2 dklen должен быть 32 для AES-256")

    def to_json(self) -> bytes:
        return json.dumps(asdict(self), ensure_ascii=False).encode("utf-8")

    @classmethod
    def from_json(cls, raw: bytes) -> "PBKDF2Params":
        return cls(**json.loads(raw.decode("utf-8")))


def generate_salt(length: int = 16) -> bytes:
    if length < 16:
        raise ValueError("Соль должна быть не меньше 16 байт")
    return os.urandom(length)


def derive_auth_hash(password: str, salt: bytes, params: Argon2Params) -> bytes:
    params.validate()
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=params.hash_len,
        type=Type.ID,
    )


def verify_auth_hash(password: str, salt: bytes, expected_hash: bytes, params: Argon2Params) -> bool:
    actual = derive_auth_hash(password, salt, params)
    return secrets.compare_digest(actual, expected_hash)


def derive_encryption_key(password: str, salt: bytes, params: PBKDF2Params) -> bytes:
    params.validate()
    return hashlib.pbkdf2_hmac(
        params.hash_name,
        password.encode("utf-8"),
        salt,
        params.iterations,
        dklen=params.dklen,
    )