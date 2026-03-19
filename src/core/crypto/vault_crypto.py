from __future__ import annotations


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("Ключ шифрования пустой")
    repeated_key = key * (len(data) // len(key) + 1)
    return bytes(b ^ repeated_key[i] for i, b in enumerate(data))


def encrypt_record(key: bytes, text: str) -> bytes:
    if text is None:
        text = ""
    data = text.encode("utf-8")
    return _xor_bytes(data, key)


def decrypt_record(key: bytes, ciphertext: bytes) -> str:
    if ciphertext is None:
        return ""
    data = _xor_bytes(ciphertext, key)
    return data.decode("utf-8")