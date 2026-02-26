import hashlib
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class KeyParams:
    # Заглушка параметров KDF для Спринта 2 (PBKDF2/Argon2 и т.д.)
    iterations: int = 100_000


class KeyManager:
    """
    Заглушка для Спринта 1.

    """

    def __init__(self, params: Optional[KeyParams] = None):
        self.params = params or KeyParams()

    def derive_key(self, password: str, salt: bytes) -> bytes:
        # Заглушка KDF: sha256( password || salt )
        # В Спринте 2 заменим на нормальную KDF (PBKDF2/Argon2) и будем хранить параметры в key_store.
        if not isinstance(password, str) or not isinstance(salt, (bytes, bytearray)):
            raise TypeError("password должен быть str, salt должен быть bytes/bytearray")

        data = password.encode("utf-8") + bytes(salt)
        return hashlib.sha256(data).digest()

    def store_key(self, *args, **kwargs):
        # Спринт 2: сохранять соль/хэш/параметры в таблицу key_store
        raise NotImplementedError("store_key будет реализован в Спринте 2")

    def load_key(self, *args, **kwargs):
        # Спринт 2: загружать соль/хэш/параметры из таблицы key_store
        raise NotImplementedError("load_key будет реализован в Спринте 2")

    def generate_salt(self, n: int = 16) -> bytes:
        # Генерация соли (может пригодиться уже в Спринте 1 при первичной настройке)
        return os.urandom(n)
