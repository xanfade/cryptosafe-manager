from __future__ import annotations

import secrets
import string


class PasswordGenerator:
    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = "!@#$%^&*()-_=+[]{};:,.?/"

    def generate(
        self,
        length: int = 20,
        use_lowercase: bool = True,
        use_uppercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
    ) -> str:
        pools = []
        required_chars = []

        if use_lowercase:
            pools.append(self.lowercase)
            required_chars.append(secrets.choice(self.lowercase))
        if use_uppercase:
            pools.append(self.uppercase)
            required_chars.append(secrets.choice(self.uppercase))
        if use_digits:
            pools.append(self.digits)
            required_chars.append(secrets.choice(self.digits))
        if use_symbols:
            pools.append(self.symbols)
            required_chars.append(secrets.choice(self.symbols))

        if not pools:
            raise ValueError("Нужно выбрать хотя бы один набор символов.")

        if length < len(required_chars):
            raise ValueError("Длина пароля меньше количества обязательных групп символов.")

        all_chars = "".join(pools)
        result = required_chars[:]

        while len(result) < length:
            result.append(secrets.choice(all_chars))

        secrets.SystemRandom().shuffle(result)
        return "".join(result)