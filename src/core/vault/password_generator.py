import secrets
import string


class PasswordGenerator:
    AMBIGUOUS_CHARS = {"l", "I", "1", "0", "O"}
    SPECIAL_CHARS = "!@#$%^&*"

    @classmethod
    def generate(
        cls,
        length: int = 16,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_special: bool = True,
        exclude_ambiguous: bool = False,
    ) -> str:
        if not 8 <= length <= 64:
            raise ValueError("Длина пароля должна быть в диапазоне от 8 до 64 символов.")

        char_sets = []

        if use_uppercase:
            chars = cls._filter_ambiguous(string.ascii_uppercase, exclude_ambiguous)
            if chars:
                char_sets.append(chars)

        if use_lowercase:
            chars = cls._filter_ambiguous(string.ascii_lowercase, exclude_ambiguous)
            if chars:
                char_sets.append(chars)

        if use_digits:
            chars = cls._filter_ambiguous(string.digits, exclude_ambiguous)
            if chars:
                char_sets.append(chars)

        if use_special:
            chars = cls._filter_ambiguous(cls.SPECIAL_CHARS, exclude_ambiguous)
            if chars:
                char_sets.append(chars)

        if not char_sets:
            raise ValueError("Нужно выбрать хотя бы один набор символов.")

        if length < len(char_sets):
            raise ValueError(
                "Длина пароля слишком мала для выбранных наборов символов."
            )

        required_chars = [secrets.choice(char_set) for char_set in char_sets]
        all_chars = "".join(char_sets)

        password_chars = required_chars[:]
        for _ in range(length - len(required_chars)):
            password_chars.append(secrets.choice(all_chars))

        cls._secure_shuffle(password_chars)

        return "".join(password_chars)

    @classmethod
    def _filter_ambiguous(cls, chars: str, exclude_ambiguous: bool) -> str:
        if not exclude_ambiguous:
            return chars
        return "".join(ch for ch in chars if ch not in cls.AMBIGUOUS_CHARS)

    @staticmethod
    def _secure_shuffle(items: list[str]) -> None:
        for i in range(len(items) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            items[i], items[j] = items[j], items[i]