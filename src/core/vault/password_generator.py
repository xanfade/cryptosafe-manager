from __future__ import annotations

import math
import secrets
import string
from collections import deque


class PasswordGenerator:
    AMBIGUOUS_CHARS = {"l", "I", "1", "0", "O"}
    SPECIAL_CHARS = "!@#$%^&*"
    HISTORY_LIMIT = 20
    MIN_STRENGTH_SCORE = 3  # нужно >= 3/4

    # История последних сгенерированных паролей
    _history: deque[str] = deque(maxlen=HISTORY_LIMIT)

    @classmethod
    def generate(
        cls,
        length: int = 16,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_special: bool = True,
        use_symbols: bool | None = None,
        exclude_ambiguous: bool = False,
        require_strong: bool = True,
        max_attempts: int = 100,
    ) -> str:
        """
        Генерирует безопасный пароль.

        GEN-1:
        - вся случайность только через secrets.choice / secrets.randbelow

        GEN-2:
        - длина 8..64, по умолчанию 16
        - выбор наборов символов
        - исключение неоднозначных символов

        GEN-3:
        - гарантируется хотя бы один символ из каждого выбранного набора

        GEN-4:
        - пароль проходит анализ надежности, оценка >= 3/4

        GEN-5:
        - предотвращаются дубликаты среди последних 20 паролей
        """
        if use_symbols is not None:
            use_special = use_symbols

        if not 8 <= length <= 64:
            raise ValueError("Длина пароля должна быть в диапазоне от 8 до 64 символов.")

        char_sets: list[str] = []

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
            raise ValueError("Длина пароля слишком мала для выбранных наборов символов.")

        for _ in range(max_attempts):
            password = cls._generate_once(length, char_sets)

            if cls._is_recent_duplicate(password):
                continue

            if require_strong and cls.strength_score(password, char_sets) < cls.MIN_STRENGTH_SCORE:
                continue

            cls._remember(password)
            return password

        raise RuntimeError(
            "Не удалось сгенерировать уникальный и достаточно надежный пароль "
            "за разумное число попыток."
        )

    @classmethod
    def _generate_once(cls, length: int, char_sets: list[str]) -> str:
        # По одному обязательному символу из каждого выбранного набора
        required_chars = [secrets.choice(char_set) for char_set in char_sets]

        # Общий пул разрешённых символов
        all_chars = "".join(char_sets)

        # Добиваем пароль до нужной длины
        password_chars = required_chars[:]
        for _ in range(length - len(required_chars)):
            password_chars.append(secrets.choice(all_chars))

        # Безопасно перемешиваем
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

    @classmethod
    def _remember(cls, password: str) -> None:
        cls._history.append(password)

    @classmethod
    def _is_recent_duplicate(cls, password: str) -> bool:
        return password in cls._history

    @classmethod
    def get_history_size(cls) -> int:
        return len(cls._history)

    @classmethod
    def clear_history(cls) -> None:
        cls._history.clear()

    @classmethod
    def strength_score(cls, password: str, char_sets: list[str] | None = None) -> int:

        if not password:
            return 0

        # Если наборы не переданы, оцениваем по факту состава пароля
        if char_sets is None:
            char_sets = cls._detect_charsets(password)

        pool_size = sum(len(char_set) for char_set in char_sets)
        if pool_size <= 1:
            return 0

        # Оценка энтропии
        entropy = len(password) * math.log2(pool_size)

        # Штраф за повторы
        unique_ratio = len(set(password)) / len(password)
        if unique_ratio < 0.5:
            entropy -= 10
        elif unique_ratio < 0.7:
            entropy -= 5

        # Штраф за последовательности
        if cls._has_sequence(password):
            entropy -= 8

        # Штраф за слишком простые паттерны
        if cls._has_repeated_blocks(password):
            entropy -= 8

        # Преобразуем в шкалу 0..4
        if entropy < 28:
            return 0
        if entropy < 36:
            return 1
        if entropy < 60:
            return 2
        if entropy < 80:
            return 3
        return 4

    @classmethod
    def _detect_charsets(cls, password: str) -> list[str]:
        char_sets: list[str] = []

        if any(ch in string.ascii_uppercase for ch in password):
            char_sets.append(string.ascii_uppercase)

        if any(ch in string.ascii_lowercase for ch in password):
            char_sets.append(string.ascii_lowercase)

        if any(ch in string.digits for ch in password):
            char_sets.append(string.digits)

        if any(ch in cls.SPECIAL_CHARS for ch in password):
            char_sets.append(cls.SPECIAL_CHARS)

        return char_sets

    @staticmethod
    def _has_sequence(password: str) -> bool:
        sequences = (
            string.ascii_lowercase,
            string.ascii_uppercase,
            string.digits,
        )

        for seq in sequences:
            for i in range(len(seq) - 2):
                part = seq[i:i + 3]
                if part in password or part[::-1] in password:
                    return True
        return False

    @staticmethod
    def _has_repeated_blocks(password: str) -> bool:
        # Например: abab, 1212, qqqq
        if len(set(password)) <= 2 and len(password) >= 4:
            return True

        for size in range(1, max(2, len(password) // 2 + 1)):
            block = password[:size]
            if block * (len(password) // size) == password[:size * (len(password) // size)]:
                if len(password) >= size * 2:
                    return True

        return False