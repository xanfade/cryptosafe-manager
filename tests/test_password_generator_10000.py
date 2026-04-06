import string

from src.core.vault.password_generator import PasswordGenerator


def test_password_generator_10000_passwords():
    PasswordGenerator.clear_history()

    passwords = []
    seen = set()

    special_chars = set(PasswordGenerator.SPECIAL_CHARS)
    ambiguous = PasswordGenerator.AMBIGUOUS_CHARS

    for _ in range(10_000):
        password = PasswordGenerator.generate(
            length=24,
            use_uppercase=True,
            use_lowercase=True,
            use_digits=True,
            use_special=True,
            exclude_ambiguous=True,
            require_strong=True,
            max_attempts=300,
        )

        assert password not in seen
        seen.add(password)
        passwords.append(password)

        assert len(password) == 24
        assert any(ch in string.ascii_uppercase for ch in password)
        assert any(ch in string.ascii_lowercase for ch in password)
        assert any(ch in string.digits for ch in password)
        assert any(ch in special_chars for ch in password)

        assert all(ch not in ambiguous for ch in password)

        score = PasswordGenerator.strength_score(password)
        assert score >= PasswordGenerator.MIN_STRENGTH_SCORE

    assert len(passwords) == 10_000
    assert len(seen) == 10_000