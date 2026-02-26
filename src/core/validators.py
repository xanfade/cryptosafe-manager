import re


def clean_text(s: str, max_len: int = 200) -> str:
    # Убираем лишние пробелы и ограничиваем длину
    s = (s or "").strip()
    if len(s) > max_len:
        s = s[:max_len]
    return s


def clean_url(url: str, max_len: int = 500) -> str:
    url = (url or "").strip()
    if len(url) > max_len:
        url = url[:max_len]
    # Простейшая проверка на "вменяемость" URL (заглушка)
    if url and not re.match(r"^https?://", url):
        # Можно либо дописать https://, либо отклонить. В Sprint 1 проще отклонить.
        raise ValueError("URL должен начинаться с http:// или https://")
    return url


def validate_required(name: str, value: str):
    if not (value or "").strip():
        raise ValueError(f"Поле '{name}' обязательно")
