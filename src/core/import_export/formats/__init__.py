from src.core.import_export.formats.csv_handler import CsvFormatHandler
from src.core.import_export.formats.json_handler import JsonFormatHandler
from src.core.import_export.formats.lastpass_csv_handler import LastPassCsvFormatHandler
from src.core.import_export.formats.password_manager_json_handler import PasswordManagerJsonFormatHandler


def get_format_handler(name: str):
    normalized = name.lower()
    if normalized == "json":
        return JsonFormatHandler()
    if normalized == "csv":
        return CsvFormatHandler()
    if normalized in {"password_manager_json", "bitwarden_json"}:
        return PasswordManagerJsonFormatHandler()
    if normalized == "lastpass_csv":
        return LastPassCsvFormatHandler()
    raise ValueError(f"unsupported import/export format: {name}")


__all__ = [
    "CsvFormatHandler",
    "JsonFormatHandler",
    "LastPassCsvFormatHandler",
    "PasswordManagerJsonFormatHandler",
    "get_format_handler",
]
