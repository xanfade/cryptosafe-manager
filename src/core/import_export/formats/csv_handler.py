from __future__ import annotations

import csv
import io
import json
from typing import Any


class CsvFormatHandler:
    FIELDNAMES = [
        "title",
        "username",
        "password",
        "url",
        "notes",
        "category",
        "tags",
    ]

    def serialize(self, entries: list[dict[str, Any]], metadata: dict[str, Any] | None = None) -> bytes:
        output = io.StringIO()
        if metadata:
            output.write(f"# cryptosafe_metadata={json.dumps(metadata, ensure_ascii=False)}\n")
        writer = csv.DictWriter(output, fieldnames=self.FIELDNAMES)
        writer.writeheader()
        for entry in entries:
            writer.writerow({field: entry.get(field, "") for field in self.FIELDNAMES})
        return output.getvalue().encode("utf-8")

    def deserialize(self, payload: bytes) -> list[dict[str, Any]]:
        text = payload.decode("utf-8-sig")
        lines = [line for line in text.splitlines() if not line.startswith("#")]
        text = "\n".join(lines)
        sample = text[:2048]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(io.StringIO(text), dialect=dialect)
        return [{field: row.get(field, "") for field in self.FIELDNAMES} for row in reader]
