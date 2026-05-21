from __future__ import annotations

import csv
import io
import json


class LastPassCsvFormatHandler:
    COLUMN_MAP = {
        "name": "title",
        "url": "url",
        "username": "username",
        "password": "password",
        "extra": "notes",
        "grouping": "category",
        "fav": "tags",
    }

    def serialize(self, entries: list[dict], metadata: dict | None = None) -> bytes:
        output = io.StringIO()
        if metadata:
            output.write(f"# cryptosafe_metadata={json.dumps(metadata, ensure_ascii=False)}\n")
        writer = csv.DictWriter(output, fieldnames=list(self.COLUMN_MAP.keys()))
        writer.writeheader()
        for entry in entries:
            row = {}
            for source, target in self.COLUMN_MAP.items():
                row[source] = entry.get(target, "")
            writer.writerow(row)
        return output.getvalue().encode("utf-8")

    def deserialize(self, payload: bytes) -> list[dict]:
        text = payload.decode("utf-8-sig")
        lines = [line for line in text.splitlines() if not line.startswith("#")]
        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        entries = []
        for row in reader:
            entries.append(
                {
                    "title": row.get("name", ""),
                    "username": row.get("username", ""),
                    "password": row.get("password", ""),
                    "url": row.get("url", ""),
                    "notes": row.get("extra", ""),
                    "category": row.get("grouping", ""),
                    "tags": row.get("fav", ""),
                }
            )
        return entries
