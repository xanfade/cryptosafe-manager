from __future__ import annotations

import json
from typing import Any


class JsonFormatHandler:
    def serialize(self, entries: list[dict[str, Any]], metadata: dict[str, Any] | None = None) -> bytes:
        return json.dumps(entries, ensure_ascii=False, indent=2).encode("utf-8")

    def deserialize(self, payload: bytes) -> list[dict[str, Any]]:
        data = json.loads(payload.decode("utf-8"))
        if not isinstance(data, list):
            raise ValueError("json import payload must contain a list of entries")
        return [dict(item) for item in data]
