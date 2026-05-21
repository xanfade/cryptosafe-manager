from __future__ import annotations

import json
from typing import Any


class PasswordManagerJsonFormatHandler:
    def serialize(self, entries: list[dict[str, Any]], metadata: dict[str, Any] | None = None) -> bytes:
        items = []
        for entry in entries:
            items.append(
                {
                    "name": entry.get("title", ""),
                    "login": {
                        "username": entry.get("username", ""),
                        "password": entry.get("password", ""),
                        "uris": [{"uri": entry.get("url", "")}] if entry.get("url") else [],
                    },
                    "notes": entry.get("notes", ""),
                    "folder": entry.get("category", ""),
                    "fields": [{"name": "tags", "value": entry.get("tags", "")}],
                }
            )
        return json.dumps({"items": items}, ensure_ascii=False, indent=2).encode("utf-8")

    def deserialize(self, payload: bytes) -> list[dict[str, Any]]:
        data = json.loads(payload.decode("utf-8"))
        items = data.get("items", [])
        result = []
        for item in items:
            login = item.get("login", {}) or {}
            uris = login.get("uris", []) or []
            url = uris[0].get("uri", "") if uris else ""
            fields = item.get("fields", []) or []
            tags = ""
            for field in fields:
                if field.get("name") == "tags":
                    tags = field.get("value", "")
                    break
            result.append(
                {
                    "title": item.get("name", ""),
                    "username": login.get("username", ""),
                    "password": login.get("password", ""),
                    "url": url,
                    "notes": item.get("notes", ""),
                    "category": item.get("folder", ""),
                    "tags": tags,
                }
            )
        return result
