from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Iterable


@dataclass
class BitwardenDirectImportResult:
    created: int = 0
    failed: int = 0
    errors: list[str] | None = None


class BitwardenDirectImporter:
    def __init__(self, bw_path: str = "bw", session: str | None = None):
        self.bw_path = bw_path
        self.session = session

    def require_ready(self) -> None:
        if not shutil.which(self.bw_path):
            raise RuntimeError("Bitwarden CLI is not installed")
        if not self.session:
            raise RuntimeError("Bitwarden CLI session is missing")

    def import_entries(self, entries: Iterable) -> BitwardenDirectImportResult:
        self.require_ready()
        created = 0
        failed = 0
        errors: list[str] = []
        env = {"BW_SESSION": self.session}

        for entry in entries:
            payload = self._entry_payload(entry)
            encoded = subprocess.run(
                [self.bw_path, "encode"],
                input=json.dumps(payload, ensure_ascii=False),
                text=True,
                capture_output=True,
                check=False,
                env=env,
            )
            if encoded.returncode != 0:
                failed += 1
                errors.append(encoded.stderr or "bw encode failed")
                continue

            created_item = subprocess.run(
                [self.bw_path, "create", "item", encoded.stdout.strip()],
                text=True,
                capture_output=True,
                check=False,
                env=env,
            )
            if created_item.returncode == 0:
                created += 1
            else:
                failed += 1
                errors.append(created_item.stderr or "bw create item failed")

        return BitwardenDirectImportResult(created=created, failed=failed, errors=errors)

    @staticmethod
    def _entry_payload(entry) -> dict:
        url = getattr(entry, "url", "") or ""
        return {
            "type": 1,
            "name": getattr(entry, "title", "") or "Imported item",
            "notes": getattr(entry, "notes", "") or "",
            "login": {
                "username": getattr(entry, "username", "") or "",
                "password": getattr(entry, "password", "") or "",
                "uris": [{"uri": url}] if url else [],
            },
        }
