from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse


class EntryIconService:
    def __init__(self, db):
        self.db = db
        self.ensure_schema()

    def ensure_schema(self) -> None:
        with self.db.connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS entry_icons (
                    domain TEXT PRIMARY KEY,
                    icon_url TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def update_from_entries(self, entries: list[dict]) -> int:
        updated = 0
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.db.connection() as conn:
            for entry in entries:
                domain = self._domain(entry.get("url", ""))
                if not domain:
                    continue
                icon_url = f"https://{domain}/favicon.ico"
                conn.execute(
                    """
                    INSERT INTO entry_icons(domain, icon_url, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(domain) DO UPDATE SET
                        icon_url = excluded.icon_url,
                        updated_at = excluded.updated_at
                    """,
                    (domain, icon_url, now),
                )
                updated += 1
            conn.commit()
        return updated

    @staticmethod
    def _domain(url: str) -> str:
        value = str(url or "").strip()
        if not value:
            return ""
        if "://" not in value:
            value = "https://" + value
        try:
            parsed = urlparse(value)
            domain = parsed.netloc.lower()
            return domain[4:] if domain.startswith("www.") else domain
        except Exception:
            return ""
