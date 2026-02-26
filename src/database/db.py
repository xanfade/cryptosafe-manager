import sqlite3
import threading
from pathlib import Path
from contextlib import contextmanager
from .models import SCHEMA_V1


class Database:
    
    def __init__(self, db_path: str):
        self.db_path = str(Path(db_path))
        self._local = threading.local()

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.execute("PRAGMA journal_mode=WAL;") 
            self._local.conn = conn
        return conn

    @contextmanager
    def connection(self):
        """Context manager to get a connection (per-thread)."""
        conn = self._get_conn()
        yield conn

    def migrate(self):
        with self.connection() as conn:
            v = conn.execute("PRAGMA user_version;").fetchone()[0]

            if v < 1:
                conn.executescript(SCHEMA_V1)
                conn.execute("PRAGMA user_version=1;")
                conn.commit()

    def close_thread_connection(self):
        """Close current thread connection if exists."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None
