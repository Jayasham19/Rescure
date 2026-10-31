"""
CalmStacks ReSecure Persistence Layer - Connection Manager
System: ReSecure (MVP v1.0)
Module: resecure.backend.src.db.connection
Engine: SQLite 3.35+
"""

from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional, Union

# Default local database file name
DEFAULT_DB_FILENAME = "resecure.db"
DEFAULT_BUSY_TIMEOUT_MS = 5000


def get_default_db_path() -> Path:
    """Resolve the default SQLite database path from environment or workspace root."""
    env_path = os.getenv("RESECURE_DB_PATH")
    if env_path:
        return Path(env_path).resolve()
    
    # Try locating project root (looking for resecure/ or .agents/ or current working directory)
    cwd = Path.cwd().resolve()
    resecure_dir = cwd / "resecure"
    if resecure_dir.is_dir():
        db_dir = resecure_dir / "database"
        db_dir.mkdir(parents=True, exist_ok=True)
        return (db_dir / DEFAULT_DB_FILENAME).resolve()
    
    return (cwd / DEFAULT_DB_FILENAME).resolve()


class DatabaseConnectionManager:
    """
    Thread-safe SQLite connection manager with WAL mode, foreign key enforcement,
    busy timeout configuration, and robust context managers for queries and transactions.
    """

    def __init__(
        self,
        db_path: Optional[Union[str, Path]] = None,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    ) -> None:
        if db_path is None:
            self.db_path = str(get_default_db_path())
        elif isinstance(db_path, Path):
            self.db_path = str(db_path.resolve())
        else:
            self.db_path = str(db_path)

        self.busy_timeout_ms = busy_timeout_ms
        self._shared_memory_conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()

        # Ensure parent directory exists if using disk path (not in-memory)
        if not self.is_memory() and not self.db_path.startswith("file:"):
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

    def is_memory(self) -> bool:
        """Returns True if database is in-memory."""
        return self.db_path == ":memory:" or "mode=memory" in self.db_path

    def _configure_connection(self, conn: sqlite3.Connection) -> sqlite3.Connection:
        """Applies required PRAGMA configurations."""
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON;")
        cursor.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms};")
        cursor.execute("PRAGMA synchronous = NORMAL;")
        
        # WAL mode is applicable to disk-backed databases
        if not self.is_memory():
            cursor.execute("PRAGMA journal_mode = WAL;")

        cursor.close()
        return conn

    def create_connection(self) -> sqlite3.Connection:
        """
        Creates and initializes a new SQLite connection.
        For :memory: databases, reuses a shared connection so schemas and data persist across queries.
        """
        if self.is_memory():
            with self._lock:
                if self._shared_memory_conn is None:
                    raw_conn = sqlite3.connect(":memory:", check_same_thread=False)
                    self._shared_memory_conn = self._configure_connection(raw_conn)
                return self._shared_memory_conn

        raw_conn = sqlite3.connect(
            self.db_path,
            timeout=self.busy_timeout_ms / 1000.0,
            check_same_thread=False,
        )
        return self._configure_connection(raw_conn)

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """
        Context manager providing a managed connection.
        Ensures proper resource cleanup upon exit.
        """
        if self.is_memory():
            yield self.create_connection()
        else:
            conn = self.create_connection()
            try:
                yield conn
            finally:
                conn.close()

    @contextmanager
    def transaction(
        self, conn: Optional[sqlite3.Connection] = None
    ) -> Generator[sqlite3.Connection, None, None]:
        """
        Context manager for atomic database transactions.
        Commits upon clean exit; rolls back on any exception.
        If an existing connection is passed, borrows it without closing it.
        """
        should_close = False
        if conn is None:
            if self.is_memory():
                conn = self.create_connection()
            else:
                conn = self.create_connection()
                should_close = True

        try:
            conn.execute("BEGIN IMMEDIATE;")
            yield conn
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            if should_close:
                conn.close()

    def close(self) -> None:
        """Closes any persistent shared connection."""
        with self._lock:
            if self._shared_memory_conn is not None:
                try:
                    self._shared_memory_conn.close()
                except Exception:
                    pass
                self._shared_memory_conn = None


# Global default connection manager instance
_default_manager: Optional[DatabaseConnectionManager] = None
_manager_lock = threading.Lock()


def get_connection_manager(
    db_path: Optional[Union[str, Path]] = None,
    reset: bool = False,
) -> DatabaseConnectionManager:
    """Thread-safe singleton accessor for the default DatabaseConnectionManager."""
    global _default_manager
    with _manager_lock:
        if _default_manager is None or reset or (db_path is not None and _default_manager.db_path != str(db_path)):
            _default_manager = DatabaseConnectionManager(db_path=db_path)
        return _default_manager


def get_db(db_path: Optional[Union[str, Path]] = None) -> Generator[sqlite3.Connection, None, None]:
    """FastAPI-style dependency injection helper yielding an active connection."""
    manager = get_connection_manager(db_path=db_path)
    with manager.connection() as conn:
        yield conn
