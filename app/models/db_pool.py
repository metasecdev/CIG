"""
Database connection pooling for improved performance
"""

import sqlite3
import threading
from typing import Optional
from pathlib import Path
from contextlib import contextmanager
from queue import Queue


class DatabasePool:
    """Thread-safe SQLite connection pool"""

    def __init__(self, db_path: str, pool_size: int = 5):
        """
        Initialize connection pool.
        
        Args:
            db_path: Path to SQLite database file
            pool_size: Maximum number of connections in pool
        """
        self.db_path = db_path
        self.pool_size = pool_size
        self._pool = Queue(maxsize=pool_size)
        self._lock = threading.Lock()
        self._initialized = False
        
        # Create parent directories if needed
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize pool with connections
        self._init_pool()

    def _init_pool(self) -> None:
        """Initialize connection pool with connections"""
        with self._lock:
            if self._initialized:
                return
            
            for _ in range(self.pool_size):
                conn = self._create_connection()
                self._pool.put(conn)
            
            self._initialized = True

    def _create_connection(self) -> sqlite3.Connection:
        """Create a new database connection"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def get_connection(self):
        """
        Get a connection from the pool.
        Usage: with pool.get_connection() as conn: ...
        """
        conn = self._pool.get()
        try:
            yield conn
        finally:
            self._pool.put(conn)

    def close_all(self) -> None:
        """Close all connections in pool"""
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                conn.close()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_all()
