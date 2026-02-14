"""Database connection and initialization helpers"""
import sqlite3
from pathlib import Path
from contextlib import contextmanager

from server.config import DATABASE_PATH, SCHEMA_PATH


def init_database():
    """Initialize database with schema"""
    Path("database").mkdir(exist_ok=True)

    with open(SCHEMA_PATH, "r") as f:
        schema = f.read()

    conn = sqlite3.connect(DATABASE_PATH)
    conn.executescript(schema)
    conn.commit()
    conn.close()

    print(f"Database initialized at {DATABASE_PATH}")


@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def dict_from_row(row):
    """Convert sqlite3.Row to dict"""
    return {key: row[key] for key in row.keys()}
