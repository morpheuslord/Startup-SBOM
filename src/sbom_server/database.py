"""Database connection and initialization helpers"""
import sqlite3
from pathlib import Path
from contextlib import contextmanager

from sbom_core.config import settings

# Determine Schema Path
# Assumes schema.sql is in a 'database' directory relative to the project root
# or packaged with the application.
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
SCHEMA_PATH = PROJECT_ROOT / "database" / "schema.sql"


def init_database():
    """Initialize database with schema"""
    db_path = Path(settings.server.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    if not SCHEMA_PATH.exists():
        print(f"Warning: Schema file not found at {SCHEMA_PATH}")
        return

    with open(SCHEMA_PATH, "r") as f:
        schema = f.read()

    conn = sqlite3.connect(str(db_path))
    conn.executescript(schema)
    conn.commit()
    conn.close()

    print(f"Database initialized at {db_path}")


@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = sqlite3.connect(settings.server.db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def dict_from_row(row):
    """Convert sqlite3.Row to dict"""
    return {key: row[key] for key in row.keys()}
