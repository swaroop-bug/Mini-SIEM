"""Database layer: creates the SQLite schema and inserts normalized events."""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "minisiem.db"

# Common schema (first 7) + optional web fields (NULL for SSH events).
# Order matters: the INSERT below is built from this tuple.
COLUMNS = (
    "timestamp", "source", "host", "user", "src_ip", "event_type", "raw",
    "method", "path", "status", "user_agent",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT NOT NULL,   -- ISO format: 2026-11-01T10:15:32
    source     TEXT NOT NULL,   -- 'auth.log' or 'web'
    host       TEXT,
    user       TEXT,
    src_ip     TEXT,
    event_type TEXT NOT NULL,   -- e.g. ssh_failed_login, web_request
    raw        TEXT NOT NULL,   -- the original log line
    method     TEXT,            -- web only: GET, POST, ...
    path       TEXT,            -- web only: URL-decoded path + query string
    status     INTEGER,         -- web only: HTTP status code
    user_agent TEXT             -- web only
);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_type_time ON events(event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);
"""


def get_connection(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # lets you do row["src_ip"] instead of row[4]
    return conn


def init_db(db_path=DB_PATH):
    """Create the table if it doesn't exist yet. Safe to call repeatedly."""
    conn = get_connection(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def reset_events(db_path=DB_PATH):
    """Delete all events (used to reload logs from scratch)."""
    conn = get_connection(db_path)
    conn.execute("DELETE FROM events")
    conn.commit()
    conn.close()


def insert_events(events, db_path=DB_PATH):
    """Insert a list of event dicts. Returns how many rows were inserted."""
    rows = [tuple(e.get(col) for col in COLUMNS) for e in events]
    # f-string SQL is safe HERE because COLUMNS is our own constant, never log data.
    # Values from logs always go through the ? placeholders.
    placeholders = ", ".join("?" for _ in COLUMNS)
    sql = f"INSERT INTO events ({', '.join(COLUMNS)}) VALUES ({placeholders})"
    conn = get_connection(db_path)
    conn.executemany(sql, rows)
    conn.commit()
    conn.close()
    return len(rows)