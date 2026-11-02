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

CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id        TEXT NOT NULL,   -- e.g. SSH-001
    rule_name      TEXT NOT NULL,
    severity       TEXT NOT NULL,   -- low / medium / high / critical
    mitre_id       TEXT,            -- e.g. T1110.001
    mitre_name     TEXT,
    mitre_tactic   TEXT,
    src_ip         TEXT,            -- the attacker (first event's IP)
    group_key      TEXT NOT NULL,   -- e.g. "src_ip=203.0.113.50, user=root"
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    event_count    INTEGER NOT NULL,
    summary        TEXT NOT NULL,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);

-- Evidence: which events caused which alert (used by the dashboard's detail view)
CREATE TABLE IF NOT EXISTS alert_events (
    alert_id INTEGER NOT NULL REFERENCES alerts(id),
    event_id INTEGER NOT NULL REFERENCES events(id),
    PRIMARY KEY (alert_id, event_id)
);
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


ALERT_COLUMNS = (
    "rule_id", "rule_name", "severity", "mitre_id", "mitre_name", "mitre_tactic",
    "src_ip", "group_key", "first_seen", "last_seen", "event_count", "summary", "created_at",
)


def reset_alerts(conn):
    """Delete all alerts and their evidence (detection is re-run from scratch each time)."""
    conn.execute("DELETE FROM alert_events")
    conn.execute("DELETE FROM alerts")
    # AUTOINCREMENT remembers its last id; forget it so ids restart at 1 on every run
    conn.execute("DELETE FROM sqlite_sequence WHERE name = 'alerts'")


def insert_alert(conn, alert, event_ids):
    """Store one alert plus the ids of the events that triggered it. Returns the alert id."""
    placeholders = ", ".join("?" for _ in ALERT_COLUMNS)
    sql = f"INSERT INTO alerts ({', '.join(ALERT_COLUMNS)}) VALUES ({placeholders})"
    cur = conn.execute(sql, tuple(alert.get(col) for col in ALERT_COLUMNS))
    alert_id = cur.lastrowid
    conn.executemany(
        "INSERT INTO alert_events (alert_id, event_id) VALUES (?, ?)",
        [(alert_id, eid) for eid in event_ids],
    )
    return alert_id