"""SQLite persistence (WAL mode, single writer, thread-safe)."""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    ts REAL NOT NULL, link TEXT NOT NULL,
    status TEXT NOT NULL,          -- confirmed state: healthy|degraded|down|unknown
    raw_state TEXT NOT NULL,       -- this poll's classification
    latency REAL, jitter REAL, loss REAL, sla_met INTEGER,
    rx_bps REAL, tx_bps REAL
);
CREATE INDEX IF NOT EXISTS ix_samples_link_ts ON samples(link, ts);
CREATE INDEX IF NOT EXISTS ix_samples_ts ON samples(ts);
CREATE TABLE IF NOT EXISTS polls (
    ts REAL PRIMARY KEY, ok INTEGER NOT NULL, error TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL,
    link TEXT, from_state TEXT, to_state TEXT, message TEXT NOT NULL,
    notified INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS reports (
    day TEXT PRIMARY KEY, created REAL NOT NULL, html_path TEXT, csv_path TEXT, summary TEXT
);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
            self._db.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _q(self, sql: str, args=()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    # --- writes --------------------------------------------------------------
    def add_poll(self, ts: float, rows: list[tuple], ok: bool, error: str | None = None) -> None:
        with self._lock:
            self._db.execute("BEGIN")
            try:
                self._db.execute("INSERT OR REPLACE INTO polls VALUES (?,?,?)", (ts, int(ok), error))
                if rows:
                    self._db.executemany("INSERT INTO samples VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def add_event(self, ts, kind, severity, link, from_state, to_state, message) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO events (ts,kind,severity,link,from_state,to_state,message) VALUES (?,?,?,?,?,?,?)",
                (ts, kind, severity, link, from_state, to_state, message))
            return cur.lastrowid

    def mark_notified(self, event_id: int, value: int) -> None:
        with self._lock:
            self._db.execute("UPDATE events SET notified=? WHERE id=?", (value, event_id))

    def save_report(self, day: str, html_path: str, csv_path: str, summary: str) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO reports VALUES (?,?,?,?,?)",
                             (day, time.time(), html_path, csv_path, summary))

    def purge(self, retention_days: int) -> int:
        cutoff = time.time() - retention_days * 86400
        with self._lock:
            n = self._db.execute("DELETE FROM samples WHERE ts < ?", (cutoff,)).rowcount
            self._db.execute("DELETE FROM polls WHERE ts < ?", (cutoff,))
            self._db.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        return n

    def vacuum(self) -> None:
        with self._lock:
            self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    # --- reads ---------------------------------------------------------------
    def samples(self, start: float, end: float, link: str | None = None) -> list[sqlite3.Row]:
        if link:
            return self._q("SELECT * FROM samples WHERE link=? AND ts>=? AND ts<? ORDER BY ts", (link, start, end))
        return self._q("SELECT * FROM samples WHERE ts>=? AND ts<? ORDER BY ts", (start, end))

    def polls(self, start: float, end: float) -> list[sqlite3.Row]:
        return self._q("SELECT * FROM polls WHERE ts>=? AND ts<? ORDER BY ts", (start, end))

    def last_state_before(self, link: str, ts: float) -> str | None:
        rows = self._q("SELECT status FROM samples WHERE link=? AND ts<? ORDER BY ts DESC LIMIT 1", (link, ts))
        return rows[0]["status"] if rows else None

    def events(self, start: float = 0, end: float | None = None, limit: int = 200) -> list[sqlite3.Row]:
        end = end or time.time() + 1
        return self._q("SELECT * FROM events WHERE ts>=? AND ts<? ORDER BY ts DESC LIMIT ?", (start, end, limit))

    def reports(self, limit: int = 60) -> list[sqlite3.Row]:
        return self._q("SELECT * FROM reports ORDER BY day DESC LIMIT ?", (limit,))

    def report(self, day: str) -> sqlite3.Row | None:
        rows = self._q("SELECT * FROM reports WHERE day=?", (day,))
        return rows[0] if rows else None
