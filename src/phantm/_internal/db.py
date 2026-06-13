import sqlite3
import json
from pathlib import Path


DB_PATH = Path.home() / ".phantm" / "phantm.db"


def _connection(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or DB_PATH
    if not path.exists():
        path.touch(mode=0o600)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(mode=0o700, exist_ok=True)
    conn = _connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            target_path TEXT NOT NULL,
            exit_code INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            severity TEXT NOT NULL,
            type TEXT NOT NULL,
            line INTEGER,
            description TEXT NOT NULL,
            fix TEXT,
            confidence TEXT NOT NULL,
            source TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_history(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS intel_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            artifact TEXT NOT NULL,
            source TEXT NOT NULL,
            result_json TEXT NOT NULL,
            cached_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(artifact, source)
        );
    """)
    conn.close()


def set_intel_cache(artifact: str, source: str, result: dict) -> None:
    conn = _connection()
    conn.execute(
        "INSERT OR REPLACE INTO intel_cache (artifact, source, result_json, cached_at) "
        "VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
        (artifact, source, json.dumps(result)),
    )
    conn.commit()
    conn.close()


def get_intel_cache(artifact: str, source: str, ttl_hours: int) -> dict | None:
    conn = _connection()
    row = conn.execute(
        "SELECT result_json FROM intel_cache "
        "WHERE artifact = ? AND source = ? "
        "AND cached_at >= datetime('now', ? || ' hours')",
        (artifact, source, -ttl_hours),
    ).fetchone()
    conn.close()
    if row is None:
        return None
    return json.loads(row["result_json"])


def record_scan(target_path: str, exit_code: int) -> int:
    conn = _connection()
    cursor = conn.execute(
        "INSERT INTO scan_history (target_path, exit_code) VALUES (?, ?)",
        (target_path, exit_code),
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id


def get_recent_scans(limit: int = 10, db_path: Path | None = None) -> list[dict]:
    conn = _connection(db_path)
    rows = conn.execute(
        """
        SELECT
            s.id,
            s.timestamp,
            s.target_path,
            s.exit_code,
            COUNT(f.id) AS findings_count
        FROM scan_history s
        LEFT JOIN findings f ON f.scan_id = s.id
        GROUP BY s.id
        ORDER BY s.timestamp DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_findings_for_scan(scan_id: int) -> list[dict]:
    conn = _connection()
    rows = conn.execute(
        "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity, line",
        (scan_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def record_finding(
    scan_id: int,
    file_path: str,
    severity: str,
    type: str,
    line: int | None,
    description: str,
    fix: str | None,
    confidence: str,
    source: str,
) -> int:
    conn = _connection()
    cursor = conn.execute(
        """
        INSERT INTO findings
            (scan_id, file_path, severity, type, line, description, fix, confidence, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (scan_id, file_path, severity, type, line, description, fix, confidence, source),
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id
