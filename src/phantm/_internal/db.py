import json
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path


DB_PATH = Path.home() / ".phantm" / "phantm.db"


def _get_connection() -> sqlite3.Connection:
    if DB_PATH.is_symlink():
        raise PermissionError("Security Violation: Symlink detected on database path.")

    DB_PATH.parent.mkdir(mode=0o700, exist_ok=True)

    if DB_PATH.exists() and DB_PATH.is_symlink():
        raise PermissionError("Security Violation: Symlink detected on database path.")

    DB_PATH.touch(mode=0o600, exist_ok=True)

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    with _get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_history (
                scan_id TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target_path TEXT NOT NULL,
                files_scanned INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                line_number TEXT,
                severity TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                description TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scan_history(scan_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS intel_cache (
                artifact_id TEXT PRIMARY KEY,
                artifact_type TEXT NOT NULL,
                result TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)


def get_intel_cache(artifact_id: str, ttl_hours: int) -> dict | None:
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT result, timestamp FROM intel_cache WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()

    if row is None:
        return None

    cached_at = datetime.fromisoformat(row["timestamp"])
    if datetime.now() - cached_at > timedelta(hours=ttl_hours):
        with _get_connection() as conn:
            conn.execute("DELETE FROM intel_cache WHERE artifact_id = ?", (artifact_id,))
        return None

    return json.loads(row["result"])


def set_intel_cache(artifact_id: str, artifact_type: str, result: dict) -> None:
    with _get_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO intel_cache (artifact_id, artifact_type, result, timestamp) "
            "VALUES (?, ?, ?, ?)",
            (artifact_id, artifact_type, json.dumps(result), datetime.now().isoformat()),
        )


def create_scan_record(target_path: str, files_scanned: int) -> str:
    scan_id = uuid.uuid4().hex
    with _get_connection() as conn:
        conn.execute(
            "INSERT INTO scan_history (scan_id, target_path, files_scanned) VALUES (?, ?, ?)",
            (scan_id, target_path, files_scanned),
        )
    return scan_id


def save_findings(scan_id: str, findings: list[dict]) -> None:
    rows = [
        (
            scan_id,
            f.get("file_path", ""),
            str(f.get("line_number", "")),
            f.get("severity", "LOW"),
            f.get("vuln_type", "unknown"),
            f.get("description", ""),
        )
        for f in findings
    ]
    with _get_connection() as conn:
        conn.executemany(
            "INSERT INTO findings (scan_id, file_path, line_number, severity, vuln_type, description) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )


def update_scan_summary(scan_id: str, total_findings: int) -> None:
    with _get_connection() as conn:
        conn.execute(
            "UPDATE scan_history SET total_findings = ? WHERE scan_id = ?",
            (total_findings, scan_id),
        )


def get_recent_scans(limit: int = 10) -> list[dict]:
    with _get_connection() as conn:
        rows = conn.execute(
            """
            SELECT scan_id, timestamp, target_path, files_scanned, total_findings
            FROM scan_history
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_findings_for_scan(scan_id: str) -> list[dict]:
    with _get_connection() as conn:
        rows = conn.execute(
            "SELECT id, file_path, line_number, severity, vuln_type, description "
            "FROM findings WHERE scan_id = ? ORDER BY severity, id",
            (scan_id,),
        ).fetchall()
    return [dict(r) for r in rows]
