import os
import stat
from pathlib import Path
from phantm._internal.db import get_recent_scans, get_findings_for_scan


def get_latest_report_data() -> dict | None:
    db_path = Path.home() / ".phantm" / "phantm.db"

    if not db_path.exists():
        return {}

    file_stat = db_path.stat()

    if file_stat.st_uid != os.getuid():
        raise PermissionError("Unauthorized: You do not own the scan database.")

    if file_stat.st_mode & 0o077:
        raise PermissionError(f"Insecure permissions on {db_path}. Run 'chmod 600' to secure it.")

    scans = get_recent_scans(limit=1)
    if not scans:
        return None

    scan = scans[0]
    findings = get_findings_for_scan(scan["scan_id"])
    return {"scan": scan, "findings": findings}
