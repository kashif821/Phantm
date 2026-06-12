from phantm._internal.db import get_recent_scans, get_findings_for_scan


def get_latest_report_data() -> dict | None:
    scans = get_recent_scans(limit=1)
    if not scans:
        return None

    scan = scans[0]
    findings = get_findings_for_scan(scan["id"])
    return {"scan": scan, "findings": findings}
