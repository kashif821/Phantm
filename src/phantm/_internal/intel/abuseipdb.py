import requests
from phantm._internal.db import get_intel_cache, set_intel_cache
from phantm._internal.intel.exceptions import IntelRateLimitError, IntelAuthError


def check_ip(ip: str, api_key: str, ttl_hours: int) -> dict:
    cached = get_intel_cache(ip, "abuseipdb", ttl_hours)
    if cached is not None:
        return cached

    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": api_key, "Accept": "application/json"},
        timeout=30,
    )

    if resp.status_code == 429:
        raise IntelRateLimitError("AbuseIPDB daily quota exceeded")
    if resp.status_code == 401:
        raise IntelAuthError("AbuseIPDB API key invalid")
    resp.raise_for_status()

    payload = resp.json().get("data", {})
    set_intel_cache(ip, "abuseipdb", payload)
    return payload
