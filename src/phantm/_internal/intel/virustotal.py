import urllib.parse
import requests
from phantm._internal.db import get_intel_cache, set_intel_cache
from phantm._internal.intel.exceptions import IntelRateLimitError, IntelAuthError


def check_artifact(artifact: str, artifact_type: str, api_key: str, ttl_hours: int) -> dict:
    artifact_id = f"{artifact_type}:{artifact}"
    cached = get_intel_cache(artifact_id, ttl_hours)
    if cached is not None:
        return cached

    safe_type = urllib.parse.quote(artifact_type, safe="")
    safe_artifact = urllib.parse.quote(artifact, safe="")
    url = f"https://www.virustotal.com/api/v3/{safe_type}/{safe_artifact}"
    resp = requests.get(
        url,
        headers={"x-apikey": api_key, "Accept": "application/json"},
        timeout=30,
    )

    if resp.status_code == 429:
        raise IntelRateLimitError("VirusTotal quota exceeded")
    if resp.status_code == 401:
        raise IntelAuthError("VirusTotal API key invalid")
    resp.raise_for_status()

    payload = resp.json().get("data", {})
    set_intel_cache(artifact_id, artifact_type, payload)
    return payload
