from dataclasses import dataclass


@dataclass
class Finding:
    file_path: str
    severity: str
    type: str
    line: int | None
    description: str
    fix: str | None
    confidence: str
    source: str
