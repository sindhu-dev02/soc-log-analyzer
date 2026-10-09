from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class LogEvent:
    """One security-relevant line from a log, in a clean structured form."""
    timestamp: datetime
    kind: str          # "failed" or "success"
    user: str
    ip: str
    line_no: int
    raw: str           # the original line, kept as evidence


@dataclass(frozen=True)
class Alert:
    """Something suspicious the detector found."""
    line_no: int
    severity: str
    message: str
    rule: str = ""
    technique: str = ""     # MITRE ATT&CK ID
    evidence: str = ""      # the raw log line that triggered it