from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Alert:
    """One alert raised by a detection rule."""

    timestamp: datetime  # time of the event that triggered the alert
    rule: str  # e.g. "brute_force"
    technique: str  # MITRE ATT&CK ID, e.g. "T1110.001"
    severity: Severity
    ip: str
    user: str | None = None  # None when the rule is about an IP, not an account
    failures: int | None = None  # failed attempts in the window, for brute-force rules
