from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class LoginEvent:
    """One SSH login attempt read from an auth log."""

    timestamp: datetime
    host: str
    user: str
    ip: str
    port: int
    success: bool
    method: str  # "password" or "publickey"
    invalid_user: bool  # True when sshd says the account doesn't exist
