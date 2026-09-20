"""
alert.py
A security alert raised by the detection engine.
"""

import time
from dataclasses import dataclass, field


@dataclass
class Alert:
    """One detected attack."""

    attack_type: str                 # PORT_SCAN / BRUTE_FORCE / TRAFFIC_FLOOD
    source_ip: str
    details: str = ""
    severity: str = "HIGH"           # LOW / MEDIUM / HIGH
    auto_blocked: int = 0            # 1 if the IP was blacklisted automatically
    timestamp: float = field(default_factory=time.time)
    id: int = 0

    @property
    def time_text(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.timestamp))

    @property
    def datetime_text(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))

    def as_row(self) -> tuple:
        """Tuple used by the Attack Detection table."""
        return (
            self.time_text,
            self.attack_type,
            self.source_ip,
            self.severity,
            "Yes" if self.auto_blocked else "No",
            self.details,
        )
