"""
packet.py
A simulated network packet.

IMPORTANT: this is a plain Python object created by our own traffic
simulator. Nothing here touches a real network interface.
"""

import time
from dataclasses import dataclass, field

from config import KIND_NORMAL


@dataclass
class Packet:
    """One simulated packet travelling through the firewall."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str = "TCP"           # TCP / UDP

    kind: str = KIND_NORMAL         # NORMAL / AUTH / SCAN / FLOOD (simulation label)
    auth_success: bool = True       # only meaningful when kind == AUTH
    size: int = 512                 # bytes
    timestamp: float = field(default_factory=time.time)

    # --- filled in by the firewall pipeline ---
    action: str = ""                # ALLOW / BLOCK
    reason: str = ""                # why that decision was taken
    rule_id: int = 0                # 0 = no rule matched (default policy)

    # ------------------------------------------------------------------
    @property
    def time_text(self) -> str:
        """Human readable timestamp, e.g. 14:05:32."""
        return time.strftime("%H:%M:%S", time.localtime(self.timestamp))

    @property
    def datetime_text(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))

    @property
    def is_failed_auth(self) -> bool:
        from config import KIND_AUTH
        return self.kind == KIND_AUTH and not self.auth_success

    def summary(self) -> str:
        return (f"{self.src_ip}:{self.src_port} -> "
                f"{self.dst_ip}:{self.dst_port} ({self.protocol})")

    def as_row(self) -> tuple:
        """Tuple used by the Traffic Monitor table."""
        return (
            self.time_text,
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.protocol,
            self.kind,
            self.action,
            self.reason,
        )
