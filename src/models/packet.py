"""
packet.py
A simulated network packet.

IMPORTANT: this is a plain Python object created by our own traffic
simulator. Nothing here touches a real network interface.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Optional

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

    # --- stateful inspection fields ---
    flags: str = ""                 # TCP flags: SYN, SYN,ACK, ACK, PSH,ACK, FIN, RST
    conn_state: str = ""            # NEW, ESTABLISHED, RELATED, INVALID, CLOSED

    # --- DPI (Deep Packet Inspection) fields ---
    payload: str = ""               # L7 Application Payload (HTTP, DNS, etc.)
    dpi_match: Any = None           # DPIMatch object if a signature was triggered

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

    @property
    def payload_preview(self) -> str:
        if not self.payload:
            return "-"
        clean = self.payload.replace("\r", " ").replace("\n", " ").strip()
        return clean[:40] + "..." if len(clean) > 40 else clean

    def summary(self) -> str:
        flags_str = f" [{self.flags}]" if self.flags else ""
        state_str = f" ({self.conn_state})" if self.conn_state else ""
        payload_str = f" | {self.payload_preview}" if self.payload else ""
        return (f"{self.src_ip}:{self.src_port} -> "
                f"{self.dst_ip}:{self.dst_port} ({self.protocol}{flags_str}){state_str}{payload_str}")

    def as_row(self) -> tuple:
        """Tuple used by the Traffic Monitor table."""
        return (
            self.time_text,
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.protocol,
            self.flags or "-",
            self.conn_state or "-",
            self.kind,
            self.payload_preview,
            self.action,
            self.reason,
        )
