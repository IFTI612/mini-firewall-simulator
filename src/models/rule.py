"""
rule.py
A single firewall rule and the matching helpers it needs.

Supported field formats
-----------------------
IP      : "*"  |  "192.168.1.10"  |  "192.168.1.*"  |  "10.0.0.0/8"
Port    : "*"  |  "80"            |  "20-25"
Protocol: "*"  |  "TCP"           |  "UDP"
"""

import ipaddress
from dataclasses import dataclass

ANY = ("*", "", "any", "ANY", "ALL", "all")


def ip_matches(pattern: str, ip: str) -> bool:
    """Does `ip` match the rule's IP `pattern`?"""
    pattern = (pattern or "*").strip()
    if pattern in ANY:
        return True

    # CIDR, e.g. 192.168.1.0/24
    if "/" in pattern:
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return False

    # Wildcard suffix, e.g. 192.168.1.*
    if pattern.endswith("*"):
        return ip.startswith(pattern[:-1])

    return pattern == ip


def port_matches(pattern, port: int) -> bool:
    """Does `port` match the rule's port `pattern`?"""
    pattern = str(pattern if pattern is not None else "*").strip()
    if pattern in ANY:
        return True

    # Range, e.g. 20-25
    if "-" in pattern:
        try:
            low, high = pattern.split("-", 1)
            return int(low) <= port <= int(high)
        except ValueError:
            return False

    try:
        return int(pattern) == port
    except ValueError:
        return False


def protocol_matches(pattern: str, protocol: str) -> bool:
    pattern = (pattern or "*").strip()
    if pattern in ANY:
        return True
    return pattern.upper() == protocol.upper()


@dataclass
class Rule:
    """One firewall rule. Lower `priority` number = checked first."""

    id: int = 0
    priority: int = 100
    src_ip: str = "*"
    dst_ip: str = "*"
    src_port: str = "*"
    dst_port: str = "*"
    protocol: str = "*"
    action: str = "BLOCK"           # ALLOW / BLOCK
    enabled: int = 1
    description: str = ""

    # ------------------------------------------------------------------
    def matches(self, packet) -> bool:
        """True if every field of this rule matches the packet."""
        if not self.enabled:
            return False
        return (
            ip_matches(self.src_ip, packet.src_ip)
            and ip_matches(self.dst_ip, packet.dst_ip)
            and port_matches(self.src_port, packet.src_port)
            and port_matches(self.dst_port, packet.dst_port)
            and protocol_matches(self.protocol, packet.protocol)
        )

    def as_row(self) -> tuple:
        """Tuple used by the Firewall Rules table."""
        return (
            self.id,
            self.priority,
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.protocol,
            self.action,
            "Yes" if self.enabled else "No",
            self.description,
        )

    @staticmethod
    def from_db_row(row) -> "Rule":
        """Build a Rule from a database row (dict-like)."""
        return Rule(
            id=row["id"],
            priority=row["priority"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            src_port=row["src_port"],
            dst_port=row["dst_port"],
            protocol=row["protocol"],
            action=row["action"],
            enabled=row["enabled"],
            description=row["description"] or "",
        )
