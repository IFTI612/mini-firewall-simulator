"""
conntrack.py
Stateful Inspection and Connection Tracking Engine (Conntrack).

Implements RFC 793 TCP state machine tracking and UDP pseudo-state tracking
similar to Linux Netfilter / iptables conntrack.

Conntrack States:
  - NEW         : Valid connection initiation (TCP SYN or 1st UDP packet)
  - ESTABLISHED : Connection has seen valid bidirectional traffic / handshake
  - RELATED     : Related to an active connection (e.g. ICMP error, FTP data)
  - INVALID     : Packet doesn't match an active connection or has illegal flags
  - CLOSED      : Connection terminated by FIN/RST or timed out
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import config
from models.packet import Packet


@dataclass
class ConnectionEntry:
    """Represents a tracked bidirectional network connection."""
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    protocol: str

    tcp_state: str = "SYN_SENT"       # SYN_SENT, SYN_RECV, ESTABLISHED, FIN_WAIT, CLOSED, UDP
    conntrack_state: str = config.CONN_NEW
    confirmed: bool = False           # True once allowed by firewall rules

    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    packets_forward: int = 1         # Client -> Server
    packets_reverse: int = 0         # Server -> Client
    bytes_total: int = 0

    @property
    def key_forward(self) -> tuple:
        return (self.client_ip, self.client_port, self.server_ip, self.server_port, self.protocol)

    @property
    def key_reverse(self) -> tuple:
        return (self.server_ip, self.server_port, self.client_ip, self.client_port, self.protocol)

    @property
    def idle_time(self) -> float:
        return max(0.0, time.time() - self.last_seen)

    def __hash__(self):
        return hash((self.client_ip, self.client_port, self.server_ip, self.server_port, self.protocol))

    def __eq__(self, other):
        if not isinstance(other, ConnectionEntry):
            return False
        return (self.client_ip, self.client_port, self.server_ip, self.server_port, self.protocol) == (
            other.client_ip, other.client_port, other.server_ip, other.server_port, other.protocol)

    def as_row(self) -> tuple:
        """Tuple for UI Active Connections table."""
        client_str = f"{self.client_ip}:{self.client_port}"
        server_str = f"{self.server_ip}:{self.server_port}"
        return (
            self.protocol,
            client_str,
            server_str,
            self.tcp_state,
            self.conntrack_state,
            self.packets_forward,
            self.packets_reverse,
            self.bytes_total,
            f"{self.idle_time:.1f}s",
        )


class ConnectionTracker:
    """
    Maintains the state of all active TCP connections and UDP streams.
    Thread-safe.
    """

    def __init__(self, tcp_timeout: int = 120, udp_timeout: int = 30):
        self._lock = threading.Lock()
        self._table: Dict[tuple, ConnectionEntry] = {}
        self._entries: set = set()
        self.tcp_timeout = tcp_timeout
        self.udp_timeout = udp_timeout
        self._last_cleanup = time.time()

    def set_timeouts(self, tcp_timeout: int, udp_timeout: int):
        with self._lock:
            self.tcp_timeout = max(5, int(tcp_timeout))
            self.udp_timeout = max(5, int(udp_timeout))

    # ------------------------------------------------------------------ packet inspection
    def process_packet(self, packet: Packet) -> Tuple[str, str]:
        """
        Stateful analysis of an incoming packet.
        Updates connection state and returns:
            (conntrack_state, reason_description)
        """
        now = packet.timestamp or time.time()
        proto = packet.protocol.upper()

        with self._lock:
            # Periodic cleanup of expired sessions
            if now - self._last_cleanup > 5.0:
                self._cleanup_expired_locked(now)
                self._last_cleanup = now

            if proto == "TCP":
                return self._process_tcp_locked(packet, now)
            elif proto == "UDP":
                return self._process_udp_locked(packet, now)
            else:
                return config.CONN_NEW, f"Unmonitored protocol {proto}"

    def _process_tcp_locked(self, packet: Packet, now: float) -> Tuple[str, str]:
        flags = (packet.flags or "").upper().replace(" ", "").split(",")
        flags = {f.strip() for f in flags if f.strip()}

        # 1. Check for illegal TCP flag combinations (RFC violations / stealth scans)
        if not flags:
            # NULL scan: packet with no flags set
            return config.CONN_INVALID, "Stealth scan detected: NULL flags (no TCP flags set)"

        if "SYN" in flags and "FIN" in flags:
            # SYN-FIN scan: impossible combination in normal TCP
            return config.CONN_INVALID, "Malformed TCP flags: SYN+FIN set simultaneously"

        if "FIN" in flags and "PSH" in flags and "URG" in flags:
            # Xmas scan: flags lit up like a Christmas tree
            return config.CONN_INVALID, "Stealth scan detected: Xmas tree flags (FIN+PSH+URG)"

        flow_key = (packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port, "TCP")
        entry: Optional[ConnectionEntry] = self._table.get(flow_key)

        # 2. Check if flow already exists in connection table
        if entry is not None:
            # Check for idle timeout
            timeout = self.tcp_timeout if entry.tcp_state == "ESTABLISHED" else 30
            if (now - entry.last_seen) > timeout:
                self._remove_entry_locked(entry)
                return config.CONN_INVALID, "Connection expired / timed out"

            entry.last_seen = now
            entry.bytes_total += packet.size

            is_client = (packet.src_ip == entry.client_ip and packet.src_port == entry.client_port)
            if is_client:
                entry.packets_forward += 1
            else:
                entry.packets_reverse += 1

            # Termination flags
            if "RST" in flags:
                entry.tcp_state = "CLOSED"
                entry.conntrack_state = config.CONN_CLOSED
                return config.CONN_ESTABLISHED, "TCP connection reset (RST)"

            if "FIN" in flags:
                if entry.tcp_state == "FIN_WAIT":
                    entry.tcp_state = "CLOSED"
                    entry.conntrack_state = config.CONN_CLOSED
                else:
                    entry.tcp_state = "FIN_WAIT"
                return config.CONN_ESTABLISHED, "TCP connection teardown (FIN)"

            # Handshake progression
            if entry.tcp_state == "SYN_SENT":
                if not is_client and "SYN" in flags and "ACK" in flags:
                    entry.tcp_state = "SYN_RECV"
                    entry.conntrack_state = config.CONN_ESTABLISHED
                    return config.CONN_ESTABLISHED, "Handshake step 2: SYN-ACK received from server"
                elif is_client and "ACK" in flags:
                    entry.tcp_state = "ESTABLISHED"
                    entry.conntrack_state = config.CONN_ESTABLISHED
                    return config.CONN_ESTABLISHED, "Handshake step 3: ACK sent by client"

            elif entry.tcp_state == "SYN_RECV":
                if is_client and "ACK" in flags:
                    entry.tcp_state = "ESTABLISHED"
                    entry.conntrack_state = config.CONN_ESTABLISHED
                    return config.CONN_ESTABLISHED, "TCP 3-way handshake established"

            elif entry.tcp_state in ("ESTABLISHED", "FIN_WAIT"):
                return config.CONN_ESTABLISHED, f"Established stream [{','.join(sorted(flags))}]"

            elif entry.tcp_state == "CLOSED":
                return config.CONN_INVALID, "Packet received for already closed TCP connection"

            return config.CONN_ESTABLISHED, f"Tracked TCP flow [{entry.tcp_state}]"

        # 3. No existing connection in table: validate connection initiation
        # A valid new TCP connection MUST be a pure SYN packet (initiating 3-way handshake)
        if "SYN" in flags and "ACK" not in flags and "FIN" not in flags:
            entry = ConnectionEntry(
                client_ip=packet.src_ip,
                client_port=packet.src_port,
                server_ip=packet.dst_ip,
                server_port=packet.dst_port,
                protocol="TCP",
                tcp_state="SYN_SENT",
                conntrack_state=config.CONN_NEW,
                confirmed=False,
                created_at=now,
                last_seen=now,
                packets_forward=1,
                packets_reverse=0,
                bytes_total=packet.size,
            )
            # Store both directions in table
            self._table[entry.key_forward] = entry
            self._table[entry.key_reverse] = entry
            self._entries.add(entry)
            return config.CONN_NEW, "Valid TCP connection initiation (SYN)"

        # Unsolicited FIN without connection (FIN Scan)
        if flags == {"FIN"}:
            return config.CONN_INVALID, "Stealth scan detected: unsolicited FIN packet without handshake"

        # Unsolicited ACK / RST / PSH-ACK without connection
        if "ACK" in flags:
            return config.CONN_INVALID, (
                f"Unsolicited ACK packet ({','.join(sorted(flags))}) for non-existent connection"
            )

        return config.CONN_INVALID, f"Invalid packet state: flags [{','.join(sorted(flags))}] without handshake"

    def _process_udp_locked(self, packet: Packet, now: float) -> Tuple[str, str]:
        flow_key = (packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port, "UDP")
        entry = self._table.get(flow_key)

        if entry is not None:
            if (now - entry.last_seen) > self.udp_timeout:
                self._remove_entry_locked(entry)
                entry = None
            else:
                entry.last_seen = now
                entry.bytes_total += packet.size
                if packet.src_ip == entry.client_ip and packet.src_port == entry.client_port:
                    entry.packets_forward += 1
                else:
                    entry.packets_reverse += 1
                entry.conntrack_state = config.CONN_ESTABLISHED
                return config.CONN_ESTABLISHED, "Active UDP stream"

        entry = ConnectionEntry(
            client_ip=packet.src_ip,
            client_port=packet.src_port,
            server_ip=packet.dst_ip,
            server_port=packet.dst_port,
            protocol="UDP",
            tcp_state="UDP",
            conntrack_state=config.CONN_NEW,
            confirmed=False,
            created_at=now,
            last_seen=now,
            packets_forward=1,
            packets_reverse=0,
            bytes_total=packet.size,
        )
        self._table[entry.key_forward] = entry
        self._table[entry.key_reverse] = entry
        self._entries.add(entry)
        return config.CONN_NEW, "New UDP stream initiated"

    # ------------------------------------------------------------------ confirmation & cleanup
    def confirm_connection(self, packet: Packet):
        """Called when a NEW packet is permitted by firewall rules."""
        key = (packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port, packet.protocol.upper())
        with self._lock:
            entry = self._table.get(key)
            if entry:
                entry.confirmed = True

    def drop_connection(self, packet: Packet):
        """Called when a NEW packet is dropped/denied by firewall rules."""
        key = (packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port, packet.protocol.upper())
        with self._lock:
            entry = self._table.get(key)
            if entry and not entry.confirmed:
                self._remove_entry_locked(entry)

    def _remove_entry_locked(self, entry: ConnectionEntry):
        self._table.pop(entry.key_forward, None)
        self._table.pop(entry.key_reverse, None)
        self._entries.discard(entry)

    def _cleanup_expired_locked(self, now: float):
        expired = []
        for entry in self._entries:
            timeout = self.tcp_timeout if entry.protocol == "TCP" else self.udp_timeout
            if entry.tcp_state == "CLOSED" or (now - entry.last_seen) > timeout:
                expired.append(entry)
        for e in expired:
            self._remove_entry_locked(e)

    # ------------------------------------------------------------------ metrics & ui
    def active_connections(self) -> List[ConnectionEntry]:
        now = time.time()
        with self._lock:
            self._cleanup_expired_locked(now)
            return sorted(list(self._entries), key=lambda e: e.last_seen, reverse=True)

    def active_count(self) -> int:
        with self._lock:
            return len(self._entries)

    def flush(self):
        """Purge all tracked connections."""
        with self._lock:
            self._table.clear()
            self._entries.clear()
