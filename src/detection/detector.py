"""
detector.py
Attack detection using sliding time windows.

For every source IP we keep three small history lists (deques). Old
entries are dropped as time moves on, so the list always holds "the last
N seconds". Then we just compare the size of that window to a threshold.

Rules implemented
-----------------
PORT_SCAN     : unique destination ports from one IP in 10 s  >= 10
BRUTE_FORCE   : failed auth attempts from one IP in 60 s      >= 5
TRAFFIC_FLOOD : packets from one IP in 5 s                    >= 100

The packet that pushes the counter over the threshold is the one that
fires the alert (i.e. the 5th failed login, the 100th packet).

A cooldown stops the same IP raising the same alert on every single
following packet while the window stays full.
"""

import threading
import time
from collections import defaultdict, deque

import config
from models.alert import Alert


class AttackDetector:
    def __init__(self, db):
        self.db = db
        self._lock = threading.Lock()

        # history per source IP
        self._ports = defaultdict(deque)        # deque of (timestamp, dst_port)
        self._auth_fails = defaultdict(deque)   # deque of timestamps
        self._packets = defaultdict(deque)      # deque of timestamps

        # last time we alerted for (ip, attack_type)
        self._last_alert = {}

        self.reload_thresholds()

    # ------------------------------------------------------------------
    def reload_thresholds(self):
        """Read the current thresholds from the Settings table."""
        with self._lock:
            self.scan_window = self.db.get_int_setting("portscan_window", 10)
            self.scan_threshold = self.db.get_int_setting("portscan_threshold", 10)
            self.brute_window = self.db.get_int_setting("bruteforce_window", 60)
            self.brute_threshold = self.db.get_int_setting("bruteforce_threshold", 5)
            self.flood_window = self.db.get_int_setting("flood_window", 5)
            self.flood_threshold = self.db.get_int_setting("flood_threshold", 100)
            self.cooldown = self.db.get_int_setting("alert_cooldown", 15)

    def reset(self):
        """Forget all history (used when the logs are cleared)."""
        with self._lock:
            self._ports.clear()
            self._auth_fails.clear()
            self._packets.clear()
            self._last_alert.clear()

    # ------------------------------------------------------------------
    @staticmethod
    def _prune(window_deque, cutoff, is_pair=False):
        """Drop entries older than `cutoff` from the left of the deque."""
        while window_deque:
            ts = window_deque[0][0] if is_pair else window_deque[0]
            if ts < cutoff:
                window_deque.popleft()
            else:
                break

    def _on_cooldown(self, ip, attack_type, now) -> bool:
        last = self._last_alert.get((ip, attack_type))
        if last is not None and (now - last) < self.cooldown:
            return True
        self._last_alert[(ip, attack_type)] = now
        return False

    # ------------------------------------------------------------------
    def inspect(self, packet):
        """
        Feed one packet to the detector.
        Returns a list of Alert objects (usually empty).
        """
        alerts = []
        now = packet.timestamp
        ip = packet.src_ip

        with self._lock:
            # ---------------------------------------------- PORT SCAN
            ports = self._ports[ip]
            ports.append((now, packet.dst_port))
            self._prune(ports, now - self.scan_window, is_pair=True)
            unique_ports = {p for _, p in ports}
            if len(unique_ports) >= self.scan_threshold:
                if not self._on_cooldown(ip, config.PORT_SCAN, now):
                    alerts.append(Alert(
                        attack_type=config.PORT_SCAN,
                        source_ip=ip,
                        severity="HIGH",
                        timestamp=now,
                        details=(f"{len(unique_ports)} unique destination ports "
                                 f"in {self.scan_window}s "
                                 f"(threshold {self.scan_threshold})"),
                    ))

            # ---------------------------------------------- BRUTE FORCE
            if packet.is_failed_auth:
                fails = self._auth_fails[ip]
                fails.append(now)
                self._prune(fails, now - self.brute_window)
                if len(fails) >= self.brute_threshold:
                    if not self._on_cooldown(ip, config.BRUTE_FORCE, now):
                        alerts.append(Alert(
                            attack_type=config.BRUTE_FORCE,
                            source_ip=ip,
                            severity="HIGH",
                            timestamp=now,
                            details=(f"{len(fails)} failed logins on port "
                                     f"{packet.dst_port} in {self.brute_window}s "
                                     f"(threshold {self.brute_threshold})"),
                        ))

            # ---------------------------------------------- TRAFFIC FLOOD
            pkts = self._packets[ip]
            pkts.append(now)
            self._prune(pkts, now - self.flood_window)
            if len(pkts) >= self.flood_threshold:
                if not self._on_cooldown(ip, config.TRAFFIC_FLOOD, now):
                    alerts.append(Alert(
                        attack_type=config.TRAFFIC_FLOOD,
                        source_ip=ip,
                        severity="HIGH",
                        timestamp=now,
                        details=(f"{len(pkts)} packets in {self.flood_window}s "
                                 f"(threshold {self.flood_threshold})"),
                    ))

        return alerts

    # ------------------------------------------------------------------
    def live_counters(self, ip: str) -> dict:
        """Current window sizes for one IP — used by the Detection tab."""
        now = time.time()
        with self._lock:
            ports = {p for ts, p in self._ports.get(ip, ()) if ts >= now - self.scan_window}
            fails = [t for t in self._auth_fails.get(ip, ()) if t >= now - self.brute_window]
            pkts = [t for t in self._packets.get(ip, ()) if t >= now - self.flood_window]
        return {"unique_ports": len(ports), "failed_logins": len(fails), "packets": len(pkts)}

    def tracked_ips(self):
        with self._lock:
            return list(self._packets.keys())
