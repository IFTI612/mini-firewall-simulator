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

            # 2. Normal background traffic
            if self.normal_enabled:
                self._emit(self._make_normal_packet())
                time.sleep(1.0 / self.speed)
            else:
                time.sleep(0.05)

    def _emit(self, packet):
        try:
            self.on_packet(packet)
        except Exception as exc:                      # never kill the thread
            print(f"[simulator] packet handler error: {exc}")

    # ------------------------------------------------------------------ generators
    def _make_normal_packet(self) -> Packet:
        """Ordinary looking traffic: web, DNS, mail, an occasional login."""
        src = random.choice(NORMAL_SOURCES + EXTERNAL_SOURCES[:2])
        dst = random.choice(SERVERS)
        dst_port = random.choices(COMMON_PORTS, weights=PORT_WEIGHTS, k=1)[0]
        protocol = "UDP" if dst_port == 53 else "TCP"

        # roughly 1 in 12 normal packets is a successful login
        if random.random() < 0.08:
            return Packet(src_ip=src, dst_ip=dst,
                          src_port=random.randint(1024, 65535), dst_port=22,
                          protocol="TCP", kind=config.KIND_AUTH,
                          auth_success=True, size=random.randint(64, 512))

        return Packet(src_ip=src, dst_ip=dst,
                      src_port=random.randint(1024, 65535), dst_port=dst_port,
                      protocol=protocol, kind=config.KIND_NORMAL,
                      size=random.randint(64, 1500))

    def _run_port_scan(self, src_ip, port_count, delay):
        """One IP touching many different destination ports quickly."""
        dst = random.choice(SERVERS)
        ports = random.sample(SCAN_PORTS, min(port_count, len(SCAN_PORTS)))
        # if more ports are requested than the well-known list holds, top up
        while len(ports) < port_count:
            extra = random.randint(1, 10000)
            if extra not in ports:
                ports.append(extra)

        for port in ports:
            if not self._running.is_set():
                return
            self._emit(Packet(src_ip=src_ip, dst_ip=dst,
                              src_port=random.randint(1024, 65535), dst_port=port,
                              protocol="TCP", kind=config.KIND_SCAN, size=64))
            time.sleep(delay)

    def _run_brute_force(self, src_ip, attempts, port, delay):
        """Repeated failed logins against one service port."""
        dst = random.choice(SERVERS)
        for i in range(attempts):
            if not self._running.is_set():
                return
            # last attempt occasionally "succeeds" — makes the demo realistic
            success = (i == attempts - 1) and random.random() < 0.2
            self._emit(Packet(src_ip=src_ip, dst_ip=dst,
                              src_port=random.randint(1024, 65535), dst_port=port,
                              protocol="TCP", kind=config.KIND_AUTH,
                              auth_success=success, size=128))
            time.sleep(delay)

    def _run_flood(self, src_ip, packet_count, delay):
        """A very high packet rate from a single IP (DoS style)."""
        dst = random.choice(SERVERS)
        dst_port = random.choice([80, 443])
        for _ in range(packet_count):
            if not self._running.is_set():
                return
            self._emit(Packet(src_ip=src_ip, dst_ip=dst,
                              src_port=random.randint(1024, 65535),
                              dst_port=dst_port, protocol="TCP",
                              kind=config.KIND_FLOOD, size=1500))
            time.sleep(delay)
