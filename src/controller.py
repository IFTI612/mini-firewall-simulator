"""
controller.py
The glue between the background simulator and the GUI.

Packet pipeline (this is the diagram to draw in your viva)
----------------------------------------------------------
    simulated packet
          |
    rule engine  ->  ALLOW / BLOCK decision
          |
    attack detector  ->  0 or more alerts
          |
    save packet + alerts to the database
          |
    if alert and auto-block is ON  ->  add source IP to blacklist
          |
    push an event onto a queue; the GUI drains it with after()

Threading note: everything above runs on the simulator thread. Tkinter is
not thread safe, so we never touch a widget here — we only put events on a
queue that the main thread reads.
"""

import queue
import threading

import config
from database.db_manager import DatabaseManager
from detection.detector import AttackDetector
from firewall.ip_lists import IPListManager, BLACKLIST
from firewall.rule_engine import RuleEngine
from simulation.traffic_simulator import TrafficSimulator


class Controller:
    def __init__(self):
        self.db = DatabaseManager()
        self.ip_lists = IPListManager(self.db)
        self.rule_engine = RuleEngine(self.db, self.ip_lists)
        self.detector = AttackDetector(self.db)
        self.simulator = TrafficSimulator(self.handle_packet)
        self.simulator.set_speed(self.db.get_int_setting("sim_speed", 20))

        self.events = queue.Queue()          # ("packet", pkt) / ("alert", alert)

        # live counters (faster than asking SQL on every refresh)
        self._stat_lock = threading.Lock()
        stats = self.db.get_statistics()
        self.total = stats["total"]
        self.allowed = stats["allowed"]
        self.blocked = stats["blocked"]
        self.attacks = stats["alerts"]

    # ------------------------------------------------------------------ pipeline
    def handle_packet(self, packet):
        """Called on the simulator thread for every generated packet."""

        # 1. firewall decision
        decision = self.rule_engine.evaluate(packet)
        packet.action = decision.action
        packet.reason = decision.reason
        packet.rule_id = decision.rule_id

        # 2. attack detection (runs on every packet, blocked or not —
        #    we still want to *see* an attack even while we drop it)
        alerts = self.detector.inspect(packet)

        # 3. auto-block before the alert is stored, so the alert row
        #    records whether the IP was blacklisted
        auto_block = self.db.get_bool_setting("auto_block")
        for alert in alerts:
            if auto_block and not self.ip_lists.is_whitelisted(alert.source_ip):
                if not self.ip_lists.is_blacklisted(alert.source_ip):
                    self.ip_lists.add(alert.source_ip, BLACKLIST,
                                      f"Auto-blocked: {alert.attack_type}")
                alert.auto_blocked = 1

        # 4. persist
        self.db.log_packet(packet)
        for alert in alerts:
            alert.id = self.db.log_alert(alert)

        # 5. counters
        with self._stat_lock:
            self.total += 1
            if packet.action == "ALLOW":
                self.allowed += 1
            else:
                self.blocked += 1
            self.attacks += len(alerts)

        # 6. tell the GUI
        self.events.put(("packet", packet))
        for alert in alerts:
            self.events.put(("alert", alert))

    # ------------------------------------------------------------------ stats
    def snapshot(self) -> dict:
        with self._stat_lock:
            return {
                "total": self.total,
                "allowed": self.allowed,
                "blocked": self.blocked,
                "attacks": self.attacks,
                "blacklisted": self.ip_lists.blacklist_size(),
            }

    def reset_counters(self):
        with self._stat_lock:
            self.total = self.allowed = self.blocked = self.attacks = 0

    # ------------------------------------------------------------------ control
    def start(self):
        self.simulator.set_speed(self.db.get_int_setting("sim_speed", 20))
        self.simulator.start()

    def stop(self):
        self.simulator.stop()

    def reload_all(self):
        """Called after the user edits rules, IP lists or settings."""
        self.ip_lists.reload()
        self.rule_engine.reload()
        self.detector.reload_thresholds()
        self.simulator.set_speed(self.db.get_int_setting("sim_speed", 20))

    def clear_data(self):
        self.db.clear_all()
        self.detector.reset()
        self.reset_counters()

    def shutdown(self):
        self.stop()
        self.db.close()
