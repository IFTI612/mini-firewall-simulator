"""
rule_engine.py
The heart of the firewall: decide ALLOW or BLOCK for one packet.

Decision order (this is the part to memorise for the viva)
---------------------------------------------------------
1. Whitelist  -> ALLOW immediately (trusted IP, never auto-blocked)
2. Blacklist  -> BLOCK immediately (manually banned or auto-blocked)
3. Rules      -> first match wins, rules sorted by priority (low number first)
4. No match   -> default policy, which is DENY
"""

import threading

import config
from firewall.conntrack import ConnectionTracker
from firewall.dpi import DPISignatureEngine
from firewall.ip_lists import IPListManager


class Decision:
    """Result of evaluating one packet."""

    def __init__(self, action: str, reason: str, rule_id: int = 0):
        self.action = action          # ALLOW / BLOCK
        self.reason = reason
        self.rule_id = rule_id

    def __repr__(self):
        return f"<Decision {self.action}: {self.reason}>"


class RuleEngine:
    def __init__(self, db, ip_lists: IPListManager):
        self.db = db
        self.ip_lists = ip_lists
        self.conntrack = ConnectionTracker()
        self.dpi = DPISignatureEngine()
        self._lock = threading.Lock()
        self._rules = []
        self.default_policy = "DENY"
        self.stateful_enabled = True
        self.dpi_enabled = True
        self.reload()

    # ------------------------------------------------------------------
    def reload(self):
        """Pull the rule set, default policy, conntrack, and DPI settings from the database."""
        rules = self.db.get_rules()          # already sorted by priority
        policy = self.db.get_setting("default_policy", "DENY")
        stateful = self.db.get_bool_setting("stateful_inspection")
        dpi_on = self.db.get_bool_setting("dpi_enabled")
        tcp_timeout = self.db.get_int_setting("conntrack_tcp_timeout", 120)
        udp_timeout = self.db.get_int_setting("conntrack_udp_timeout", 30)

        self.conntrack.set_timeouts(tcp_timeout, udp_timeout)
        with self._lock:
            self._rules = rules
            self.default_policy = policy
            self.stateful_enabled = stateful
            self.dpi_enabled = dpi_on

    def rules(self):
        with self._lock:
            return list(self._rules)

    # ------------------------------------------------------------------
    def evaluate(self, packet) -> Decision:
        """Apply the stateful and DPI decision chain to a packet."""

        # 1. Whitelist wins over everything
        if self.ip_lists.is_whitelisted(packet.src_ip):
            packet.conn_state = config.CONN_ESTABLISHED
            return Decision("ALLOW", "Whitelisted source IP")

        # 2. Blacklist (manual bans and auto-blocked attackers)
        if self.ip_lists.is_blacklisted(packet.src_ip):
            packet.conn_state = config.CONN_INVALID
            return Decision("BLOCK", "Blacklisted source IP")

        with self._lock:
            stateful = self.stateful_enabled
            dpi_on = self.dpi_enabled
            rules = self._rules
            policy = self.default_policy

        # 3. Deep Packet Inspection (DPI / L7 Signatures)
        if dpi_on and packet.payload:
            match = self.dpi.inspect(packet)
            if match:
                packet.dpi_match = match
                if stateful:
                    self.conntrack.drop_connection(packet)
                return Decision("BLOCK", f"DPI: {match.attack_type} blocked ({match.name})")

        # 4. Stateful Inspection & Connection Tracking
        if stateful:
            conn_state, track_reason = self.conntrack.process_packet(packet)
            packet.conn_state = conn_state

            # Drop INVALID packets (unsolicited ACKs, stealth scans, out-of-order data)
            if conn_state == config.CONN_INVALID:
                return Decision("BLOCK", f"Stateful Conntrack: INVALID ({track_reason})")
        else:
            packet.conn_state = "STATELESS"

        # 5. Fast-path for verified ESTABLISHED connections
        if stateful and packet.conn_state in (config.CONN_ESTABLISHED, config.CONN_RELATED):
            flag_str = f" [{packet.flags}]" if packet.flags else ""
            return Decision("ALLOW", f"Stateful Conntrack: ESTABLISHED flow{flag_str}")

        # 4. First matching rule, by priority (for NEW connections or stateless mode)
        for rule in rules:
            if rule.matches(packet):
                label = rule.description or f"rule #{rule.id}"
                if stateful and packet.conn_state == config.CONN_NEW:
                    if rule.action == "ALLOW":
                        self.conntrack.confirm_connection(packet)
                    else:
                        self.conntrack.drop_connection(packet)

                return Decision(rule.action,
                                f"Matched rule #{rule.id} ({label})",
                                rule.id)

        # 5. Nothing matched -> default policy
        if policy == "ALLOW":
            if stateful and packet.conn_state == config.CONN_NEW:
                self.conntrack.confirm_connection(packet)
            return Decision("ALLOW", "Default policy: ALLOW")

        if stateful and packet.conn_state == config.CONN_NEW:
            self.conntrack.drop_connection(packet)
        return Decision("BLOCK", "Default policy: DENY")
