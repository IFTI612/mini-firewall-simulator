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
        self._lock = threading.Lock()
        self._rules = []
        self.default_policy = "DENY"
        self.reload()

    # ------------------------------------------------------------------
    def reload(self):
        """Pull the rule set and default policy from the database."""
        rules = self.db.get_rules()          # already sorted by priority
        policy = self.db.get_setting("default_policy", "DENY")
        with self._lock:
            self._rules = rules
            self.default_policy = policy

    def rules(self):
        with self._lock:
            return list(self._rules)

    # ------------------------------------------------------------------
    def evaluate(self, packet) -> Decision:
        """Apply the full decision chain to a packet."""

        # 1. Whitelist wins over everything
        if self.ip_lists.is_whitelisted(packet.src_ip):
            return Decision("ALLOW", "Whitelisted source IP")

        # 2. Blacklist (manual bans and auto-blocked attackers)
        if self.ip_lists.is_blacklisted(packet.src_ip):
            return Decision("BLOCK", "Blacklisted source IP")

        # 3. First matching rule, by priority
        with self._lock:
            rules = self._rules
            policy = self.default_policy

        for rule in rules:
            if rule.matches(packet):
                label = rule.description or f"rule #{rule.id}"
                return Decision(rule.action,
                                f"Matched rule #{rule.id} ({label})",
                                rule.id)

        # 4. Nothing matched -> default policy
        if policy == "ALLOW":
            return Decision("ALLOW", "Default policy: ALLOW")
        return Decision("BLOCK", "Default policy: DENY")
