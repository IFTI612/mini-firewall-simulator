"""
ip_lists.py
Whitelist / blacklist manager.

The lists live in the database, but we keep an in-memory copy so that
checking an IP during packet processing is an O(1) set lookup instead of
an SQL query for every single packet.
"""

import threading

WHITELIST = "WHITELIST"
BLACKLIST = "BLACKLIST"


class IPListManager:
    def __init__(self, db):
        self.db = db
        self._lock = threading.Lock()
        self._white = set()
        self._black = set()
        self.reload()

    # ------------------------------------------------------------------
    def reload(self):
        """Re-read both lists from the database into memory."""
        rows = self.db.get_ip_list()
        white, black = set(), set()
        for r in rows:
            if r["list_type"] == WHITELIST:
                white.add(r["ip"])
            else:
                black.add(r["ip"])
        with self._lock:
            self._white, self._black = white, black

    # ------------------------------------------------------------------
    def is_whitelisted(self, ip: str) -> bool:
        with self._lock:
            return ip in self._white

    def is_blacklisted(self, ip: str) -> bool:
        with self._lock:
            return ip in self._black

    def blacklist_size(self) -> int:
        with self._lock:
            return len(self._black)

    # ------------------------------------------------------------------
    def add(self, ip: str, list_type: str, reason: str = ""):
        """Add an IP to a list. An IP can only be on one list at a time."""
        self.db.add_ip(ip, list_type, reason)
        with self._lock:
            self._white.discard(ip)
            self._black.discard(ip)
            (self._white if list_type == WHITELIST else self._black).add(ip)

    def remove(self, ip: str):
        self.db.remove_ip(ip)
        with self._lock:
            self._white.discard(ip)
            self._black.discard(ip)

    def entries(self, list_type: str):
        return self.db.get_ip_list(list_type)
