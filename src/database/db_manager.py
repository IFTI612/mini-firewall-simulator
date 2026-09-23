"""
db_manager.py
All PostgreSQL access lives here. No other module imports psycopg2, so
changing the database backend only means rewriting this one file.

Two threads use the database at the same time (the Tkinter GUI thread and
the traffic simulator thread). Instead of sharing one connection behind a
lock, we use psycopg2's ThreadedConnectionPool: each thread borrows a
connection, uses it, and returns it. That is the normal way to talk to
PostgreSQL from a multi-threaded program.
"""

import csv
import os
import time
from contextlib import contextmanager

import psycopg2
from psycopg2 import pool as pg_pool
from psycopg2.extras import RealDictCursor

import config
from models.rule import Rule
from models.alert import Alert

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")


class DatabaseError(Exception):
    """Raised when the application cannot reach PostgreSQL."""


class DatabaseManager:
    """Thin, explicit wrapper around the PostgreSQL database."""

    def __init__(self, params: dict = None):
        self.params = params or config.db_params()
        try:
            self.pool = pg_pool.ThreadedConnectionPool(
                config.DB_POOL_MIN, config.DB_POOL_MAX, **self.params)
        except psycopg2.OperationalError as exc:
            raise DatabaseError(self._friendly_error(exc)) from exc

        self._create_schema()
        self._seed_settings()
        self._seed_default_rules()

    # ------------------------------------------------------------ errors
    def _friendly_error(self, exc) -> str:
        return (
            f"Could not connect to PostgreSQL at "
            f"{self.params['host']}:{self.params['port']} "
            f"(database '{self.params['dbname']}', user '{self.params['user']}').\n\n"
            f"{exc}\n"
            f"Checklist:\n"
            f"  1. Is the PostgreSQL service running?\n"
            f"  2. Does the database exist?  python src/database/setup_db.py\n"
            f"  3. Are DB_USER / DB_PASSWORD in your .env file correct?"
        )

    # ------------------------------------------------------------ plumbing
    @contextmanager
    def _cursor(self, commit=False):
        """Borrow a connection from the pool and hand back a dict cursor."""
        conn = self.pool.getconn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                yield cur
            if commit:
                conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.pool.putconn(conn)

    def _query(self, sql, params=()):
        with self._cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()

    def _one(self, sql, params=()):
        rows = self._query(sql, params)
        return rows[0] if rows else None

    def _execute(self, sql, params=()):
        """Run a statement. If it ends with RETURNING id, give back that id."""
        with self._cursor(commit=True) as cur:
            cur.execute(sql, params)
            if cur.description is not None:
                row = cur.fetchone()
                if row:
                    return row.get("id")
        return None

    def _create_schema(self):
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            script = f.read()
        with self._cursor(commit=True) as cur:
            cur.execute(script)
            cur.execute("ALTER TABLE traffic_logs ADD COLUMN IF NOT EXISTS flags TEXT DEFAULT ''")
            cur.execute("ALTER TABLE traffic_logs ADD COLUMN IF NOT EXISTS conn_state TEXT DEFAULT ''")

    def close(self):
        if self.pool and not self.pool.closed:
            self.pool.closeall()

    # ------------------------------------------------------------ settings
    def _seed_settings(self):
        for key, value in config.DEFAULT_SETTINGS.items():
            self._execute(
                "INSERT INTO settings (key, value) VALUES (%s, %s) "
                "ON CONFLICT (key) DO NOTHING",
                (key, value),
            )

    def get_setting(self, key, default=None):
        row = self._one("SELECT value FROM settings WHERE key = %s", (key,))
        if row is None:
            return default if default is not None else config.DEFAULT_SETTINGS.get(key)
        return row["value"]

    def get_int_setting(self, key, default=0):
        try:
            return int(self.get_setting(key))
        except (TypeError, ValueError):
            return default

    def get_bool_setting(self, key):
        return self.get_setting(key) in ("1", "true", "True", "yes")

    def set_setting(self, key, value):
        self._execute(
            "INSERT INTO settings (key, value) VALUES (%s, %s) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            (key, str(value)),
        )

    def all_settings(self) -> dict:
        return {r["key"]: r["value"] for r in self._query("SELECT key, value FROM settings")}

    # ------------------------------------------------------------ rules
    def _seed_default_rules(self):
        row = self._one("SELECT COUNT(*) AS c FROM firewall_rules")
        if row and row["c"] > 0:
            return
        starter_rules = [
            # priority, src_ip, dst_ip, src_port, dst_port, proto, action, desc
            (10, "*", "*", "*", "22", "TCP", "BLOCK", "Block SSH from anywhere"),
            (20, "192.168.1.*", "*", "*", "*", "*", "ALLOW", "Trust local LAN"),
            (30, "*", "*", "*", "80", "TCP", "ALLOW", "Allow HTTP"),
            (40, "*", "*", "*", "443", "TCP", "ALLOW", "Allow HTTPS"),
            (50, "*", "*", "*", "53", "UDP", "ALLOW", "Allow DNS"),
            (60, "*", "*", "*", "3389", "TCP", "BLOCK", "Block RDP"),
        ]
        for r in starter_rules:
            self.add_rule(Rule(priority=r[0], src_ip=r[1], dst_ip=r[2], src_port=r[3],
                               dst_port=r[4], protocol=r[5], action=r[6], description=r[7]))

    def get_rules(self):
        rows = self._query(
            "SELECT * FROM firewall_rules ORDER BY priority ASC, id ASC")
        return [Rule.from_db_row(r) for r in rows]

    def add_rule(self, rule: Rule) -> int:
        return self._execute(
            "INSERT INTO firewall_rules "
            "(priority, src_ip, dst_ip, src_port, dst_port, protocol, action, enabled, description) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (rule.priority, rule.src_ip, rule.dst_ip, rule.src_port, rule.dst_port,
             rule.protocol, rule.action, rule.enabled, rule.description),
        )

    def update_rule(self, rule: Rule):
        self._execute(
            "UPDATE firewall_rules SET priority=%s, src_ip=%s, dst_ip=%s, src_port=%s, "
            "dst_port=%s, protocol=%s, action=%s, enabled=%s, description=%s WHERE id=%s",
            (rule.priority, rule.src_ip, rule.dst_ip, rule.src_port, rule.dst_port,
             rule.protocol, rule.action, rule.enabled, rule.description, rule.id),
        )

    def delete_rule(self, rule_id: int):
        self._execute("DELETE FROM firewall_rules WHERE id = %s", (rule_id,))

    def toggle_rule(self, rule_id: int):
        self._execute(
            "UPDATE firewall_rules SET enabled = 1 - enabled WHERE id = %s", (rule_id,))

    # ------------------------------------------------------------ traffic
    def log_packet(self, packet) -> int:
        return self._execute(
            "INSERT INTO traffic_logs "
            "(ts, ts_text, src_ip, src_port, dst_ip, dst_port, protocol, kind, action, reason, rule_id, size, flags, conn_state) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (packet.timestamp, packet.datetime_text, packet.src_ip, packet.src_port,
             packet.dst_ip, packet.dst_port, packet.protocol, packet.kind,
             packet.action, packet.reason, packet.rule_id, packet.size,
             getattr(packet, "flags", ""), getattr(packet, "conn_state", "")),
        )

    def get_logs(self, limit=200, action=None, src_ip=None, protocol=None, kind=None):
        sql = "SELECT * FROM traffic_logs WHERE 1=1"
        params = []
        if action and action != "ALL":
            sql += " AND action = %s"
            params.append(action)
        if src_ip:
            sql += " AND src_ip LIKE %s"
            params.append(f"%{src_ip}%")
        if protocol and protocol != "ALL":
            sql += " AND protocol = %s"
            params.append(protocol)
        if kind and kind != "ALL":
            sql += " AND kind = %s"
            params.append(kind)
        sql += " ORDER BY id DESC LIMIT %s"
        params.append(int(limit))
        return self._query(sql, tuple(params))

    # ------------------------------------------------------------ alerts
    def log_alert(self, alert: Alert) -> int:
        return self._execute(
            "INSERT INTO security_alerts (ts, ts_text, attack_type, source_ip, severity, details, auto_blocked) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (alert.timestamp, alert.datetime_text, alert.attack_type,
             alert.source_ip, alert.severity, alert.details, alert.auto_blocked),
        )

    def get_alerts(self, limit=200, attack_type=None, source_ip=None):
        sql = "SELECT * FROM security_alerts WHERE 1=1"
        params = []
        if attack_type and attack_type != "ALL":
            sql += " AND attack_type = %s"
            params.append(attack_type)
        if source_ip:
            sql += " AND source_ip LIKE %s"
            params.append(f"%{source_ip}%")
        sql += " ORDER BY id DESC LIMIT %s"
        params.append(int(limit))
        return self._query(sql, tuple(params))

    # ------------------------------------------------------------ ip lists
    def get_ip_list(self, list_type=None):
        if list_type:
            return self._query(
                "SELECT * FROM ip_lists WHERE list_type = %s ORDER BY added_at DESC",
                (list_type,))
        return self._query("SELECT * FROM ip_lists ORDER BY added_at DESC")

    def add_ip(self, ip: str, list_type: str, reason: str = ""):
        self._execute(
            "INSERT INTO ip_lists (ip, list_type, reason) VALUES (%s,%s,%s) "
            "ON CONFLICT (ip) DO UPDATE SET list_type = EXCLUDED.list_type, "
            "reason = EXCLUDED.reason",
            (ip, list_type, reason),
        )

    def remove_ip(self, ip: str):
        self._execute("DELETE FROM ip_lists WHERE ip = %s", (ip,))

    # ------------------------------------------------------------ statistics
    def get_statistics(self) -> dict:
        row = self._one(
            "SELECT COUNT(*) AS total, "
            "COALESCE(SUM(CASE WHEN action='ALLOW' THEN 1 ELSE 0 END), 0) AS allowed, "
            "COALESCE(SUM(CASE WHEN action='BLOCK' THEN 1 ELSE 0 END), 0) AS blocked "
            "FROM traffic_logs")
        alerts = self._one("SELECT COUNT(*) AS c FROM security_alerts")
        blacklisted = self._one(
            "SELECT COUNT(*) AS c FROM ip_lists WHERE list_type='BLACKLIST'")
        return {
            "total": int(row["total"]) if row else 0,
            "allowed": int(row["allowed"]) if row else 0,
            "blocked": int(row["blocked"]) if row else 0,
            "alerts": int(alerts["c"]) if alerts else 0,
            "blacklisted": int(blacklisted["c"]) if blacklisted else 0,
        }

    def get_attack_counts(self) -> dict:
        rows = self._query(
            "SELECT attack_type, COUNT(*) AS c FROM security_alerts GROUP BY attack_type")
        counts = {t: 0 for t in config.ATTACK_TYPES}
        for r in rows:
            counts[r["attack_type"]] = int(r["c"])
        return counts

    def get_top_talkers(self, limit=5):
        return self._query(
            "SELECT src_ip, COUNT(*) AS c FROM traffic_logs "
            "GROUP BY src_ip ORDER BY c DESC LIMIT %s", (limit,))

    def get_protocol_counts(self) -> dict:
        rows = self._query(
            "SELECT protocol, COUNT(*) AS c FROM traffic_logs GROUP BY protocol")
        return {r["protocol"]: int(r["c"]) for r in rows}

    # ------------------------------------------------------------ maintenance
    def clear_traffic_logs(self):
        self._execute("TRUNCATE TABLE traffic_logs RESTART IDENTITY")

    def clear_alerts(self):
        self._execute("TRUNCATE TABLE security_alerts RESTART IDENTITY")

    def clear_all(self):
        self.clear_traffic_logs()
        self.clear_alerts()

    # ------------------------------------------------------------ export
    def export_logs_csv(self, path: str, limit=100000, **filters) -> int:
        """Write traffic logs to a CSV file. Returns the number of rows."""
        rows = self.get_logs(limit=limit, **filters)
        headers = ["id", "ts_text", "src_ip", "src_port", "dst_ip", "dst_port",
                   "protocol", "flags", "conn_state", "kind", "action", "reason", "rule_id", "size"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for r in rows:
                writer.writerow([r.get(h, "") for h in headers])
        return len(rows)

    def export_alerts_csv(self, path: str, limit=100000) -> int:
        rows = self.get_alerts(limit=limit)
        headers = ["id", "ts_text", "attack_type", "source_ip",
                   "severity", "details", "auto_blocked"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for r in rows:
                writer.writerow([r[h] for h in headers])
        return len(rows)

    @staticmethod
    def default_export_name(prefix="security_logs") -> str:
        return f"{prefix}_{time.strftime('%Y%m%d_%H%M%S')}.csv"
