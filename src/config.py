"""
config.py
Central configuration for the Mini Firewall Simulator.

Everything that a user might want to tweak lives here or in the
`settings` table of the database (see database/db_manager.py).
"""

import os

# ---------------------------------------------------------------- paths
# src/config.py  ->  src/  ->  project root
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SRC_DIR)
DATA_DIR = os.path.join(BASE_DIR, "data")
DOCS_DIR = os.path.join(BASE_DIR, "docs")
os.makedirs(DATA_DIR, exist_ok=True)

# ---------------------------------------------------------------- database
# PostgreSQL connection settings.
# Values come from environment variables so no password is ever committed
# to git. Copy .env.example to .env and edit it, or export the variables
# in your shell. The fallbacks below match a default local install.
try:
    from dotenv import load_dotenv           # optional convenience
    load_dotenv(os.path.join(BASE_DIR, ".env"))
except ImportError:
    pass

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "firewall_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")

# Connection pool size. Two is enough: one for the GUI thread, one for the
# traffic simulator thread. A third is kept spare.
DB_POOL_MIN = 1
DB_POOL_MAX = 5


def db_params(dbname=None) -> dict:
    """Keyword arguments for psycopg2.connect()."""
    return {
        "host": DB_HOST,
        "port": DB_PORT,
        "dbname": dbname or DB_NAME,
        "user": DB_USER,
        "password": DB_PASSWORD,
    }


def db_summary() -> str:
    """Readable connection string for the Settings tab (no password)."""
    return f"postgresql://{DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# ---------------------------------------------------------------- app
APP_NAME = "Mini Firewall Simulator"
APP_VERSION = "1.0"

PROTOCOLS = ["TCP", "UDP"]
ACTIONS = ["ALLOW", "BLOCK"]
POLICIES = ["DENY", "ALLOW"]

# Attack type names (used in DB + charts)
PORT_SCAN = "PORT_SCAN"
BRUTE_FORCE = "BRUTE_FORCE"
TRAFFIC_FLOOD = "TRAFFIC_FLOOD"
STEALTH_SCAN = "STEALTH_SCAN"
SQL_INJECTION = "SQL_INJECTION"
XSS = "XSS"
PATH_TRAVERSAL = "PATH_TRAVERSAL"
ATTACK_TYPES = [PORT_SCAN, BRUTE_FORCE, TRAFFIC_FLOOD, STEALTH_SCAN, SQL_INJECTION, XSS, PATH_TRAVERSAL]

# Packet "kind" — a simulation label, not a real protocol field
KIND_NORMAL = "NORMAL"
KIND_AUTH = "AUTH"
KIND_SCAN = "SCAN"
KIND_FLOOD = "FLOOD"
KIND_STEALTH = "STEALTH"
KIND_SQLI = "SQLI"
KIND_XSS = "XSS"
KIND_TRAVERSAL = "TRAVERSAL"

# Connection tracking states (RFC / Netfilter conntrack)
CONN_NEW = "NEW"
CONN_ESTABLISHED = "ESTABLISHED"
CONN_RELATED = "RELATED"
CONN_INVALID = "INVALID"
CONN_CLOSED = "CLOSED"

# ---------------------------------------------------------------- defaults
# These are written into the `settings` table the first time the app runs.
# After that, the values in the database win (Settings tab edits them).
DEFAULT_SETTINGS = {
    "default_policy": "DENY",       # default DENY policy
    "auto_block": "1",              # 1 = auto-blacklist attacking IPs
    "dpi_enabled": "1",             # 1 = Deep Packet Inspection enabled, 0 = disabled

    "stateful_inspection": "1",     # 1 = stateful connection tracking enabled, 0 = stateless
    "conntrack_tcp_timeout": "120", # seconds before idle TCP connection is expired
    "conntrack_udp_timeout": "30",  # seconds before idle UDP stream is expired

    "portscan_window": "10",        # seconds
    "portscan_threshold": "10",     # unique destination ports

    "bruteforce_window": "60",      # seconds
    "bruteforce_threshold": "5",    # failed auth attempts

    "flood_window": "5",            # seconds
    "flood_threshold": "100",       # packets

    "alert_cooldown": "15",         # do not re-alert same IP+type for N seconds
    "sim_speed": "20",              # normal traffic packets per second
}

# UI
MAX_LIVE_ROWS = 400                 # rows kept in the live Traffic Monitor table
UI_REFRESH_MS = 200                 # how often the GUI drains the event queue
CHART_REFRESH_MS = 1000             # how often dashboard charts redraw
CHART_HISTORY = 60                  # seconds of history in the traffic chart
