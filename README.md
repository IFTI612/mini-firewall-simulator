# Mini Firewall Simulator with Attack Detection

An educational desktop application that simulates how a network firewall filters
traffic and how an intrusion detection system spots three classic attack
patterns. Built with **Python + Tkinter + PostgreSQL + Matplotlib**.

> **Safety statement**
> Every packet in this program is a Python object created by the built-in traffic
> generator. The application opens no sockets, captures no real traffic, and
> never contacts, scans or attacks any external system. It is safe to run on a
> normal machine or inside a virtual machine.

---

## Features

| #   | Feature                                                                                    |
| --- | ------------------------------------------------------------------------------------------ |
| 1   | Local packet simulation (stateful TCP conversations + 4 attack scenarios)                  |
| 2   | Stateful Inspection: RFC 793 TCP Conntrack, 3-way handshakes, fast-path, default DENY     |
| 3   | Attack detection: port scan, brute force, traffic flood, stealth scans (FIN/Xmas/NULL)     |
| 4   | Automatic alert generation with optional automatic IP blocking                             |
| 5   | IP whitelist and blacklist                                                                 |
| 6   | PostgreSQL storage for traffic logs, rules, alerts and IP lists                            |
| 7   | Eight-tab Tkinter GUI with dedicated Live Connection Tracking tab                         |
| 8   | Live dashboard with active connection counters and Matplotlib charts                      |
| 9   | CSV export of traffic logs and security alerts                                             |

---

## Requirements

- Python 3.9 or newer
- Tkinter (bundled with Python on Windows/macOS; on Ubuntu run `sudo apt install python3-tk`)
- **PostgreSQL 12 or newer**, running locally
- Matplotlib and psycopg2 (installed by `requirements.txt`)

### 1. Install PostgreSQL

```bash
# Ubuntu / Debian
sudo apt install postgresql
sudo systemctl start postgresql

# macOS
brew install postgresql@16 && brew services start postgresql@16
```

Windows: use the installer from postgresql.org and remember the password you
set for the `postgres` user.

### 2. Install the project

```bash
git clone <your-repo-url>
cd mini-firewall-simulator

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### 3. Configure the connection

```bash
cp .env.example .env
```

Then edit `.env`:

```
DB_HOST=localhost
DB_PORT=5432
DB_NAME=firewall_db
DB_USER=postgres
DB_PASSWORD=your_password_here
```

`.env` is in `.gitignore`, so your password never reaches the repository.
If you prefer, export the same names as environment variables instead.

### 4. Create the database

```bash
python src/database/setup_db.py
```

This creates the `firewall_db` database, builds the five tables and inserts six
starter firewall rules. Run it once. Use `--reset` to drop everything and start
over.

## Running

```bash
python src/main.py
```

---

## Quick demo

1. Click **Start simulation**. Normal traffic begins flowing.
2. Open **Traffic Monitor** — green rows were allowed, red rows were blocked.
3. Open **Firewall Rules** — note rule #1 blocks SSH. Watch SSH packets get
   blocked in the monitor.
4. Open **Attack Detection** and click **Launch port scan**. An alert appears
   within a second and the attacking IP is added to the blacklist.
5. Return to **Dashboard** — the counters and both charts have updated.
6. Open **IP Management** — the attacker is now on the blacklist, so every
   further packet from that IP is blocked before any rule is even checked.
7. Open **Security Logs** and click **Export traffic to CSV**.

---

## Project structure

```
mini-firewall-simulator/
├── README.md
├── requirements.txt
├── .gitignore
├── .env.example                   # template for database credentials
├── data/                          # CSV exports (created at runtime)
├── docs/
│   ├── ARCHITECTURE.md            # module-by-module explanation
└── src/
    ├── main.py                    # entry point
    ├── config.py                  # paths, constants, default settings
    ├── controller.py              # wires everything together, owns the pipeline
    ├── models/
    │   ├── packet.py              # Packet dataclass
    │   ├── rule.py                # Rule dataclass + IP/port matching
    │   └── alert.py               # Alert dataclass
    ├── firewall/
    │   ├── rule_engine.py         # ALLOW/BLOCK decision, default DENY
    │   └── ip_lists.py            # whitelist / blacklist
    ├── detection/
    │   └── detector.py            # sliding-window attack detection
    ├── simulation/
    │   └── traffic_simulator.py   # fake packet generator (background thread)
    ├── database/
    │   ├── schema.sql             # table definitions
    │   ├── setup_db.py            # one-time database creation
    │   └── db_manager.py          # all SQL lives here
    └── ui/
        ├── app.py                 # main window + event pump
        ├── theme.py               # shared styles and widgets
        ├── dashboard.py
        ├── traffic_monitor.py
        ├── rules_tab.py
        ├── detection_tab.py
        ├── ip_tab.py
        ├── logs_tab.py
        └── settings_tab.py
```

---

## How a packet is processed

```
        simulated packet
               │
      ┌────────▼────────┐
      │   rule engine   │  1. whitelist  → ALLOW
      │                 │  2. blacklist  → BLOCK
      │                 │  3. first matching rule by priority
      │                 │  4. no match   → default DENY
      └────────┬────────┘
               │  ALLOW / BLOCK
      ┌────────▼────────┐
      │ attack detector │  sliding time windows per source IP
      └────────┬────────┘
               │  0 or more alerts
      ┌────────▼────────┐
      │  auto-block ON? │  → add source IP to blacklist
      └────────┬────────┘
               │
      ┌────────▼────────┐
      │   PostgreSQL    │  traffic_logs + security_alerts
      └────────┬────────┘
               │
          event queue  →  Tkinter GUI updates
```

## Detection rules

| Attack          | Condition                                             | Fires on               |
| --------------- | ----------------------------------------------------- | ---------------------- |
| `PORT_SCAN`     | ≥ 10 unique destination ports from one IP within 10 s | the 10th unique port   |
| `BRUTE_FORCE`   | ≥ 5 failed login attempts from one IP within 60 s     | the 5th failed attempt |
| `TRAFFIC_FLOOD` | ≥ 100 packets from one IP within 5 s                  | the 100th packet       |

All six numbers are editable in the **Settings** tab.

After an alert, a cooldown (15 s by default) stops the same IP raising the same
alert on every following packet while its window stays full.

---

## Firewall rule syntax

| Field    | Accepted values                         | Examples                                         |
| -------- | --------------------------------------- | ------------------------------------------------ |
| IP       | `*`, exact, wildcard suffix, CIDR       | `*`, `192.168.1.10`, `192.168.1.*`, `10.0.0.0/8` |
| Port     | `*`, exact, range                       | `*`, `443`, `20-25`                              |
| Protocol | `*`, `TCP`, `UDP`                       | `TCP`                                            |
| Action   | `ALLOW`, `BLOCK`                        | `BLOCK`                                          |
| Priority | any integer, **lower is checked first** | `10`                                             |

The first rule that matches wins. If no rule matches, the default policy applies,
which is **DENY**.

---

## Database tables

| Table             | Purpose                                 |
| ----------------- | --------------------------------------- |
| `traffic_logs`    | every processed packet with its verdict |
| `firewall_rules`  | the rule set                            |
| `security_alerts` | detected attacks                        |
| `ip_lists`        | blacklist and whitelist entries         |
| `settings`        | policy, thresholds, simulation speed    |

Connections are handed out by a `ThreadedConnectionPool`, because the GUI thread
and the traffic simulator thread both query the database.

Swapping PostgreSQL for another backend (Supabase, MySQL, SQLite) only requires
rewriting `src/database/db_manager.py` — no other module imports `psycopg2` or
contains SQL.

---

## Troubleshooting

| Symptom                                 | Fix                                                        |
| --------------------------------------- | ---------------------------------------------------------- |
| `Could not connect to PostgreSQL`       | Is the service running? `sudo systemctl status postgresql` |
| `database "firewall_db" does not exist` | Run `python src/database/setup_db.py`                      |
| `password authentication failed`        | Check `DB_USER` / `DB_PASSWORD` in `.env`                  |
| `ModuleNotFoundError: psycopg2`         | `pip install -r requirements.txt`                          |
| Want a clean slate                      | `python src/database/setup_db.py --reset`                  |

---

## Known limitations

- Traffic is simulated, so results do not reflect real network conditions.
- Detection is threshold-based only; there is no machine learning component.
- Rules are matched in Python, which is fine for a few hundred packets per
  second but not for real line-rate traffic.
- IP lists are exact-match only; CIDR ranges are supported in rules, not in the
  blacklist.

## Author

Course project — Cyber Security.
