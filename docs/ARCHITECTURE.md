# Architecture

## Layers

The project is split into five layers. Each one only talks to the layer below it.

```
          ui/            Tkinter widgets, charts, tables
           │
      controller.py      packet pipeline, event queue, live counters
           │
  ┌────────┼────────┬──────────────┐
firewall/  detection/  simulation/   ← business logic, no GUI code
  └────────┼────────┴──────────────┘
           │
      database/          all SQL in one class
           │
       models/           plain dataclasses shared by everyone
```

Why this matters: the firewall logic, detection logic and database layer contain
no Tkinter imports at all. They can be tested or reused from a terminal script,
and the GUI can be rewritten without touching them.

---

## Module by module

### `models/`

Three dataclasses with no behaviour beyond simple helpers.

* `Packet` — one simulated packet. Carries the five-tuple (source IP, source
  port, destination IP, destination port, protocol) plus a `kind` label used by
  the simulator and an `auth_success` flag used by brute-force detection. The
  firewall fills in `action`, `reason` and `rule_id` as it processes the packet.
* `Rule` — one firewall rule, with a `matches(packet)` method.
* `Alert` — one detected attack.

`rule.py` also holds the three matching helpers: `ip_matches`, `port_matches`
and `protocol_matches`. Keeping them as module-level functions makes them easy
to explain and easy to check by hand.

### `database/db_manager.py`

One class, `DatabaseManager`, wrapping a PostgreSQL connection pool.

Three details worth knowing:

* Two threads use the database at once — the Tkinter GUI thread and the traffic
  simulator thread. A single connection would have to be serialised behind a
  lock, so instead we use `psycopg2.pool.ThreadedConnectionPool`. Each thread
  borrows a connection, runs its query, and returns it.
* The `_cursor()` context manager handles borrow, commit, rollback and return,
  so no individual query has to remember any of that. A failed statement rolls
  back before the connection goes back to the pool, which matters in PostgreSQL:
  a connection left in a failed transaction rejects every later query with
  "current transaction is aborted".
* Inserts end with `RETURNING id` because PostgreSQL has no `lastrowid`.

Rows come back as dictionaries (`RealDictCursor`), so the rest of the code can
write `row["src_ip"]` instead of `row[2]`.

`schema.sql` runs on startup. Every statement uses `IF NOT EXISTS`, so starting
the app again never destroys data.

`setup_db.py` is separate because PostgreSQL will not create a database on
demand the way SQLite creates a file. It connects to the built-in `postgres`
database, issues `CREATE DATABASE`, then builds the tables.

### `firewall/ip_lists.py`

The whitelist and blacklist live in the `ip_lists` table, but checking them for
every packet with an SQL query would be slow. So `IPListManager` keeps both
lists as Python `set` objects in memory and refreshes them from the database
whenever they change. A set lookup is O(1).

### `firewall/rule_engine.py`

`evaluate(packet)` returns a `Decision` object. The order is fixed:

1. **Whitelist** — trusted IPs are allowed immediately and are never
   auto-blocked.
2. **Blacklist** — banned IPs are blocked before any rule is examined.
3. **Rules** — the rule list is already sorted by priority when it comes out of
   the database, so a simple `for` loop with an early `return` gives
   "first match wins".
4. **Default policy** — DENY.

### `detection/detector.py`

One `collections.deque` per source IP per attack type. On every packet we append
the new entry and then pop entries older than the window from the left. The
deque therefore always represents exactly "the last N seconds", and detection is
just `len(window) >= threshold`.

Using a deque rather than a list matters: popping from the left of a list is
O(n), popping from the left of a deque is O(1).

A cooldown dictionary keyed by `(ip, attack_type)` prevents one attack from
generating hundreds of duplicate alerts while its window stays full.

### `simulation/traffic_simulator.py`

Runs a loop on a `threading.Thread`. Each iteration:

1. Checks a job queue for a pending attack scenario and plays it out packet by
   packet if one is waiting.
2. Emits one normal packet and sleeps for `1 / speed` seconds.

Attack scenarios are queued rather than executed directly, so clicking a button
in the GUI never blocks the interface.

### `controller.py`

`handle_packet` is the pipeline. It runs on the simulator thread and performs
the six steps described in the README diagram, ending by putting an event on a
`queue.Queue`.

### `ui/app.py`

Tkinter is not thread safe — calling a widget method from a background thread
can crash the interpreter. The solution used here is the standard one:

* the background thread only **puts** events on a queue
* the main thread **drains** that queue from a repeating `after()` callback
  (`FirewallApp._pump`)

`_pump` processes at most 400 events per cycle so that a 1000-packet flood
cannot freeze the window.

---

## Threading summary

| Thread | What it does | Touches widgets? |
|--------|--------------|------------------|
| Main (Tkinter) | draws the GUI, drains the event queue, redraws charts every second | yes |
| `TrafficSimulator` | generates packets, runs the pipeline, writes to PostgreSQL | no |

Shared state is protected by two locks — one in `IPListManager`, one in
`AttackDetector` — plus one guarding the counters in `Controller`. The database
needs no lock of its own because the connection pool gives each thread its own
connection.
