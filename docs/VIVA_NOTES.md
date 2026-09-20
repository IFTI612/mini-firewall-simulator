# Viva notes

Short answers to the questions most likely to be asked.

---

**What does your project do?**

It simulates a network firewall and an intrusion detection system. A generator
produces fake packets, a rule engine decides ALLOW or BLOCK for each one, and a
detector watches for three attack patterns. Everything is logged to PostgreSQL
and shown in a Tkinter interface with live charts.

**Does it touch a real network?**

No. Every packet is a Python object created by `traffic_simulator.py`. No socket
is opened, no interface is read, and nothing outside the process is contacted.
That was a deliberate design constraint — scanning real systems without
authorisation is illegal.

---

## Firewall

**Explain your rule matching order.**

Whitelist, then blacklist, then rules by priority, then default policy. The
first matching rule wins and the loop returns immediately.

**Why is whitelist checked before blacklist?**

So a trusted address can never be locked out by the automatic blocking feature.
The auto-block code also refuses to blacklist a whitelisted IP, so the two
behaviours agree.

**What is a default DENY policy and why use it?**

If no rule matches a packet, it is blocked. The alternative, default ALLOW,
means anything you forgot to write a rule for gets through. Default DENY fails
safe: a mistake costs you connectivity, not security.

**What does rule priority mean?**

Lower number is evaluated first. The database returns rules with
`ORDER BY priority ASC, id ASC`, so the Python loop is already in the right
order. Priority lets you put a narrow exception above a broad block.

**How do you match `192.168.1.*` or `10.0.0.0/8`?**

`ip_matches()` in `models/rule.py`. A trailing `*` is handled with
`str.startswith`. CIDR is handled by Python's `ipaddress` module:
`ip_address(ip) in ip_network(pattern)`.

---

## Detection

**How does port scan detection work?**

For each source IP I keep a deque of `(timestamp, destination_port)`. On each
packet I append the new entry and drop everything older than 10 seconds from the
left. If the number of *unique* ports in that window reaches 10, I raise a
`PORT_SCAN` alert. A scanner sweeps many ports quickly, which normal traffic
never does.

**Why unique ports and not total packets?**

A client can send 50 packets to port 443 during one download. That is normal. A
scanner sends one packet each to 50 *different* ports. The distinguishing
feature is port diversity, not volume.

**How does brute force detection work?**

Only packets with `kind == AUTH` and `auth_success == False` are counted. Five
of them from the same IP within 60 seconds raises `BRUTE_FORCE`. The fifth
attempt is what fires the alert.

**How does flood detection work?**

A deque of timestamps per IP, window 5 seconds. The 100th packet inside that
window fires `TRAFFIC_FLOOD`. That is a rate of 20 packets per second sustained
from a single address, far above normal.

**Why a deque instead of a list?**

Removing from the front of a list is O(n) because every remaining element
shifts. `deque.popleft()` is O(1). Since we prune on every single packet, that
difference matters.

**What is the cooldown for?**

Once a flood is detected, the window stays full for the next several seconds, so
every subsequent packet would satisfy the condition again. Without a cooldown
you would get hundreds of identical alerts. The cooldown suppresses repeats of
the same `(IP, attack type)` pair for 15 seconds.

**Could you get a false positive?**

Yes. A legitimate service discovery tool or a busy backup client could look like
a scan or a flood. That is why the thresholds are configurable and why there is
a whitelist.

**Could you get a false negative?**

Yes. A slow scan — one port every 30 seconds — never fills a 10-second window,
so it is missed. Real IDS products address this with longer windows and
statistical baselining.

---

## Database

**Why PostgreSQL?**

It is a proper client/server RDBMS, so the log tables can grow large without the
single-writer limitation of an embedded database, and multiple clients could read
the same data at once. It also gives me real types, proper indexes, `TRUNCATE`,
and `ON CONFLICT` upserts.

**What is the trade-off versus SQLite?**

PostgreSQL needs a server installed, a database created in advance and
credentials configured. SQLite is just a file. For a single-user desktop tool
SQLite is simpler; PostgreSQL is the better answer if the logs are meant to be
shared, queried externally, or kept long term.

**How do you handle two threads talking to the database?**

With a `ThreadedConnectionPool`. Each thread borrows its own connection from the
pool instead of sharing one behind a lock, which is the standard pattern for
psycopg2. The pool is sized 1 to 5; only two connections are ever really in use.

**Why do your inserts end with RETURNING id?**

PostgreSQL has no `lastrowid`. `RETURNING id` makes the INSERT hand back the
generated primary key in the same round trip.

**Why do you roll back on error?**

In PostgreSQL, once a statement inside a transaction fails, every later query on
that connection is rejected until the transaction is rolled back. Since
connections are reused from a pool, a failed query must be rolled back before the
connection is returned, or it would poison the next thread that borrows it.

**How do you keep the database password out of git?**

It is read from environment variables, loaded from a `.env` file that is listed
in `.gitignore`. The repository only contains `.env.example` with placeholder
values.

**What are `%s` placeholders for?**

Parameterised queries. The driver sends the value separately from the SQL text,
so user input can never be interpreted as SQL. That is what prevents SQL
injection — relevant here since this is a security project.

**Why is all the SQL in one file?**

Separation of concerns. No other module imports `sqlite3`. If I wanted to move
to Supabase or MySQL, I would rewrite `db_manager.py` and nothing else.

**Which tables do you have?**

`traffic_logs`, `firewall_rules`, `security_alerts`, `ip_lists`, `settings`.

**What are the indexes for?**

`traffic_logs` grows quickly. Indexes on `ts`, `src_ip` and `action` keep the
filtered queries in the Security Logs tab fast as the table grows.

---

## GUI and threading

**Why do you need a queue between the simulator and the GUI?**

Tkinter is not thread safe. Calling a widget method from a background thread can
corrupt its internal state or crash the interpreter. So the background thread
only appends to a `queue.Queue`, and the main thread drains it from a repeating
`after()` callback.

**What is `after()`?**

Tkinter's way of scheduling a function to run later on the main event loop.
`self.after(200, self._pump)` re-runs the pump every 200 ms without blocking the
interface.

**Why cap the pump at 400 events?**

During a flood the queue can fill faster than the GUI can draw. Processing the
whole queue in one cycle would freeze the window. Capping it keeps the interface
responsive and the backlog drains over the next few cycles.

**Why limit the Traffic Monitor to 400 rows?**

A Treeview with tens of thousands of rows becomes slow. The full history is
still in the database and visible in the Security Logs tab.

---

## Design questions

**What would you improve with more time?**

Rate-limiting instead of outright blocking; automatic unblocking after a
timeout; connection state tracking so the firewall is stateful rather than
stateless; and a longer-window detector for slow scans.

**Is your firewall stateful or stateless?**

Stateless. Each packet is judged on its own fields. A real stateful firewall
tracks connections and allows return traffic for a connection it already
approved.

**What is the difference between a firewall and an IDS?**

A firewall decides whether each packet is allowed through, based on rules. An
IDS looks for patterns across many packets and raises alerts. This project
contains both, which is why an attack can be detected even while its packets are
being blocked.
