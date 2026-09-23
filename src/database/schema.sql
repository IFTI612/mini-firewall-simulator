-- ---------------------------------------------------------------
-- Mini Firewall Simulator - database schema (PostgreSQL)
-- ---------------------------------------------------------------
-- Run automatically on startup by db_manager.py.
-- Every statement is idempotent, so restarting never destroys data.

-- Every simulated packet that passed through the firewall
CREATE TABLE IF NOT EXISTS traffic_logs (
    id        BIGSERIAL PRIMARY KEY,
    ts        DOUBLE PRECISION NOT NULL,   -- unix timestamp (sorting / windows)
    ts_text   TEXT             NOT NULL,   -- readable timestamp
    src_ip    TEXT             NOT NULL,
    src_port  INTEGER          NOT NULL,
    dst_ip    TEXT             NOT NULL,
    dst_port  INTEGER          NOT NULL,
    protocol  TEXT             NOT NULL,
    kind      TEXT             NOT NULL,   -- NORMAL / AUTH / SCAN / FLOOD
    action    TEXT             NOT NULL,   -- ALLOW / BLOCK
    reason    TEXT,
    rule_id   INTEGER DEFAULT 0,
    size      INTEGER DEFAULT 0,
    flags     TEXT DEFAULT '',
    conn_state TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_traffic_ts     ON traffic_logs (ts);
CREATE INDEX IF NOT EXISTS idx_traffic_src    ON traffic_logs (src_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_action ON traffic_logs (action);

-- Firewall rule set
CREATE TABLE IF NOT EXISTS firewall_rules (
    id          SERIAL PRIMARY KEY,
    priority    INTEGER  NOT NULL DEFAULT 100,
    src_ip      TEXT     NOT NULL DEFAULT '*',
    dst_ip      TEXT     NOT NULL DEFAULT '*',
    src_port    TEXT     NOT NULL DEFAULT '*',
    dst_port    TEXT     NOT NULL DEFAULT '*',
    protocol    TEXT     NOT NULL DEFAULT '*',
    action      TEXT     NOT NULL DEFAULT 'BLOCK',
    -- kept as a small integer (not BOOLEAN) so the GUI can toggle it
    -- with a simple  SET enabled = 1 - enabled
    enabled     SMALLINT NOT NULL DEFAULT 1,
    description TEXT     DEFAULT '',
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_rules_priority ON firewall_rules (priority, id);

-- Alerts raised by the detection engine
CREATE TABLE IF NOT EXISTS security_alerts (
    id           BIGSERIAL PRIMARY KEY,
    ts           DOUBLE PRECISION NOT NULL,
    ts_text      TEXT             NOT NULL,
    attack_type  TEXT             NOT NULL,  -- PORT_SCAN / BRUTE_FORCE / TRAFFIC_FLOOD
    source_ip    TEXT             NOT NULL,
    severity     TEXT             NOT NULL DEFAULT 'HIGH',
    details      TEXT,
    auto_blocked SMALLINT         NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_alert_ts   ON security_alerts (ts);
CREATE INDEX IF NOT EXISTS idx_alert_type ON security_alerts (attack_type);

-- Blacklist / whitelist (one row per IP)
CREATE TABLE IF NOT EXISTS ip_lists (
    ip        TEXT PRIMARY KEY,
    list_type TEXT NOT NULL,                -- BLACKLIST / WHITELIST
    reason    TEXT DEFAULT '',
    added_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Simple key/value settings store
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
