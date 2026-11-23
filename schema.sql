-- IDS database schema (SQLite)

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name      TEXT    NOT NULL UNIQUE,
    description    TEXT    NOT NULL,
    threshold      INTEGER NOT NULL CHECK (threshold > 0),
    window_seconds INTEGER NOT NULL CHECK (window_seconds > 0)
);

CREATE TABLE IF NOT EXISTS network_events (
    event_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT    NOT NULL,            -- 'YYYY-MM-DD HH:MM:SS'
    src_ip     TEXT    NOT NULL,
    dst_ip     TEXT    NOT NULL,
    protocol   TEXT    NOT NULL,
    dst_port   INTEGER NOT NULL CHECK (dst_port BETWEEN 0 AND 65535),
    event_type TEXT    NOT NULL CHECK (event_type IN ('connection', 'login_success', 'login_failed')),
    label      TEXT                         -- optional ground truth, used only for evaluation
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     INTEGER NOT NULL,
    src_ip      TEXT    NOT NULL,
    dst_ip      TEXT    NOT NULL,
    first_seen  TEXT    NOT NULL,
    last_seen   TEXT    NOT NULL,
    event_count INTEGER NOT NULL CHECK (event_count > 0),
    severity    TEXT    NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    description TEXT    NOT NULL,
    FOREIGN KEY (rule_id) REFERENCES detection_rules (rule_id)
);

CREATE INDEX IF NOT EXISTS idx_events_src  ON network_events (src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_sev  ON alerts (severity);
