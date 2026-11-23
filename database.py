"""Member 2 - Database Design & Integration (SQLite).

Other modules only call the functions here; they never write SQL themselves.
Use ":memory:" for a throw-away database or a file path such as "data/ids.db".
"""
import sqlite3
from pathlib import Path

import pandas as pd

SCHEMA_PATH = Path(__file__).parent / "schema.sql"
TIME_FMT = "%Y-%m-%d %H:%M:%S"


def connect(path=":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn, reset: bool = True) -> None:
    if reset:
        conn.executescript(
            "DROP TABLE IF EXISTS alerts;"
            "DROP TABLE IF EXISTS network_events;"
            "DROP TABLE IF EXISTS detection_rules;"
        )
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.commit()


def seed_rules(conn, catalog) -> None:
    conn.executemany(
        "INSERT OR REPLACE INTO detection_rules (rule_name, description, threshold, window_seconds) "
        "VALUES (:rule_name, :description, :threshold, :window_seconds)",
        catalog,
    )
    conn.commit()


def insert_events(conn, df: pd.DataFrame) -> int:
    rows = [
        (ts.strftime(TIME_FMT), r.src_ip, r.dst_ip, r.protocol, int(r.dst_port),
         r.event_type, None if pd.isna(r.label) else str(r.label))
        for r in df.itertuples(index=False)
        for ts in [r.timestamp]
    ]
    conn.executemany(
        "INSERT INTO network_events (timestamp, src_ip, dst_ip, protocol, dst_port, event_type, label) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
    conn.commit()
    return len(rows)


def get_rule_id(conn, rule_name: str) -> int:
    row = conn.execute("SELECT rule_id FROM detection_rules WHERE rule_name = ?",
                       (rule_name,)).fetchone()
    if row is None:
        raise KeyError(f"Unknown rule: {rule_name}")
    return row[0]


def insert_alert(conn, alert: dict) -> int:
    cur = conn.execute(
        "INSERT INTO alerts (rule_id, src_ip, dst_ip, first_seen, last_seen, event_count, severity, description) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (get_rule_id(conn, alert["rule_name"]), alert["src_ip"], alert["dst_ip"],
         pd.Timestamp(alert["first_seen"]).strftime(TIME_FMT),
         pd.Timestamp(alert["last_seen"]).strftime(TIME_FMT),
         int(alert["event_count"]), alert["severity"], alert["description"]),
    )
    conn.commit()
    return cur.lastrowid


def fetch_events(conn) -> pd.DataFrame:
    df = pd.read_sql_query("SELECT * FROM network_events ORDER BY timestamp", conn)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def fetch_alerts(conn) -> pd.DataFrame:
    df = pd.read_sql_query(
        "SELECT a.alert_id, r.rule_name, a.src_ip, a.dst_ip, a.first_seen, a.last_seen, "
        "       a.event_count, a.severity, a.description "
        "FROM alerts a JOIN detection_rules r ON r.rule_id = a.rule_id "
        "ORDER BY a.first_seen", conn)
    for col in ("first_seen", "last_seen"):
        df[col] = pd.to_datetime(df[col])
    return df


def alerts_by_severity(conn) -> pd.DataFrame:
    return pd.read_sql_query(
        "SELECT severity, COUNT(*) AS alerts FROM alerts GROUP BY severity", conn)


def alerts_by_rule(conn) -> pd.DataFrame:
    return pd.read_sql_query(
        "SELECT r.rule_name, COUNT(*) AS alerts FROM alerts a "
        "JOIN detection_rules r ON r.rule_id = a.rule_id GROUP BY r.rule_name", conn)
