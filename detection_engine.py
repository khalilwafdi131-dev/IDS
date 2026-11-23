"""Member 3 - Detection Engine (rule-based, no machine learning).

Each rule looks for a burst of activity inside a sliding time window.
Once a burst raises an alert, the engine skips past it so one attack does not
produce a stream of duplicate alerts.
"""
import numpy as np
import pandas as pd

RULE_FAILED_LOGIN = "Repeated Failed Logins"
RULE_PORT_SCAN = "Port Scanning"
RULE_CONN_RATE = "Suspicious Connection Rate"

DEFAULT_CONFIG = {
    "failed_login_threshold": 5,   # failed logins ...
    "failed_login_window": 60,     # ... within this many seconds
    "port_scan_threshold": 10,     # distinct destination ports ...
    "port_scan_window": 30,        # ... within this many seconds
    "conn_rate_threshold": 50,     # connections ...
    "conn_rate_window": 10,        # ... within this many seconds
}


def rule_catalog(cfg):
    """Rule metadata, saved into the detection_rules table."""
    return [
        {"rule_name": RULE_FAILED_LOGIN,
         "description": "Many failed logins from one source to one target in a short time.",
         "threshold": cfg["failed_login_threshold"], "window_seconds": cfg["failed_login_window"]},
        {"rule_name": RULE_PORT_SCAN,
         "description": "One source probes many different ports in a short time.",
         "threshold": cfg["port_scan_threshold"], "window_seconds": cfg["port_scan_window"]},
        {"rule_name": RULE_CONN_RATE,
         "description": "One source opens an unusually high number of connections in a short time.",
         "threshold": cfg["conn_rate_threshold"], "window_seconds": cfg["conn_rate_window"]},
    ]


def _bursts(times, values, window, threshold, distinct):
    """Find non-overlapping bursts. Returns a list of (start, end, count)."""
    found, i, n = [], 0, len(times)
    while i < n:
        j = int(np.searchsorted(times, times[i] + window, side="right")) - 1
        chunk = values[i:j + 1]
        count = len(set(chunk)) if distinct else len(chunk)
        if count >= threshold:
            found.append((i, j, count))
            i = j + 1
        else:
            i += 1
    return found


def _seconds(series: pd.Series) -> np.ndarray:
    return (series - pd.Timestamp("1970-01-01")).dt.total_seconds().to_numpy()


def _failed_logins(df, cfg):
    alerts = []
    sub = df[df["event_type"] == "login_failed"]
    for (src, dst), g in sub.groupby(["src_ip", "dst_ip"]):
        g = g.sort_values("timestamp")
        for s, e, count in _bursts(_seconds(g["timestamp"]), g["dst_port"].tolist(),
                                   cfg["failed_login_window"], cfg["failed_login_threshold"], False):
            rows = g.iloc[s:e + 1]
            alerts.append({
                "rule_name": RULE_FAILED_LOGIN, "src_ip": src, "dst_ip": dst,
                "first_seen": rows["timestamp"].iloc[0], "last_seen": rows["timestamp"].iloc[-1],
                "event_count": count,
                "severity": "High" if count >= 2 * cfg["failed_login_threshold"] else "Medium",
                "description": (f"{count} failed login attempts from {src} to {dst} within "
                                f"{cfg['failed_login_window']}s (threshold: {cfg['failed_login_threshold']})."),
            })
    return alerts


def _port_scans(df, cfg):
    alerts = []
    for src, g in df.groupby("src_ip"):
        g = g.sort_values("timestamp")
        for s, e, count in _bursts(_seconds(g["timestamp"]), g["dst_port"].tolist(),
                                   cfg["port_scan_window"], cfg["port_scan_threshold"], True):
            rows = g.iloc[s:e + 1]
            targets = rows["dst_ip"].unique()
            dst = targets[0] if len(targets) == 1 else f"multiple ({len(targets)} hosts)"
            alerts.append({
                "rule_name": RULE_PORT_SCAN, "src_ip": src, "dst_ip": dst,
                "first_seen": rows["timestamp"].iloc[0], "last_seen": rows["timestamp"].iloc[-1],
                "event_count": len(rows),
                "severity": "High" if count >= 2 * cfg["port_scan_threshold"] else "Medium",
                "description": (f"{src} probed {count} distinct ports on {dst} within "
                                f"{cfg['port_scan_window']}s (threshold: {cfg['port_scan_threshold']})."),
            })
    return alerts


def _connection_rate(df, cfg):
    alerts = []
    sub = df[df["event_type"] == "connection"]
    for src, g in sub.groupby("src_ip"):
        g = g.sort_values("timestamp")
        for s, e, count in _bursts(_seconds(g["timestamp"]), g["dst_port"].tolist(),
                                   cfg["conn_rate_window"], cfg["conn_rate_threshold"], False):
            rows = g.iloc[s:e + 1]
            targets = rows["dst_ip"].unique()
            dst = targets[0] if len(targets) == 1 else f"multiple ({len(targets)} hosts)"
            alerts.append({
                "rule_name": RULE_CONN_RATE, "src_ip": src, "dst_ip": dst,
                "first_seen": rows["timestamp"].iloc[0], "last_seen": rows["timestamp"].iloc[-1],
                "event_count": count,
                "severity": "High" if count >= 2 * cfg["conn_rate_threshold"] else "Medium",
                "description": (f"{src} opened {count} connections to {dst} within "
                                f"{cfg['conn_rate_window']}s (threshold: {cfg['conn_rate_threshold']})."),
            })
    return alerts


def detect(df: pd.DataFrame, cfg=None):
    """Run all rules on a clean events DataFrame and return a list of alert dicts."""
    cfg = {**DEFAULT_CONFIG, **(cfg or {})}
    alerts = _failed_logins(df, cfg) + _port_scans(df, cfg) + _connection_rate(df, cfg)
    return sorted(alerts, key=lambda a: a["first_seen"])
