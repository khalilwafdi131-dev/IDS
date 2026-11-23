"""Generate a reproducible sample dataset with normal and suspicious activity.

Run:  python generate_sample_data.py
Output: data/network_events.csv
"""
import random
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

DEFAULT_PATH = Path(__file__).parent / "data" / "network_events.csv"


def generate(seed: int = 42, path=DEFAULT_PATH) -> pd.DataFrame:
    rng = random.Random(seed)
    start = datetime(2026, 10, 21, 9, 0, 0)
    rows = []

    def add(t, src, dst, proto, port, etype, label):
        rows.append({
            "timestamp": t.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src, "dst_ip": dst, "protocol": proto,
            "dst_port": port, "event_type": etype, "label": label,
        })

    internal = [f"192.168.1.{i}" for i in range(10, 40)]
    servers = ["192.168.1.200", "192.168.1.201", "192.168.1.202"]
    common_ports = [22, 80, 443, 3306, 8080, 53]

    # --- Normal traffic (2 hours) ---
    for _ in range(1500):
        t = start + timedelta(seconds=rng.randint(0, 7200))
        etype = rng.choices(["connection", "login_success", "login_failed"],
                            weights=[80, 17, 3])[0]
        port = rng.choice(common_ports) if etype == "connection" else rng.choice([22, 443, 3306])
        add(t, rng.choice(internal), rng.choice(servers), "TCP", port, etype, "normal")

    # --- Attack 1: brute force, High (12 failed logins in ~40 s) ---
    t0 = start + timedelta(minutes=20)
    for k in range(12):
        add(t0 + timedelta(seconds=k * 3.5), "203.0.113.50", "192.168.1.200",
            "TCP", 22, "login_failed", "brute_force")

    # --- Attack 2: brute force, Medium (6 failed logins in ~50 s) ---
    t0 = start + timedelta(minutes=55)
    for k in range(6):
        add(t0 + timedelta(seconds=k * 9), "198.51.100.23", "192.168.1.201",
            "TCP", 3306, "login_failed", "brute_force")

    # --- Attack 3: port scan, High (25 ports in ~20 s) ---
    t0 = start + timedelta(minutes=40)
    for k, port in enumerate(range(20, 45)):
        add(t0 + timedelta(seconds=k * 0.8), "203.0.113.77", "192.168.1.201",
            "TCP", port, "connection", "port_scan")

    # --- Attack 4: port scan, Medium (12 ports in ~25 s) ---
    t0 = start + timedelta(minutes=75)
    for k, port in enumerate([21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389]):
        add(t0 + timedelta(seconds=k * 2), "198.51.100.99", "192.168.1.202",
            "TCP", port, "connection", "port_scan")

    # --- Attack 5: connection flood, Medium (80 connections in ~8 s) ---
    t0 = start + timedelta(minutes=95)
    for k in range(80):
        add(t0 + timedelta(seconds=k * 0.1), "203.0.113.200", "192.168.1.200",
            "TCP", 80, "connection", "conn_flood")

    # --- Borderline but NORMAL: should not raise alerts ---
    t0 = start + timedelta(minutes=30)       # user mistyped a password 3 times
    for k in range(3):
        add(t0 + timedelta(seconds=k * 10), "192.168.1.15", "192.168.1.200",
            "TCP", 22, "login_failed", "normal")
    t0 = start + timedelta(minutes=62)       # admin checks a few services
    for k, port in enumerate([22, 80, 443, 3306, 8080, 53]):
        add(t0 + timedelta(seconds=k * 5), "192.168.1.22", "192.168.1.201",
            "TCP", port, "connection", "normal")

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)
    return df


if __name__ == "__main__":
    out = generate()
    print(f"Wrote {len(out)} events to {DEFAULT_PATH}")
