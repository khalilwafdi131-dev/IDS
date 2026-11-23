"""Member 1 - Data Collection & Preprocessing.

Reads a CSV of network events, validates it, and returns a clean DataFrame
in the unified event format used by the rest of the system.
"""
import ipaddress

import pandas as pd

REQUIRED_COLUMNS = ["timestamp", "src_ip", "dst_ip", "protocol", "dst_port", "event_type"]
ALLOWED_EVENT_TYPES = {"connection", "login_success", "login_failed"}


class DataValidationError(Exception):
    """Raised when the input file cannot be used at all."""


def _is_valid_ip(value) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def clean_events(df: pd.DataFrame):
    """Validate and clean a DataFrame. Returns (clean_df, report)."""
    df = df.copy()
    df.columns = [str(c).strip().lower() for c in df.columns]

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise DataValidationError(
            f"Missing required columns: {', '.join(missing)}. "
            f"Expected: {', '.join(REQUIRED_COLUMNS)} (optional: label)."
        )
    if "label" not in df.columns:
        df["label"] = None

    rows_in = len(df)
    reasons = {}

    def drop(mask, reason):
        nonlocal df
        n = int(mask.sum())
        if n:
            reasons[reason] = reasons.get(reason, 0) + n
            df = df[~mask]

    for col in ["src_ip", "dst_ip", "protocol", "event_type"]:
        df[col] = df[col].astype(str).str.strip()
    df["protocol"] = df["protocol"].str.upper()
    df["event_type"] = df["event_type"].str.lower()

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    drop(df["timestamp"].isna(), "invalid timestamp")

    for col in ["src_ip", "dst_ip"]:
        valid = {ip: _is_valid_ip(ip) for ip in df[col].unique()}
        drop(~df[col].map(valid), f"invalid {col}")

    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")
    drop(df["dst_port"].isna() | (df["dst_port"] < 0) | (df["dst_port"] > 65535),
         "invalid dst_port")
    df["dst_port"] = df["dst_port"].astype(int)

    drop(~df["event_type"].isin(ALLOWED_EVENT_TYPES), "unknown event_type")

    # Note: identical rows are kept on purpose. Repeated identical events in the
    # same second (e.g. a connection flood) are exactly what the rules look for.

    df = df.sort_values("timestamp").reset_index(drop=True)
    report = {"rows_in": rows_in, "rows_out": len(df),
              "rows_dropped": rows_in - len(df), "reasons": reasons}
    if df.empty:
        raise DataValidationError("No valid rows left after cleaning.")
    return df, report


def load_events(source):
    """Load events from a file path or file-like object (e.g. an upload)."""
    try:
        raw = pd.read_csv(source)
    except Exception as exc:  # noqa: BLE001
        raise DataValidationError(f"Could not read the CSV file: {exc}") from exc
    return clean_events(raw)
