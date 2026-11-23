import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from data_processor import DataValidationError, clean_events  # noqa: E402
from detection_engine import DEFAULT_CONFIG, detect  # noqa: E402
from evaluation import evaluate  # noqa: E402
from generate_sample_data import generate  # noqa: E402
from pipeline import run_pipeline  # noqa: E402


def make_events(rows):
    df = pd.DataFrame(rows, columns=["timestamp", "src_ip", "dst_ip", "protocol", "dst_port", "event_type"])
    df["label"] = None
    clean, _ = clean_events(df)
    return clean


def failed_logins(n, spacing, src="10.0.0.9"):
    return [(pd.Timestamp("2026-10-21 10:00:00") + pd.Timedelta(seconds=i * spacing),
             src, "10.0.0.1", "TCP", 22, "login_failed") for i in range(n)]


def test_brute_force_detected():
    alerts = detect(make_events(failed_logins(8, 2)))
    assert len(alerts) == 1 and alerts[0]["rule_name"] == "Repeated Failed Logins"


def test_few_failed_logins_not_detected():
    assert detect(make_events(failed_logins(4, 2))) == []


def test_slow_failed_logins_not_detected():
    # 8 attempts but 30 s apart: never 5 inside one 60 s window
    assert detect(make_events(failed_logins(8, 30))) == []


def test_port_scan_detected():
    rows = [(pd.Timestamp("2026-10-21 10:00:00") + pd.Timedelta(seconds=i),
             "10.0.0.9", "10.0.0.1", "TCP", 1000 + i, "connection") for i in range(12)]
    alerts = detect(make_events(rows))
    assert [a["rule_name"] for a in alerts] == ["Port Scanning"]


def test_repeated_same_port_is_not_port_scan():
    rows = [(pd.Timestamp("2026-10-21 10:00:00") + pd.Timedelta(seconds=i * 0.1),
             "10.0.0.9", "10.0.0.1", "TCP", 80, "connection") for i in range(20)]
    assert detect(make_events(rows)) == []


def test_one_burst_gives_one_alert():
    assert len(detect(make_events(failed_logins(20, 1)))) == 1


def test_validation_rejects_missing_columns():
    with pytest.raises(DataValidationError):
        clean_events(pd.DataFrame({"timestamp": ["2026-10-21 10:00:00"]}))


def test_validation_drops_bad_rows():
    df = pd.DataFrame({
        "timestamp": ["2026-10-21 10:00:00", "not a date", "2026-10-21 10:00:01"],
        "src_ip": ["10.0.0.1", "10.0.0.1", "999.1.1.1"],
        "dst_ip": ["10.0.0.2"] * 3, "protocol": ["tcp"] * 3,
        "dst_port": [80, 80, 80], "event_type": ["connection"] * 3})
    clean, report = clean_events(df)
    assert len(clean) == 1 and report["rows_dropped"] == 2


def test_sample_dataset_end_to_end(tmp_path):
    events = generate(path=tmp_path / "sample.csv")
    clean, _ = clean_events(events)
    res = run_pipeline(clean)
    assert len(res["alerts"]) == 5
    m = res["metrics"]
    assert m["precision"] == 1.0 and m["recall"] == 1.0 and m["fpr"] == 0.0


def test_stricter_threshold_lowers_recall(tmp_path):
    events = generate(path=tmp_path / "sample.csv")
    clean, _ = clean_events(events)
    res = run_pipeline(clean, {"failed_login_threshold": 50, "port_scan_threshold": 50,
                               "conn_rate_threshold": 500})
    assert res["metrics"]["recall"] < 1.0
