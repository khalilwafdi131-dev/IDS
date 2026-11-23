"""Command-line run: python main.py  (also saves a real database file at data/ids.db)"""
from pathlib import Path

from data_processor import load_events
from generate_sample_data import generate
from pipeline import run_pipeline

DATA = Path(__file__).parent / "data" / "network_events.csv"
DB = Path(__file__).parent / "data" / "ids.db"

if __name__ == "__main__":
    if not DATA.exists():
        generate()
    events, report = load_events(DATA)
    print(f"Loaded {report['rows_out']} events ({report['rows_dropped']} dropped)")
    res = run_pipeline(events, db_path=str(DB))
    print(f"\n{len(res['alerts'])} alerts saved to {DB}\n")
    print(res["alerts"][["alert_id", "rule_name", "src_ip", "severity", "event_count"]].to_string(index=False))
    if res["metrics"]:
        m = res["metrics"]
        print(f"\nPrecision {m['precision']:.2f} | Recall {m['recall']:.2f} | FPR {m['fpr']:.2f}")
