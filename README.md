# IDS - Intrusion Detection System

Rule-based intrusion detection (no machine learning) with a SQLite database and a Streamlit dashboard.

## Project structure

| File | Owner | Purpose |
|------|-------|---------|
| `generate_sample_data.py`, `data_processor.py` | Member 1 - Data Collection & Preprocessing | Sample dataset, CSV validation and cleaning |
| `schema.sql`, `database.py` | Member 2 - Database Design & Integration | Tables, constraints, and Python functions for saving/reading data |
| `detection_engine.py`, `alert_manager.py` | Member 3 - Detection Engine & Alert Management | Detection rules, severity, de-duplication, saving alerts |
| `app.py`, `evaluation.py`, `tests/` | Member 4 - Dashboard & System Evaluation | Streamlit dashboard, Precision/Recall/FPR, test cases |
| `pipeline.py`, `main.py` | Shared | Connects all parts; command-line run |

Data flow: CSV -> `data_processor` -> `database` -> `detection_engine` -> `alert_manager` -> `database` -> `app`

## Run locally

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows   (Mac/Linux: source .venv/bin/activate)
pip install -r requirements.txt
streamlit run app.py
```

The browser opens at http://localhost:8501.

Other commands:

```bash
python main.py            # command-line run, also writes data/ids.db
python -m pytest -q tests # run the tests
python generate_sample_data.py   # regenerate data/network_events.csv
```

## CSV format

Required columns: `timestamp, src_ip, dst_ip, protocol, dst_port, event_type`
`event_type` must be `connection`, `login_success`, or `login_failed`.
Optional column: `label` (`normal` or an attack name). When present, the Evaluation tab is enabled.

## Detection rules (default thresholds, adjustable in the dashboard sidebar)

1. **Repeated Failed Logins** - 5+ failed logins from one source to one target within 60 s
2. **Port Scanning** - 10+ distinct destination ports from one source within 30 s
3. **Suspicious Connection Rate** - 50+ connections from one source within 10 s

Severity is High when the count reaches twice the threshold, otherwise Medium.

## Deploy on Streamlit Community Cloud

Push this folder to GitHub, then create the app at https://share.streamlit.io with `app.py` as the main file.
The app builds its SQLite database in memory at startup, so no external database is needed.
