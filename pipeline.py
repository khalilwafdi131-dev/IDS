"""Glue code: events -> database -> detection -> alerts -> results."""
import alert_manager
import database
import detection_engine
import evaluation


def run_pipeline(events_df, cfg=None, db_path=":memory:"):
    cfg = {**detection_engine.DEFAULT_CONFIG, **(cfg or {})}
    conn = database.connect(db_path)
    try:
        database.init_db(conn, reset=True)
        database.seed_rules(conn, detection_engine.rule_catalog(cfg))
        database.insert_events(conn, events_df)

        alerts = detection_engine.detect(database.fetch_events(conn), cfg)
        alert_manager.save_alerts(conn, alerts)

        events = database.fetch_events(conn)
        saved_alerts = database.fetch_alerts(conn)
        result = {
            "events": events,
            "alerts": saved_alerts,
            "by_severity": database.alerts_by_severity(conn),
            "by_rule": database.alerts_by_rule(conn),
            "metrics": None,
            "per_attack": None,
        }
        if evaluation.has_labels(events):
            result["metrics"] = evaluation.evaluate(events, saved_alerts)
            result["per_attack"] = evaluation.per_attack_table(events, saved_alerts)
        return result
    finally:
        conn.close()
