"""Member 3 - Alert Management: de-duplicate alerts and save them via database.py."""
import logging

import database

log = logging.getLogger(__name__)


def save_alerts(conn, alerts) -> int:
    """Save alerts, skipping exact duplicates and bad records. Returns number saved."""
    seen, saved = set(), 0
    for alert in alerts:
        key = (alert["rule_name"], alert["src_ip"], alert["dst_ip"], str(alert["first_seen"]))
        if key in seen:
            continue
        seen.add(key)
        try:
            database.insert_alert(conn, alert)
            saved += 1
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not save alert %s: %s", key, exc)
    return saved
