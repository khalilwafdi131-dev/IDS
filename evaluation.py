"""Member 4 - System Evaluation.

Evaluation is done per SOURCE IP, using the 'label' column as ground truth:
  * a source is malicious if any of its events has a label other than 'normal';
  * a source counts as detected if at least one alert names it.
Precision, Recall and False Positive Rate are computed from that.
"""
import pandas as pd


def has_labels(events: pd.DataFrame) -> bool:
    return "label" in events.columns and events["label"].notna().any()


def evaluate(events: pd.DataFrame, alerts: pd.DataFrame) -> dict:
    all_src = set(events["src_ip"])
    malicious = set(events.loc[events["label"].notna() & (events["label"] != "normal"), "src_ip"])
    normal = all_src - malicious
    detected = set(alerts["src_ip"]) if len(alerts) else set()

    tp, fn = len(malicious & detected), len(malicious - detected)
    fp, tn = len(normal & detected), len(normal - detected)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall, "fpr": fpr}


def per_attack_table(events: pd.DataFrame, alerts: pd.DataFrame) -> pd.DataFrame:
    rows = []
    attacks = events[events["label"].notna() & (events["label"] != "normal")]
    for label, g in attacks.groupby("label"):
        for src in sorted(g["src_ip"].unique()):
            fired = sorted(alerts.loc[alerts["src_ip"] == src, "rule_name"].unique()) if len(alerts) else []
            rows.append({"attack_type": label, "source_ip": src,
                         "detected": bool(fired), "rules_fired": ", ".join(fired) or "-"})
    return pd.DataFrame(rows)
