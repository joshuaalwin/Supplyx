#!/usr/bin/env python3
"""
Publish eval/metrics.json + eval/adversarial_results.json into Postgres so the
Grafana ML dashboard can display them.

Run this after `scripts/eval_model.py` and `scripts/eval_adversarial.py`.

Idempotent — inserts a new row per run, keyed by MLflow model_version.
"""
import json
import os
import sys
from pathlib import Path

# Sensible host-side defaults
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_PORT", "15432")
os.environ.setdefault("DB_NAME", "packages")
os.environ.setdefault("DB_USER", "appuser")
os.environ.setdefault("DB_PASS", "apppass")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dags"))
from storage.db import get_conn

ROOT = Path(__file__).parent.parent
EVAL_DIR = ROOT / "eval"
MODEL_LABEL = "v7-robust"
MODEL_VERSION = os.environ.get("MODEL_VERSION", "3")


def publish_metrics():
    metrics_file = EVAL_DIR / "metrics.json"
    if not metrics_file.exists():
        print(f"[publish] {metrics_file} not found — skipping metrics")
        return False
    m = json.loads(metrics_file.read_text())

    row = {
        "model_version":   MODEL_VERSION,
        "model_label":     MODEL_LABEL,
        "f1":              m.get("f1"),
        "precision_score": m.get("precision"),
        "recall":          m.get("recall"),
        "roc_auc":         m.get("roc_auc"),
        "accuracy":        (m.get("tp", 0) + m.get("tn", 0)) / max(m.get("n_test", 1), 1),
        "tn":              m.get("tn"),
        "fp":              m.get("fp"),
        "fn":              m.get("fn"),
        "tp":              m.get("tp"),
        "n_total":         m.get("n_total"),
        "n_test":          m.get("n_test"),
        "n_malicious":     m.get("n_malicious"),
        "n_benign":        m.get("n_benign"),
        "scale_pos_weight": m.get("scale_pos_weight"),
        "n_features":      len(m.get("shap_importance", {})),
        "n_estimators":    400,
    }

    sql = """
        INSERT INTO model_metrics
            (model_version, model_label, f1, precision_score, recall, roc_auc, accuracy,
             tn, fp, fn, tp, n_total, n_test, n_malicious, n_benign,
             scale_pos_weight, n_features, n_estimators)
        VALUES
            (%(model_version)s, %(model_label)s, %(f1)s, %(precision_score)s, %(recall)s,
             %(roc_auc)s, %(accuracy)s, %(tn)s, %(fp)s, %(fn)s, %(tp)s,
             %(n_total)s, %(n_test)s, %(n_malicious)s, %(n_benign)s,
             %(scale_pos_weight)s, %(n_features)s, %(n_estimators)s)
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, row)
    print(f"[publish] model_metrics: f1={row['f1']:.4f} precision={row['precision_score']:.4f} "
          f"recall={row['recall']:.4f} roc_auc={row['roc_auc']:.4f}")

    # SHAP feature importance — wipe previous run for this version, then insert
    shap = m.get("shap_importance", {})
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM model_shap WHERE model_version = %s", (MODEL_VERSION,))
            for feat, imp in shap.items():
                cur.execute(
                    "INSERT INTO model_shap (model_version, feature_name, importance) VALUES (%s, %s, %s)",
                    (MODEL_VERSION, feat, float(imp)),
                )
    print(f"[publish] model_shap: {len(shap)} features")
    return True


def publish_adversarial():
    adv_file = EVAL_DIR / "adversarial_results.json"
    if not adv_file.exists():
        print(f"[publish] {adv_file} not found — skipping adversarial")
        return False
    a = json.loads(adv_file.read_text())

    with get_conn() as conn:
        with conn.cursor() as cur:
            # Wipe previous adversarial rows for this version
            cur.execute("DELETE FROM model_adversarial WHERE model_version = %s", (MODEL_VERSION,))
            for attack_key, attack_label in [
                ("attack_a_text",     "text_padding"),
                ("attack_b_metadata", "metadata_claim"),
            ]:
                if attack_key not in a:
                    continue
                for side, label in [("v1_baseline", "v1"), ("v7_robust", "v7")]:
                    r = a[attack_key].get(side, {})
                    cur.execute(
                        "INSERT INTO model_adversarial "
                        "(model_version, attack_class, model_label, flagged, evaded, rate) "
                        "VALUES (%s, %s, %s, %s, %s, %s)",
                        (MODEL_VERSION, attack_label, label,
                         r.get("flagged"), r.get("evaded"), r.get("rate")),
                    )
    print(f"[publish] model_adversarial: 4 rows (text x v1/v7 + metadata x v1/v7)")
    return True


def main():
    print(f"[publish] writing eval artifacts for model_version={MODEL_VERSION}")
    publish_metrics()
    publish_adversarial()
    print("[publish] done")


if __name__ == "__main__":
    main()
