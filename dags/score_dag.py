"""
Scoring DAG — runs every 30 min on newly extracted live packages.

Loads the Production model from MLflow, scores unscored packages,
computes SHAP values, builds a markdown report, writes to scores table.
"""
import json
import os
from datetime import datetime, timedelta

import mlflow.xgboost
import numpy as np
import pandas as pd
import psycopg2
import shap
from airflow import DAG
from airflow.operators.python import PythonOperator

from storage.db import get_conn

MLFLOW_URI = os.environ.get("MLFLOW_TRACKING_URI", "http://mlflow:5000")
MODEL_NAME = "malicious-package-detector"
BATCH = 100

FEATURES = [
    "entropy_max", "has_network_in_install", "has_credential_access",
    "has_obfuscated_code", "has_exec_eval", "install_script_lines",
    "dangerous_import_count", "has_os_targeting", "has_external_payload",
    "api_category_count", "typosquat_distance", "is_typosquat",
    "has_repo_link", "version_count", "version_jump_suspicious",
    "description_length", "readme_length",
]

FEATURE_LABELS = {
    "entropy_max":              "high-entropy strings (obfuscation)",
    "has_network_in_install":   "network call in install script",
    "has_credential_access":    "credential file access",
    "has_obfuscated_code":      "obfuscated/encoded code",
    "has_exec_eval":            "eval/exec on dynamic content",
    "install_script_lines":     "long install script",
    "dangerous_import_count":   "dangerous imports",
    "has_os_targeting":         "OS-specific targeting code",
    "has_external_payload":     "downloads+executes external payload",
    "api_category_count":       "multiple suspicious API categories",
    "typosquat_distance":       "typosquatting distance",
    "is_typosquat":             "typosquatting a popular package",
    "has_repo_link":            "missing repository link",
    "version_count":            "version count",
    "version_jump_suspicious":  "suspicious version jump",
    "description_length":       "description length",
    "readme_length":            "readme length",
}

default_args = {"owner": "mlpro", "retries": 1, "retry_delay": timedelta(minutes=5)}


def _risk_level(score: float) -> str:
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.3:
        return "medium"
    return "low"


def _build_report(name: str, version: str, registry: str,
                  score: float, risk: str, shap_dict: dict) -> str:
    top = sorted(shap_dict.items(), key=lambda x: abs(x[1]), reverse=True)[:5]
    lines = [
        f"# {registry}/{name}@{version}",
        f"",
        f"**Risk level:** {risk.upper()}  |  **Score:** {score:.3f}",
        f"",
        f"## Top signals",
        f"",
    ]
    for feat, val in top:
        direction = "↑ raises" if val > 0 else "↓ lowers"
        label = FEATURE_LABELS.get(feat, feat)
        lines.append(f"- **{label}** — {direction} risk (SHAP {val:+.3f})")
    lines += [
        f"",
        f"## Recommendation",
        f"",
    ]
    if risk == "critical":
        lines.append("Do **not** install. Strong malicious indicators present.")
    elif risk == "high":
        lines.append("Treat with caution. Manual review recommended before use.")
    elif risk == "medium":
        lines.append("Some suspicious signals. Review install scripts before using.")
    else:
        lines.append("No strong malicious indicators detected.")
    return "\n".join(lines)


def score_batch(**_) -> None:
    mlflow.set_tracking_uri(MLFLOW_URI)

    # Load champion model
    try:
        model = mlflow.xgboost.load_model(f"models:/{MODEL_NAME}@champion")
        client = mlflow.tracking.MlflowClient()
        champion_mv = client.get_model_version_by_alias(MODEL_NAME, "champion")
        model_version = champion_mv.version
    except Exception as exc:
        print(f"[score] no champion model available yet: {exc}")
        return

    # Fetch unscored packages
    sql = """
        SELECT
            p.id, p.name, p.version, p.registry,
            COALESCE(f.entropy_max, 0)                              AS entropy_max,
            COALESCE(f.has_network_in_install::int, 0)              AS has_network_in_install,
            COALESCE(f.has_credential_access::int, 0)               AS has_credential_access,
            COALESCE(f.has_obfuscated_code::int, 0)                 AS has_obfuscated_code,
            COALESCE(f.has_exec_eval::int, 0)                       AS has_exec_eval,
            COALESCE(f.install_script_lines, 0)                     AS install_script_lines,
            COALESCE(f.dangerous_import_count, 0)                   AS dangerous_import_count,
            COALESCE(f.has_os_targeting::int, 0)                    AS has_os_targeting,
            COALESCE(f.has_external_payload::int, 0)                AS has_external_payload,
            COALESCE(f.api_category_count, 0)                       AS api_category_count,
            COALESCE(f.typosquat_distance, 0)                       AS typosquat_distance,
            CASE WHEN f.typosquat_target IS NOT NULL THEN 1 ELSE 0 END AS is_typosquat,
            COALESCE(f.has_repo_link::int, 0)                       AS has_repo_link,
            COALESCE(f.version_count, 1)                            AS version_count,
            COALESCE(f.version_jump_suspicious::int, 0)             AS version_jump_suspicious,
            COALESCE(f.description_length, 0)                       AS description_length,
            COALESCE(f.readme_length, 0)                            AS readme_length
        FROM packages p
        JOIN features f ON f.package_id = p.id
        LEFT JOIN scores s ON s.package_id = p.id
        WHERE p.label IS NULL
          AND p.extraction_status = 'done'
          AND s.id IS NULL
        LIMIT %s
    """
    with get_conn() as conn:
        df = pd.read_sql(sql, conn, params=(BATCH,))

    if df.empty:
        print("[score] nothing to score")
        return

    X = df[FEATURES]
    scores = model.predict_proba(X)[:, 1]

    explainer = shap.TreeExplainer(model)
    shap_matrix = explainer.shap_values(X)

    rows_written = 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            for i, row in df.iterrows():
                score = float(scores[i - df.index[0]])
                risk = _risk_level(score)
                shap_dict = dict(zip(FEATURES, shap_matrix[i - df.index[0]].tolist()))
                report = _build_report(
                    row["name"], row["version"], row["registry"],
                    score, risk, shap_dict,
                )
                cur.execute("""
                    INSERT INTO scores
                        (package_id, score, risk_level, shap_values, report_md, model_version)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (package_id) DO UPDATE SET
                        score         = EXCLUDED.score,
                        risk_level    = EXCLUDED.risk_level,
                        shap_values   = EXCLUDED.shap_values,
                        report_md     = EXCLUDED.report_md,
                        model_version = EXCLUDED.model_version,
                        scored_at     = NOW()
                """, (
                    int(row["id"]), score, risk,
                    json.dumps(shap_dict), report, str(model_version),
                ))
                rows_written += 1
        conn.commit()

    print(f"[score] scored {rows_written} packages (model v{model_version})")


with DAG(
    dag_id="score_packages",
    default_args=default_args,
    description="Score newly extracted live packages using the Production model",
    schedule_interval="*/30 * * * *",
    start_date=datetime(2025, 1, 1),
    catchup=False,
    max_active_runs=1,
    tags=["ml", "scoring"],
) as dag:

    PythonOperator(task_id="score_batch", python_callable=score_batch)
