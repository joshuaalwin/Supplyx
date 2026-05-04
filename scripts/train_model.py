#!/usr/bin/env python3
"""
Standalone training script — same logic as train_dag.py but no Airflow dependency.
Run from ~/MLPro with the venv active:

    source .venv/bin/activate
    MLFLOW_TRACKING_URI=http://localhost:5000 \
    MLFLOW_S3_ENDPOINT_URL=http://localhost:9000 \
    AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
    python3 scripts/train_model.py
"""
import json
import os
import sys
import tempfile

import mlflow
import mlflow.xgboost
import numpy as np
import pandas as pd
import shap
from sklearn.metrics import (classification_report, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import StratifiedKFold, train_test_split
from xgboost import XGBClassifier

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dags"))
from storage.db import get_conn

MLFLOW_URI = os.environ.get("MLFLOW_TRACKING_URI", "http://localhost:5000")
MODEL_NAME = "malicious-package-detector"

FEATURES = [
    "entropy_max", "has_network_in_install", "has_credential_access",
    "has_obfuscated_code", "has_exec_eval", "install_script_lines",
    "dangerous_import_count", "has_os_targeting", "has_external_payload",
    "api_category_count", "typosquat_distance", "is_typosquat",
    "has_repo_link", "version_count", "version_jump_suspicious",
    "description_length", "readme_length",
]


def load_training_data():
    sql = """
        SELECT
            p.label,
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
        WHERE p.label IS NOT NULL
    """
    with get_conn() as conn:
        df = pd.read_sql(sql, conn)
    y = df.pop("label")
    return df[FEATURES], y


def train():
    mlflow.set_tracking_uri(MLFLOW_URI)
    mlflow.set_experiment("malicious-package-detection")

    X, y = load_training_data()
    n_total = len(X)
    n_mal = int(y.sum())
    n_ben = n_total - n_mal
    print(f"[train] dataset: {n_total} samples  malicious={n_mal}  benign={n_ben}")

    if n_total < 100:
        raise ValueError(f"Not enough labeled samples ({n_total}). Run build_dataset.py first.")

    scale_pos_weight = n_ben / max(n_mal, 1)

    def _make_model():
        return XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=scale_pos_weight,
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        )

    # 5-fold cross-validation for honest evaluation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    fold_f1, fold_precision, fold_recall, fold_auc = [], [], [], []
    for fold, (train_idx, val_idx) in enumerate(cv.split(X, y), 1):
        m = _make_model()
        m.fit(X.iloc[train_idx], y.iloc[train_idx], verbose=False)
        yp = m.predict(X.iloc[val_idx])
        yprob = m.predict_proba(X.iloc[val_idx])[:, 1]
        fold_f1.append(f1_score(y.iloc[val_idx], yp, zero_division=0))
        fold_precision.append(precision_score(y.iloc[val_idx], yp, zero_division=0))
        fold_recall.append(recall_score(y.iloc[val_idx], yp, zero_division=0))
        fold_auc.append(roc_auc_score(y.iloc[val_idx], yprob))
        print(f"[train] fold {fold}/5  f1={fold_f1[-1]:.4f}  auc={fold_auc[-1]:.4f}")

    # Final model trained on all data
    model = _make_model()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    with mlflow.start_run() as run:
        metrics = {
            "precision":      round(precision_score(y_test, y_pred, zero_division=0), 4),
            "recall":         round(recall_score(y_test, y_pred, zero_division=0), 4),
            "f1":             round(f1_score(y_test, y_pred, zero_division=0), 4),
            "roc_auc":        round(roc_auc_score(y_test, y_prob), 4),
            "cv_f1_mean":     round(float(np.mean(fold_f1)), 4),
            "cv_f1_std":      round(float(np.std(fold_f1)), 4),
            "cv_auc_mean":    round(float(np.mean(fold_auc)), 4),
            "cv_precision_mean": round(float(np.mean(fold_precision)), 4),
            "cv_recall_mean": round(float(np.mean(fold_recall)), 4),
            "n_train":        len(X_train),
            "n_test":         len(X_test),
            "n_malicious":    n_mal,
            "n_benign":       n_ben,
        }
        for i, f in enumerate(fold_f1, 1):
            metrics[f"cv_f1_fold_{i}"] = round(f, 4)

        mlflow.log_metrics(metrics)
        mlflow.log_params({
            "n_estimators":      300,
            "max_depth":         6,
            "learning_rate":     0.05,
            "scale_pos_weight":  round(scale_pos_weight, 4),
            "cv_folds":          5,
        })

        print(f"[train] CV F1: {metrics['cv_f1_mean']:.4f} ± {metrics['cv_f1_std']:.4f}")
        print(f"[train] final metrics: {metrics}")
        print(classification_report(y_test, y_pred, target_names=["benign", "malicious"]))

        # SHAP feature importance
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X_test)
        mean_abs_shap = dict(zip(FEATURES, np.abs(shap_values).mean(axis=0).tolist()))
        mlflow.log_dict(mean_abs_shap, "shap_feature_importance.json")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(classification_report(y_test, y_pred, target_names=["benign", "malicious"]))
            mlflow.log_artifact(f.name, "classification_report.txt")

        mlflow.xgboost.log_model(model, "model", registered_model_name=MODEL_NAME)

        client = mlflow.tracking.MlflowClient()
        versions = client.search_model_versions(f"name='{MODEL_NAME}'")
        latest = max(versions, key=lambda v: int(v.version))

        # Promote to champion alias if this run beats the current champion
        should_promote = True
        try:
            champion_mv = client.get_model_version_by_alias(MODEL_NAME, "champion")
            champion_run = client.get_run(champion_mv.run_id)
            champion_f1 = champion_run.data.metrics.get("f1", 0)
            should_promote = metrics["f1"] >= champion_f1
        except Exception:
            pass  # no champion yet

        if should_promote:
            client.set_registered_model_alias(MODEL_NAME, "champion", latest.version)
            print(f"[train] promoted version {latest.version} to champion (F1={metrics['f1']})")
        else:
            print(f"[train] version {latest.version} kept — did not beat champion F1")

        print(f"[train] MLflow run: {run.info.run_id}")


if __name__ == "__main__":
    train()
