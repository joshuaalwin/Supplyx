#!/usr/bin/env python3
"""
Evaluate the champion model on the full labeled dataset.

Produces every figure / number needed for the slide deck:
  eval/metrics.json
  eval/classification_report.txt
  eval/confusion_matrix.png
  eval/roc_curve.png
  eval/pr_curve.png
  eval/shap_summary_bar.png
  eval/shap_summary_beeswarm.png
  eval/feature_distribution.png   (benign-vs-malicious for each feature)

Usage (from repo root, venv active):
    MLFLOW_TRACKING_URI=http://localhost:5000 \
    MLFLOW_S3_ENDPOINT_URL=http://localhost:9000 \
    AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
    DB_HOST=localhost DB_PORT=15432 DB_NAME=packages DB_USER=appuser DB_PASS=apppass \
    .venv/bin/python scripts/eval_model.py
"""
import json
import os
import sys
from pathlib import Path

# Sensible host-side defaults — override by exporting before running.
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_PORT", "15432")
os.environ.setdefault("DB_NAME", "packages")
os.environ.setdefault("DB_USER", "appuser")
os.environ.setdefault("DB_PASS", "apppass")
os.environ.setdefault("MLFLOW_TRACKING_URI", "http://localhost:5000")
os.environ.setdefault("MLFLOW_S3_ENDPOINT_URL", "http://localhost:9000")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "minioadmin")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "minioadmin")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import mlflow
import mlflow.xgboost
import numpy as np
import pandas as pd
import shap
from sklearn.metrics import (classification_report, confusion_matrix,
                             f1_score, precision_recall_curve,
                             precision_score, recall_score, roc_auc_score,
                             roc_curve)
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dags"))
from storage.db import get_conn

ROOT = Path(__file__).parent.parent
EVAL_DIR = ROOT / "eval"
EVAL_DIR.mkdir(exist_ok=True)

MLFLOW_URI = os.environ.get("MLFLOW_TRACKING_URI", "http://localhost:5000")
MODEL_NAME = "malicious-package-detector"

FEATURES = [
    "entropy_max", "has_network_in_install", "has_credential_access",
    "has_obfuscated_code", "has_exec_eval", "install_script_lines",
    "dangerous_import_count", "has_os_targeting", "has_external_payload",
    "api_category_count", "typosquat_distance", "is_typosquat",
    "version_jump_suspicious",
]


def load_labeled_data() -> pd.DataFrame:
    sql = """
        SELECT
            p.name, p.registry, p.label,
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
            COALESCE(f.version_jump_suspicious::int, 0)             AS version_jump_suspicious
        FROM packages p
        JOIN features f ON f.package_id = p.id
        WHERE p.label IS NOT NULL
    """
    with get_conn() as conn:
        return pd.read_sql(sql, conn)


def plot_confusion_matrix(y, y_pred, out: Path) -> dict:
    cm = confusion_matrix(y, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["Pred Benign", "Pred Malicious"])
    ax.set_yticklabels(["True Benign", "True Malicious"])
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black",
                    fontsize=14)
    ax.set_title("Confusion Matrix — v7-Robust")
    plt.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}


def plot_roc_pr(y, y_prob, roc_out: Path, pr_out: Path) -> tuple[float, float]:
    fpr, tpr, _ = roc_curve(y, y_prob)
    auc = roc_auc_score(y, y_prob)
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.plot(fpr, tpr, color="crimson", linewidth=2, label=f"AUC = {auc:.3f}")
    ax.plot([0, 1], [0, 1], "--", color="gray", linewidth=1)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve — v7-Robust")
    ax.legend(loc="lower right")
    plt.tight_layout()
    fig.savefig(roc_out, dpi=150)
    plt.close(fig)

    prec, rec, _ = precision_recall_curve(y, y_prob)
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.plot(rec, prec, color="navy", linewidth=2)
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall Curve — v7-Robust")
    plt.tight_layout()
    fig.savefig(pr_out, dpi=150)
    plt.close(fig)
    return auc, float(np.trapezoid(prec, rec))


def plot_shap(model, X_sample: pd.DataFrame, bar_out: Path, beeswarm_out: Path):
    explainer = shap.TreeExplainer(model)
    shap_vals = explainer.shap_values(X_sample)

    plt.figure(figsize=(8, 5))
    shap.summary_plot(shap_vals, X_sample, plot_type="bar", show=False)
    plt.title("Mean |SHAP| — Feature Importance")
    plt.tight_layout()
    plt.savefig(bar_out, dpi=150, bbox_inches="tight")
    plt.close()

    plt.figure(figsize=(8, 6))
    shap.summary_plot(shap_vals, X_sample, show=False)
    plt.title("SHAP Beeswarm")
    plt.tight_layout()
    plt.savefig(beeswarm_out, dpi=150, bbox_inches="tight")
    plt.close()

    return dict(zip(FEATURES, np.abs(shap_vals).mean(axis=0).tolist()))


def plot_feature_distributions(df: pd.DataFrame, out: Path):
    binary = [f for f in FEATURES if df[f].dropna().isin([0, 1]).all()]
    continuous = [f for f in FEATURES if f not in binary]
    fig, axes = plt.subplots(3, 5, figsize=(18, 10))
    for ax, feat in zip(axes.flat, FEATURES):
        ben = df[df.label == 0][feat]
        mal = df[df.label == 1][feat]
        if feat in binary:
            br = ben.mean()
            mr = mal.mean()
            ax.bar(["benign", "malicious"], [br, mr],
                   color=["steelblue", "crimson"])
            ax.set_ylim(0, 1)
            ax.set_title(f"{feat}\nben {br:.1%} | mal {mr:.1%}", fontsize=9)
        else:
            ax.hist([ben, mal], bins=30, label=["benign", "malicious"],
                    color=["steelblue", "crimson"], density=True)
            ax.set_title(f"{feat}\nμ_ben={ben.mean():.2f} μ_mal={mal.mean():.2f}", fontsize=9)
            ax.legend(fontsize=7)
    for ax in axes.flat[len(FEATURES):]:
        ax.axis("off")
    plt.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)


def main():
    mlflow.set_tracking_uri(MLFLOW_URI)
    print(f"[eval] loading champion model from {MLFLOW_URI}")
    model = mlflow.xgboost.load_model(f"models:/{MODEL_NAME}@champion")

    df = load_labeled_data()
    n_total = len(df)
    n_mal = int((df.label == 1).sum())
    n_ben = int((df.label == 0).sum())
    print(f"[eval] {n_total} labeled rows ({n_mal} malicious / {n_ben} benign)")

    X = df[FEATURES]
    y = df.label.values

    # Held-out test split mirroring the training script (random_state=42, 80/20, stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    metrics = {
        "f1":           float(f1_score(y_test, y_pred, zero_division=0)),
        "precision":    float(precision_score(y_test, y_pred, zero_division=0)),
        "recall":       float(recall_score(y_test, y_pred, zero_division=0)),
        "roc_auc":      float(roc_auc_score(y_test, y_prob)),
        "n_total":      n_total,
        "n_malicious":  n_mal,
        "n_benign":     n_ben,
        "n_test":       int(len(y_test)),
        "scale_pos_weight": round(n_ben / max(n_mal, 1), 4),
    }

    cm_counts = plot_confusion_matrix(y_test, y_pred, EVAL_DIR / "confusion_matrix.png")
    auc, ap = plot_roc_pr(y_test, y_prob, EVAL_DIR / "roc_curve.png", EVAL_DIR / "pr_curve.png")
    metrics["roc_auc_plot"] = float(auc)
    metrics["avg_precision"] = float(ap)
    metrics.update(cm_counts)

    # SHAP on a 1000-row sample for plot speed
    X_shap = X_test.sample(min(1000, len(X_test)), random_state=42)
    shap_importance = plot_shap(model, X_shap,
                                EVAL_DIR / "shap_summary_bar.png",
                                EVAL_DIR / "shap_summary_beeswarm.png")
    metrics["shap_importance"] = shap_importance

    plot_feature_distributions(df, EVAL_DIR / "feature_distribution.png")

    report = classification_report(y_test, y_pred, target_names=["benign", "malicious"], digits=4)
    (EVAL_DIR / "classification_report.txt").write_text(report)
    print(report)

    (EVAL_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"[eval] metrics → {EVAL_DIR/'metrics.json'}")
    print(f"[eval] figures → {EVAL_DIR}/")


if __name__ == "__main__":
    main()
