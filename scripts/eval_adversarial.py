#!/usr/bin/env python3
"""
Adversarial evaluation — v1 baseline (17 features) vs v7-Robust (15 features).

Demonstrates that the v1 model can be evaded by trivial text-feature perturbations
(set description_length / readme_length toward benign ranges) while v7-Robust
cannot, because those features were eliminated.

Outputs:
  eval/adversarial_results.json
  eval/evasion_rate_v1_vs_v7.png

Usage (from repo root, venv active):
    DB_HOST=localhost DB_PORT=15432 DB_NAME=packages DB_USER=appuser DB_PASS=apppass \
    .venv/bin/python scripts/eval_adversarial.py
"""
import json
import os
import sys
from copy import deepcopy
from pathlib import Path

# Sensible host-side defaults — override by exporting before running.
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_PORT", "15432")
os.environ.setdefault("DB_NAME", "packages")
os.environ.setdefault("DB_USER", "appuser")
os.environ.setdefault("DB_PASS", "apppass")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dags"))
from storage.db import get_conn

ROOT = Path(__file__).parent.parent
EVAL_DIR = ROOT / "eval"
EVAL_DIR.mkdir(exist_ok=True)
MODEL_DIR = ROOT / "model"

# v1 baseline used 17 features (the two extra are description_length / readme_length).
V1_FEATURES = [
    "entropy_max", "has_network_in_install", "has_credential_access",
    "has_obfuscated_code", "has_exec_eval", "install_script_lines",
    "dangerous_import_count", "has_os_targeting", "has_external_payload",
    "api_category_count", "typosquat_distance", "is_typosquat",
    "has_repo_link", "version_count", "version_jump_suspicious",
    "description_length", "readme_length",
]

# v7 dropped 4 features compared to v1: description_length, readme_length (text),
# has_repo_link, version_count (collection artifacts)
V7_FEATURES = [
    "entropy_max", "has_network_in_install", "has_credential_access",
    "has_obfuscated_code", "has_exec_eval", "install_script_lines",
    "dangerous_import_count", "has_os_targeting", "has_external_payload",
    "api_category_count", "typosquat_distance", "is_typosquat",
    "version_jump_suspicious",
]

# Two distinct attack classes — each tests a different threat-model assumption.
# Attack A: trivial text-feature padding — the original v1 vulnerability the slides claim
#           v7-Robust eliminates these features entirely; the attack should fail completely.
ATTACK_A_TEXT = [
    ("description_length", 120),   # short → "looks legitimate"
    ("readme_length", 2000),       # empty → "looks documented"
]

# Attack B: metadata-claim attack — attacker fakes a GitHub URL or claims a release history.
#           This is a NEW attack class made possible BECAUSE v7-Robust trusts metadata heavily
#           (monotonic c=-1 on has_repo_link, version_count). Honest finding: adversarial
#           hardening shifted the attack surface from text features to metadata features.
ATTACK_B_METADATA = [
    ("has_repo_link", 1),          # claim a repo URL in setup.py
    ("version_count", 8),          # claim a release history
    ("is_typosquat", 0),           # rename
    ("typosquat_distance", 5),     # rename further
]

# Combined view for the slide-10 chart that mirrors what the slides previously claimed.
PERTURBATIONS = ATTACK_A_TEXT + ATTACK_B_METADATA

LOW_RISK_THRESHOLD = 0.3  # score below this = classified low-risk by the platform


def load_test_pool(limit: int = 500) -> pd.DataFrame:
    """Sample malicious test packages that the model currently flags as risky."""
    sql = """
        SELECT
            p.name, p.registry,
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
        WHERE p.label = 1
        ORDER BY p.id
        LIMIT %s
    """
    with get_conn() as conn:
        return pd.read_sql(sql, conn, params=(limit,))


def load_model(path: Path) -> XGBClassifier:
    m = XGBClassifier()
    m.load_model(str(path))
    return m


def evaluate_evasion(model: XGBClassifier, df: pd.DataFrame, features: list[str],
                     perturbations: list[tuple[str, int]]) -> dict:
    """For each malicious sample, score it, then try each perturbation greedily.
    A sample is 'evaded' if any single perturbation drops the score below LOW_RISK_THRESHOLD."""
    X = df[features].copy()
    base_scores = model.predict_proba(X)[:, 1]

    flagged_idx = np.where(base_scores >= LOW_RISK_THRESHOLD)[0]
    n_flagged = len(flagged_idx)
    if n_flagged == 0:
        return {"flagged": 0, "evaded": 0, "rate": 0.0, "by_pert": {}}

    evaded_overall = np.zeros(n_flagged, dtype=bool)
    per_pert_evasions = {p[0]: 0 for p in perturbations}

    for feat, value in perturbations:
        if feat not in features:
            continue
        X_pert = X.iloc[flagged_idx].copy()
        X_pert[feat] = value
        new_scores = model.predict_proba(X_pert)[:, 1]
        evaded_now = new_scores < LOW_RISK_THRESHOLD
        per_pert_evasions[feat] = int(evaded_now.sum())
        evaded_overall = evaded_overall | evaded_now

    return {
        "flagged": int(n_flagged),
        "evaded": int(evaded_overall.sum()),
        "rate":   float(evaded_overall.mean()),
        "by_pert": per_pert_evasions,
    }


def _print_summary(label: str, results: dict) -> None:
    print(f"\n=== {label} ===")
    print(f"  flagged: {results['flagged']}")
    print(f"  evaded:  {results['evaded']}")
    print(f"  rate:    {results['rate']:.1%}")
    print(f"  by perturbation:")
    for k, v in results["by_pert"].items():
        print(f"    {k:25s} {v} of {results['flagged']}")


def main():
    v1_path = MODEL_DIR / "champion-v1-baseline.json"
    v7_path = MODEL_DIR / "champion.json"

    if not v1_path.exists():
        sys.exit(f"missing {v1_path} — run Phase B first")
    if not v7_path.exists():
        sys.exit(f"missing {v7_path} — run training (Phase E) first")

    v1 = load_model(v1_path)
    v7 = load_model(v7_path)
    df = load_test_pool(limit=500)
    print(f"[adv] sampling 500 malicious — got {len(df)} packages")

    # === Attack A: text-feature padding (slide-10 headline) ===
    print("\n" + "=" * 60)
    print("ATTACK A — Text-feature padding (description / readme)")
    print("=" * 60)
    v1_text = evaluate_evasion(v1, df, V1_FEATURES, ATTACK_A_TEXT)
    v7_text = evaluate_evasion(v7, df, V7_FEATURES, ATTACK_A_TEXT)
    _print_summary("v1 baseline — TEXT attack", v1_text)
    _print_summary("v7-robust — TEXT attack",   v7_text)

    # === Attack B: metadata-claim attack ===
    print("\n" + "=" * 60)
    print("ATTACK B — Metadata-claim attack (repo URL / versions)")
    print("=" * 60)
    v1_meta = evaluate_evasion(v1, df, V1_FEATURES, ATTACK_B_METADATA)
    v7_meta = evaluate_evasion(v7, df, V7_FEATURES, ATTACK_B_METADATA)
    _print_summary("v1 baseline — METADATA attack", v1_meta)
    _print_summary("v7-robust — METADATA attack",   v7_meta)

    # === Combined (kept for the original chart shape) ===
    v1_all = evaluate_evasion(v1, df, V1_FEATURES, PERTURBATIONS)
    v7_all = evaluate_evasion(v7, df, V7_FEATURES, PERTURBATIONS)

    out = {
        "threshold": LOW_RISK_THRESHOLD,
        "attack_a_text": {
            "perturbations":  ATTACK_A_TEXT,
            "v1_baseline":    v1_text,
            "v7_robust":      v7_text,
            "reduction_pct":  round((1 - v7_text["rate"] / max(v1_text["rate"], 1e-9)) * 100, 1),
        },
        "attack_b_metadata": {
            "perturbations":  ATTACK_B_METADATA,
            "v1_baseline":    v1_meta,
            "v7_robust":      v7_meta,
            "reduction_pct":  round((1 - v7_meta["rate"] / max(v1_meta["rate"], 1e-9)) * 100, 1),
        },
        "combined": {
            "v1_baseline":    v1_all,
            "v7_robust":      v7_all,
        },
    }
    (EVAL_DIR / "adversarial_results.json").write_text(json.dumps(out, indent=2, default=int))
    print(f"\n[adv] results → {EVAL_DIR/'adversarial_results.json'}")

    # Chart 1 — Text attack only (the slide-10 headline)
    fig, ax = plt.subplots(figsize=(7, 5))
    rates = [v1_text["rate"] * 100, v7_text["rate"] * 100]
    ax.bar(
        ["v1 baseline\n(17 features)", "v7-Robust\n(15 features)"],
        rates,
        color=["#c0392b", "#27ae60"],
    )
    for i, v in enumerate(rates):
        ax.text(i, v + 1, f"{v:.1f}%", ha="center", fontsize=12, fontweight="bold")
    ax.set_ylabel("Evasion rate (%)")
    ax.set_title(
        f"Text-Padding Attack (description_length, readme_length)\n"
        f"v1 evaded {v1_text['evaded']}/{v1_text['flagged']}  →  "
        f"v7 evaded {v7_text['evaded']}/{v7_text['flagged']}  "
        f"({out['attack_a_text']['reduction_pct']:.0f}% reduction)"
    )
    ax.set_ylim(0, max(105, max(rates) + 10))
    plt.tight_layout()
    fig.savefig(EVAL_DIR / "evasion_rate_v1_vs_v7.png", dpi=150)
    plt.close(fig)
    print(f"[adv] text-attack chart → eval/evasion_rate_v1_vs_v7.png")

    # Chart 2 — Side-by-side honest two-pane (both attack classes)
    fig, ax = plt.subplots(figsize=(9, 5))
    x = np.arange(2)
    width = 0.35
    ax.bar(x - width/2, [v1_text["rate"]*100, v1_meta["rate"]*100], width,
           label="v1 baseline (17 features)", color="#c0392b")
    ax.bar(x + width/2, [v7_text["rate"]*100, v7_meta["rate"]*100], width,
           label="v7-Robust (15 features + monotonic)", color="#27ae60")
    for i, (a, b) in enumerate([(v1_text["rate"], v7_text["rate"]),
                                 (v1_meta["rate"], v7_meta["rate"])]):
        ax.text(i - width/2, a*100 + 1, f"{a:.0%}", ha="center", fontsize=10)
        ax.text(i + width/2, b*100 + 1, f"{b:.0%}", ha="center", fontsize=10)
    ax.set_xticks(x)
    ax.set_xticklabels(["TEXT-PADDING\nattack", "METADATA-CLAIM\nattack"])
    ax.set_ylabel("Evasion rate (%)")
    ax.set_title("Adversarial Attack-Class Trade-off\nHardening shifts attack surface, doesn't eliminate it")
    ax.set_ylim(0, 110)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.08), ncol=2)
    plt.tight_layout()
    fig.savefig(EVAL_DIR / "attack_tradeoff.png", dpi=150)
    plt.close(fig)
    print(f"[adv] tradeoff chart  → eval/attack_tradeoff.png")


if __name__ == "__main__":
    main()
