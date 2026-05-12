#!/usr/bin/env python3
"""
Slide-10 demo — show v1's spurious-correlation vulnerability live.

Picks one malicious package, scores it with the v1 baseline (17 features),
then re-scores it after padding description_length from 0 → 120.
v1 should drop from "critical" → "low" purely from cosmetic metadata padding.

Then runs the same demo against v7-robust (15 features), which doesn't even
look at description_length, so the score should not move.

Usage (after retraining):
    DB_HOST=localhost DB_PORT=15432 ... .venv/bin/python scripts/demo_evasion.py
"""
import json
import os
import sys
from pathlib import Path

import pandas as pd
from xgboost import XGBClassifier

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dags"))
from storage.db import get_conn

ROOT = Path(__file__).parent.parent

V1_FEATURES = [
    "entropy_max", "has_network_in_install", "has_credential_access",
    "has_obfuscated_code", "has_exec_eval", "install_script_lines",
    "dangerous_import_count", "has_os_targeting", "has_external_payload",
    "api_category_count", "typosquat_distance", "is_typosquat",
    "has_repo_link", "version_count", "version_jump_suspicious",
    "description_length", "readme_length",
]
V7_FEATURES = [
    "entropy_max", "has_network_in_install", "has_credential_access",
    "has_obfuscated_code", "has_exec_eval", "install_script_lines",
    "dangerous_import_count", "has_os_targeting", "has_external_payload",
    "api_category_count", "typosquat_distance", "is_typosquat",
    "version_jump_suspicious",
]


def pick_demo_package() -> dict:
    """Pick a malicious package with empty description/readme that v1 will flag highly."""
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
        WHERE p.label = 1 AND f.has_obfuscated_code = TRUE
          AND COALESCE(f.description_length, 0) <= 50
        ORDER BY p.id
        LIMIT 1
    """
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(sql)
        row = cur.fetchone()
        cols = [c.name for c in cur.description]
    if not row:
        raise RuntimeError("no suitable malicious package in DB")
    return dict(zip(cols, row))


def score(model: XGBClassifier, features_list: list[str], row: dict) -> float:
    X = pd.DataFrame([{f: row[f] for f in features_list}])
    return float(model.predict_proba(X)[0, 1])


def main():
    v1_path = ROOT / "model" / "champion-v1-baseline.json"
    v7_path = ROOT / "model" / "champion.json"

    if not v1_path.exists() or not v7_path.exists():
        sys.exit("missing v1 baseline or v7 champion — run training first")

    v1 = XGBClassifier(); v1.load_model(str(v1_path))
    v7 = XGBClassifier(); v7.load_model(str(v7_path))

    pkg = pick_demo_package()
    print(f"=== Demo package: {pkg['registry']}/{pkg['name']} ===")
    print(f"   Real features: obfuscated={bool(pkg['has_obfuscated_code'])}, "
          f"install_lines={pkg['install_script_lines']}, "
          f"dangerous_imports={pkg['dangerous_import_count']}")
    print(f"   Description length: {pkg['description_length']}")
    print(f"   Readme length:      {pkg['readme_length']}")
    print()

    # === v1 baseline (17 features) — VULNERABLE ===
    base_v1 = score(v1, V1_FEATURES, pkg)
    pkg_pad = {**pkg, "description_length": 120, "readme_length": 2000}
    pad_v1 = score(v1, V1_FEATURES, pkg_pad)

    print("=== v1 baseline (17 features) ===")
    print(f"   Original score:                {base_v1:.4f}  ({'CRITICAL' if base_v1>=0.8 else 'high' if base_v1>=0.6 else 'med' if base_v1>=0.3 else 'low'})")
    print(f"   After description=120/readme=2000: {pad_v1:.4f}  ({'critical' if pad_v1>=0.8 else 'high' if pad_v1>=0.6 else 'med' if pad_v1>=0.3 else 'LOW'})")
    print(f"   --> score moved by {(base_v1 - pad_v1):+.4f} (attacker padding ONLY)")
    print()

    # === v7-robust (15 features) — RESISTANT ===
    base_v7 = score(v7, V7_FEATURES, pkg)
    pad_v7 = score(v7, V7_FEATURES, pkg_pad)  # same row — v7 doesn't read description_length/readme_length anyway

    print("=== v7-Robust (15 features, monotonic) ===")
    print(f"   Original score:                {base_v7:.4f}  ({'critical' if base_v7>=0.8 else 'high' if base_v7>=0.6 else 'med' if base_v7>=0.3 else 'low'})")
    print(f"   After description=120/readme=2000: {pad_v7:.4f}  (text features not in model)")
    print(f"   --> score moved by {(base_v7 - pad_v7):+.4f}")
    print()

    print("TAKEAWAY:")
    print(f"   v1 lost {(base_v1 - pad_v1) * 100:+.1f} percentage points from metadata-only padding.")
    print(f"   v7 lost {(base_v7 - pad_v7) * 100:+.1f} percentage points — text features eliminated.")


if __name__ == "__main__":
    main()
