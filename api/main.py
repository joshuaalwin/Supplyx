"""
MLPro REST API — query risk scores and reports for packages.
"""
import json
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import mlflow.xgboost
import psycopg2
import psycopg2.extras
import shap
import xgboost as xgb
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent / "dags"))
from extractors.code_features import extract_code_features
from extractors.metadata_features import extract_metadata_features
from extractors.text_features import extract_text_features

MLFLOW_URI = os.environ.get("MLFLOW_TRACKING_URI", "http://mlflow:5000")
MODEL_NAME = "malicious-package-detector"
MODEL_FILE = Path(__file__).parent / "model" / "champion.json"

FEATURES = [
    "entropy_max", "has_network_in_install", "has_credential_access",
    "has_obfuscated_code", "has_exec_eval", "install_script_lines",
    "dangerous_import_count", "has_os_targeting", "has_external_payload",
    "api_category_count", "typosquat_distance", "is_typosquat",
    "has_repo_link", "version_count", "version_jump_suspicious",
    "description_length", "readme_length",
]

DB = {
    "host":     os.environ.get("DB_HOST", "postgres"),
    "port":     int(os.environ.get("DB_PORT", "5432")),
    "dbname":   os.environ.get("DB_NAME", "packages"),
    "user":     os.environ.get("DB_USER", "appuser"),
    "password": os.environ.get("DB_PASS", "apppass"),
}

_model = None
_explainer = None


def _load_model():
    global _model, _explainer
    # Load from bundled file first (works out of the box after git clone)
    if MODEL_FILE.exists():
        from xgboost import XGBClassifier
        _model = XGBClassifier()
        _model.load_model(str(MODEL_FILE))
        print(f"[api] model loaded from {MODEL_FILE}")
    else:
        # Fall back to MLflow (after retraining a new champion)
        mlflow.set_tracking_uri(MLFLOW_URI)
        _model = mlflow.xgboost.load_model(f"models:/{MODEL_NAME}@champion")
        print("[api] model loaded from MLflow")
    _explainer = shap.TreeExplainer(_model)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        _load_model()
    except Exception as exc:
        print(f"[api] warning: could not load model at startup: {exc}")
    yield


app = FastAPI(title="MLPro", version="1.0.0", lifespan=lifespan)


def _conn():
    return psycopg2.connect(**DB)


def _risk_level(score: float) -> str:
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.3:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class ScoreRequest(BaseModel):
    registry: str
    name: str
    version: str


class ScoreResponse(BaseModel):
    registry: str
    name: str
    version: str
    score: float
    risk_level: str
    report_md: str
    model_version: Optional[str]
    cached: bool


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {"status": "ok", "model_loaded": _model is not None}


@app.get("/api/report/{registry}/{name}/{version}")
def get_report(registry: str, name: str, version: str):
    with _conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT s.score, s.risk_level, s.shap_values, s.report_md,
                       s.model_version, s.scored_at
                FROM packages p
                JOIN scores s ON s.package_id = p.id
                WHERE p.registry = %s AND p.name = %s AND p.version = %s
            """, (registry, name, version))
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="No score found for this package")
    return dict(row)


@app.post("/api/score", response_model=ScoreResponse)
def score_package(req: ScoreRequest):
    # Return cached score if available
    with _conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT s.score, s.risk_level, s.report_md, s.model_version
                FROM packages p
                JOIN scores s ON s.package_id = p.id
                WHERE p.registry=%s AND p.name=%s AND p.version=%s
            """, (req.registry, req.name, req.version))
            cached = cur.fetchone()

    if cached:
        return ScoreResponse(
            registry=req.registry, name=req.name, version=req.version,
            score=cached["score"], risk_level=cached["risk_level"],
            report_md=cached["report_md"], model_version=cached["model_version"],
            cached=True,
        )

    if _model is None:
        raise HTTPException(status_code=503, detail="Model not loaded yet")

    # Look up features from DB
    with _conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT
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
                WHERE p.registry=%s AND p.name=%s AND p.version=%s
            """, (req.registry, req.name, req.version))
            feat_row = cur.fetchone()

    if not feat_row:
        raise HTTPException(status_code=404,
                            detail="Package not in DB — trigger ingest first")

    import pandas as pd
    X = pd.DataFrame([dict(feat_row)])[FEATURES]
    score = float(_model.predict_proba(X)[0, 1])
    risk = _risk_level(score)

    shap_vals = _explainer.shap_values(X)[0]
    shap_dict = dict(zip(FEATURES, shap_vals.tolist()))

    top = sorted(shap_dict.items(), key=lambda x: abs(x[1]), reverse=True)[:5]
    report_lines = [
        f"# {req.registry}/{req.name}@{req.version}",
        f"",
        f"**Risk:** {risk.upper()}  |  **Score:** {score:.3f}",
        f"",
        f"## Top signals",
        f"",
    ]
    for feat, val in top:
        direction = "↑" if val > 0 else "↓"
        report_lines.append(f"- **{feat}**: {direction} ({val:+.3f})")
    report_md = "\n".join(report_lines)

    client = mlflow.tracking.MlflowClient()
    try:
        champion_mv = client.get_model_version_by_alias(MODEL_NAME, "champion")
        model_version = champion_mv.version
    except Exception:
        model_version = None

    # Persist the computed score so GET /api/report works subsequently
    with _conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id FROM packages WHERE registry=%s AND name=%s AND version=%s",
                        (req.registry, req.name, req.version))
            pkg = cur.fetchone()
        if pkg:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO scores (package_id, score, risk_level, shap_values, report_md, model_version)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (package_id) DO UPDATE SET
                        score=EXCLUDED.score, risk_level=EXCLUDED.risk_level,
                        shap_values=EXCLUDED.shap_values, report_md=EXCLUDED.report_md,
                        model_version=EXCLUDED.model_version, scored_at=NOW()
                """, (pkg["id"], score, risk, json.dumps(shap_dict), report_md, str(model_version)))
            conn.commit()

    return ScoreResponse(
        registry=req.registry, name=req.name, version=req.version,
        score=score, risk_level=risk, report_md=report_md,
        model_version=str(model_version), cached=False,
    )
