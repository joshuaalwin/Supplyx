# MLPro — ML-Powered Malicious Package Detection

Detects malicious npm and PyPI packages using XGBoost trained on 13 static signals (10 code-behaviour + 3 metadata). Every prediction includes a SHAP explanation of which signals drove the score.

**The pre-trained model is included — no training required to get started.**

---

## Quickstart

**Requirements:** Docker, Docker Compose, Git

### 1. Clone the repo

```bash
git clone https://github.com/Elnimo-00/MLPro.git
cd MLPro
cp .env.example .env
```

### 2. Start Postgres + MinIO

```bash
docker compose up -d postgres minio minio-init
# Wait until Postgres is healthy (~20 sec)
docker compose ps postgres
```

### 3. Start MLflow

```bash
docker compose up -d mlflow
# Wait until healthy (~15 sec)
docker compose ps mlflow
```

### 4. Initialise Airflow

```bash
docker compose up -d airflow-init
# Wait for the init container to exit (status "Exited 0")
docker compose ps airflow-init
```

### 5. Start Airflow + Grafana

```bash
docker compose up -d airflow-webserver airflow-scheduler grafana
```

### 6. Start the API

```bash
docker compose up -d api
# Wait until the API logs "startup complete"
docker compose logs -f api
```

### 7. Verify everything is running

```bash
curl http://localhost:8000/api/health
# → {"status":"ok","model_loaded":true}
```

| Service | URL | Credentials |
|---|---|---|
| REST API | http://localhost:8000 | — |
| API docs | http://localhost:8000/docs | — |
| Airflow | http://localhost:8080 | admin / admin |
| MLflow | http://localhost:5000 | — |
| Grafana | http://localhost:3000 | admin / admin |
| MinIO | http://localhost:9001 | minioadmin / minioadmin |
| Postgres | localhost:15432 | appuser / apppass (db: packages) |

---

## Scoring a Package

The API can score any package that is already in the database. Airflow's `ingest_dag` polls PyPI and npm every 15 minutes and ingests new packages automatically. You can also trigger it manually from the Airflow UI.

```bash
curl -X POST http://localhost:8000/api/score \
  -H "Content-Type: application/json" \
  -d '{"registry":"npm","name":"000webhost-admin","version":"0.0.1-security"}'
```

```json
{
  "score": 0.723,
  "risk_level": "high",
  "report_md": "## Top signals\n- entropy_max ↑ raises risk (+1.254)\n- has_exec_eval ↑ raises risk (+0.665)...",
  "model_version": "1",
  "cached": false
}
```

Risk levels: `low` (< 0.3) · `medium` (0.3–0.6) · `high` (0.6–0.8) · `critical` (≥ 0.8)

Fetch a saved report:
```bash
curl http://localhost:8000/api/report/npm/000webhost-admin/0.0.1-security
```

---

## The Dataset

The model was trained on two publicly available datasets:

| Class | Source | Count |
|---|---|---|
| malicious | [pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) — verified malicious packages removed from PyPI (ASE 2023 paper) | ~10,968 |
| malicious | DataDog malware dataset | ~9,874 |
| benign | Top 2,000 PyPI packages by downloads | ~1,887 |
| benign | Top 100 npm packages by downloads | 105 |

The dataset is **not included in this repo** (1.2 GB). To build it yourself:

```bash
# Set up a Python virtual environment on the host
python3 -m venv .venv
source .venv/bin/activate
pip install requests psycopg2-binary mlflow xgboost scikit-learn shap pandas numpy boto3

# The stack must already be running (Postgres must be up)
# Build the dataset — takes 30–60 min
DB_HOST=localhost DB_PORT=15432 DB_NAME=packages DB_USER=appuser DB_PASS=apppass \
python3 scripts/build_dataset.py
```

This clones `pypi_malregistry`, downloads the top PyPI/npm packages, extracts all 15 model features (plus 2 collection-only text fields kept in the DB but excluded from the model), and writes everything to Postgres.

---

## Retraining the Model

After building the dataset:

```bash
source .venv/bin/activate

MLFLOW_TRACKING_URI=http://localhost:5000 \
MLFLOW_S3_ENDPOINT_URL=http://localhost:9000 \
AWS_ACCESS_KEY_ID=minioadmin \
AWS_SECRET_ACCESS_KEY=minioadmin \
DB_HOST=localhost DB_PORT=15432 DB_NAME=packages DB_USER=appuser DB_PASS=apppass \
python3 scripts/train_model.py
```

Takes ~2 minutes. Trains XGBoost on 13 features with monotonic constraints and 400 estimators. If the new model beats the current champion F1, it gets promoted automatically. Copy the new model file so the API uses it:

```bash
source .venv/bin/activate

MLFLOW_TRACKING_URI=http://localhost:5000 \
MLFLOW_S3_ENDPOINT_URL=http://localhost:9000 \
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
python3 -c "
import mlflow
mlflow.set_tracking_uri('http://localhost:5000')
m = mlflow.xgboost.load_model('models:/malicious-package-detector@champion')
m.save_model('model/champion.json')
print('done')
"

docker compose up -d --build api
```

---

## The 13 Features

XGBoost is trained with **monotonic constraints** so each feature is forced to move
risk in the direction below — eliminating learned spurious correlations.

| Category | Feature | Monotonic | What it detects |
|---|---|---|---|
| Code | `entropy_max` | +1 | Base64/obfuscated payloads |
| Code | `has_network_in_install` | +1 | Exfiltration during `pip install` |
| Code | `has_credential_access` | +1 | Reads `~/.aws`, `~/.ssh`, env tokens |
| Code | `has_exec_eval` | +1 | `eval()`/`exec()` co-located with decode/download |
| Code | `has_obfuscated_code` | +1 | Long base64 / hex / encoded payloads |
| Code | `has_os_targeting` | +1 | Platform check gating a suspicious payload |
| Code | `has_external_payload` | +1 | Downloads then executes a remote file |
| Code | `install_script_lines` | +1 | Abnormally long install hooks |
| Code | `dangerous_import_count` | +1 | `ctypes`, `cffi`, `marshal`, or network imports in install |
| Code | `api_category_count` | +1 | Suspicious shell / exfil / dyn-exec / persistence combos |
| Metadata | `is_typosquat` | +1 | Name ≤2 edits from a popular package |
| Metadata | `typosquat_distance` | 0 | Edit distance (0 = on top-package list) |
| Metadata | `version_jump_suspicious` | +1 | Jumped from 0.1 to 9.9 |

> **Removed post-audit (4 features):** Two rounds of adversarial auditing eliminated
> features that were collection artifacts rather than malicious-behaviour signals:
>
> - **Round 1** — `description_length`, `readme_length`: pypi_malregistry packages
>   were removed from PyPI before collection so they had empty descriptions; the v1
>   model learned "no description ⇒ malicious" and could be evaded by simply padding
>   the description field.
> - **Round 2** — `has_repo_link`, `version_count`: top-PyPI benigns nearly always
>   have a GitHub URL and many releases (92.5% / avg 88); pypi_malregistry packages
>   never do (0% / always 1). 100% separable but trivially evadable — an attacker
>   can claim a fake repo URL in `setup.py` and our adversarial test confirmed this
>   evaded 500/500 sampled malicious packages.

---

## Architecture

```
PyPI / npm APIs
      ↓  every 15 min   [Airflow: ingest_dag]
MinIO (raw archives) + Postgres (packages table)
      ↓  every 30 min   [Airflow: extract_dag]
13 features extracted → Postgres (features table)
      ↓  weekly         [Airflow: train_dag]
XGBoost → MLflow experiment tracking → champion model
      ↓  every 30 min   [Airflow: score_dag]
SHAP explanations → Postgres (scores table)
      ↓
REST API :8000   +   Grafana dashboard :3000
```

---

## Jupyter Notebook

For interactive exploration of the model, SHAP plots, and scoring:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install jupyter matplotlib pandas numpy shap xgboost mlflow psycopg2-binary requests boto3

jupyter notebook notebooks/model_demo.ipynb
```

---

## Stopping

```bash
docker compose down        # stop containers, keep data
docker compose down -v     # stop and DELETE all data (full reset)
```

---

## Full Setup Guide

For a complete from-scratch walkthrough including Postgres schema details, Airflow DAG configuration, and troubleshooting, see [SETUP.md](SETUP.md).
