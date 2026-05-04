# MLPro — ML-Powered Malicious Package Detection

Detects malicious npm and PyPI packages using XGBoost trained on 17 static signals (code behaviour, metadata, and text). Every prediction includes a SHAP explanation of which signals drove the score.

**The pre-trained model is included** — clone and run, no training required.

---

## Quickstart

**Requirements:** Docker, Docker Compose, Git

```bash
git clone https://github.com/Elnimo-00/MLPro.git
cd MLPro
cp .env.example .env
./start.sh
```

That's it. After ~2 minutes:

```
  API      → http://localhost:8000/api/health
  Airflow  → http://localhost:8080   (admin / admin)
  MLflow   → http://localhost:5000
  Grafana  → http://localhost:3000   (admin / admin)
  MinIO    → http://localhost:9001   (minioadmin / minioadmin)

  ✓ Model loaded — ready to score packages
```

---

## Scoring a Package

```bash
# Score any package (must exist in the database)
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

The model was trained on two sources:

| Class | Source | Count |
|---|---|---|
| malicious | [pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) — verified malicious packages removed from PyPI (ASE 2023 paper) | ~10,968 |
| malicious | DataDog malware dataset | ~9,874 |
| benign | Top 2,000 PyPI packages by downloads | ~1,887 |
| benign | Top 100 npm packages by downloads | 105 |

The dataset is **not included in this repo** (1.2 GB). To build it yourself:

```bash
# Set up the Python environment
python3 -m venv .venv
source .venv/bin/activate
pip install requests psycopg2-binary mlflow xgboost scikit-learn shap pandas numpy boto3

# Start the stack first (Postgres must be running)
./start.sh

# Build the dataset — takes 30–60 min
DB_HOST=localhost DB_PORT=5432 DB_NAME=packages DB_USER=appuser DB_PASS=apppass \
python3 scripts/build_dataset.py
```

This clones `pypi_malregistry`, downloads the top PyPI/npm packages, extracts features, and writes everything to Postgres.

---

## Retraining the Model

After building the dataset:

```bash
source .venv/bin/activate

MLFLOW_TRACKING_URI=http://localhost:5000 \
MLFLOW_S3_ENDPOINT_URL=http://localhost:9000 \
AWS_ACCESS_KEY_ID=minioadmin \
AWS_SECRET_ACCESS_KEY=minioadmin \
DB_HOST=localhost DB_PORT=5432 DB_NAME=packages DB_USER=appuser DB_PASS=apppass \
python3 scripts/train_model.py
```

Takes ~2 minutes. If the new model beats the current champion F1, it gets promoted automatically. Copy the new model file so the API uses it:

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

## The 17 Features

| Category | Feature | What it detects |
|---|---|---|
| Code | `entropy_max` | Base64/obfuscated payloads |
| Code | `has_network_in_install` | Exfiltration during `pip install` |
| Code | `has_credential_access` | Reads `~/.aws`, `~/.ssh`, env tokens |
| Code | `has_exec_eval` | `eval()`/`exec()` on downloaded content |
| Code | `has_obfuscated_code` | Encoded or compressed code |
| Code | `has_os_targeting` | OS-specific attack logic |
| Code | `has_external_payload` | Downloads and executes a remote file |
| Code | `install_script_lines` | Abnormally long install hooks |
| Code | `dangerous_import_count` | `subprocess`, `socket`, `ctypes`, etc. |
| Code | `api_category_count` | Multiple suspicious API categories used |
| Metadata | `is_typosquat` | Name ≤2 edits from a popular package |
| Metadata | `typosquat_distance` | Edit distance to nearest popular package |
| Metadata | `has_repo_link` | No repository link |
| Metadata | `version_count` | Only 1 version (throwaway account) |
| Metadata | `version_jump_suspicious` | Jumped from 0.1 to 9.9 |
| Text | `description_length` | Empty or placeholder description |
| Text | `readme_length` | Missing or copied README |

---

## Architecture

```
PyPI / npm APIs
      ↓  every 15 min   [Airflow: ingest_dag]
MinIO (raw archives) + Postgres (packages table)
      ↓  every 30 min   [Airflow: extract_dag]
17 features extracted → Postgres (features table)
      ↓  weekly         [Airflow: train_dag]
XGBoost → MLflow experiment tracking → champion model
      ↓  every 30 min   [Airflow: score_dag]
SHAP explanations → Postgres (scores table)
      ↓
REST API :8000   +   Grafana dashboard :3000
```

---

## Services

| Service | URL | Credentials |
|---|---|---|
| REST API | http://localhost:8000 | — |
| API docs (Swagger) | http://localhost:8000/docs | — |
| Airflow | http://localhost:8080 | admin / admin |
| MLflow | http://localhost:5000 | — |
| Grafana | http://localhost:3000 | admin / admin |
| MinIO | http://localhost:9001 | minioadmin / minioadmin |
| Postgres | localhost:5432 | appuser / apppass (db: packages) |

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
