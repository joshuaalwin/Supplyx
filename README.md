# MLPro — ML-Powered Malicious Package Detection

Detects malicious npm and PyPI packages using XGBoost trained on 17 static signals extracted from code, metadata, and text. Every prediction comes with a SHAP-based explanation of which signals drove the risk score.

---

## How It Works

```
New package uploaded to PyPI / npm
        ↓
Airflow pulls it every 15 min          [ingest_dag]
        ↓
Extract 17 signals from the archive    [extract_dag]
        ↓
XGBoost scores it 0.0 – 1.0           [score_dag]
        ↓
SHAP explains which signals fired      [score_dag]
        ↓
REST API serves the report             [:8000]
        ↓
Grafana shows the dashboard            [:3000]
```

---

## Services

| Service | URL | Credentials |
|---|---|---|
| Airflow UI | http://localhost:8080 | admin / admin |
| MLflow UI | http://localhost:5000 | — |
| REST API | http://localhost:8000 | — |
| Grafana | http://localhost:3000 | admin / admin |
| MinIO console | http://localhost:9001 | minioadmin / minioadmin |
| PostgreSQL | localhost:5432 | appuser / apppass (db: packages) |

---

## Starting the Stack After a Reboot

Everything is stateful — Postgres and MinIO use named Docker volumes, so your data and trained model survive restarts.

```bash
cd ~/MLPro

# 1. Start infrastructure first
docker compose up -d postgres minio minio-init

# 2. Wait for postgres to be healthy, then start MLflow
docker compose up -d mlflow
until docker compose ps mlflow | grep -q "healthy"; do sleep 3; done

# 3. Start Airflow (init checks if DB is already migrated — safe to re-run)
docker compose up -d airflow-init
until docker compose ps airflow-init | grep -qE "Exit|Exited"; do sleep 3; done

# 4. Start everything else
docker compose up -d airflow-webserver airflow-scheduler api grafana
```

**That's it.** The model is already trained and stored in MLflow. The API loads it at startup automatically.

Verify everything is up:
```bash
docker compose ps
curl http://localhost:8000/api/health
# → {"status":"ok","model_loaded":true}
```

> **If model_loaded is false:** MLflow wasn't healthy when the API started. Run `docker compose restart api` after MLflow shows healthy.

---

## DAG States After Restart

Airflow remembers DAG pause states in its database, so these should already be set correctly. Double-check in the UI (http://localhost:8080) or via:

```bash
curl -s -u admin:admin http://localhost:8080/api/v1/dags | python3 -c "
import json,sys
for d in json.load(sys.stdin)['dags']:
    print(d['dag_id'], '— paused:', d['is_paused'])"
```

Expected state:

| DAG | Should be |
|---|---|
| `ingest_packages` | **unpaused** |
| `extract_features` | **unpaused** |
| `train_model` | **unpaused** |
| `score_packages` | **unpaused** |
| `build_labeled_dataset` | **paused** (deprecated) |

If any operational DAG is paused, unpause it:
```bash
curl -s -u admin:admin -X PATCH http://localhost:8080/api/v1/dags/ingest_packages \
  -H "Content-Type: application/json" -d '{"is_paused": false}'
```

---

## Using the REST API

### Score a package on demand

```bash
curl -X POST http://localhost:8000/api/score \
  -H "Content-Type: application/json" \
  -d '{"registry":"pypi","name":"requests","version":"2.31.0"}'
```

Response:
```json
{
  "registry": "pypi",
  "name": "requests",
  "version": "2.31.0",
  "score": 0.001,
  "risk_level": "low",
  "report_md": "# pypi/requests@2.31.0\n...",
  "model_version": "1",
  "cached": false
}
```

Risk levels: `low` (< 0.3) · `medium` (0.3–0.6) · `high` (0.6–0.8) · `critical` (≥ 0.8)

> **Note:** The package must already be in the database (either ingested by `ingest_dag` or added by `build_dataset.py`). If you get a 404, the package isn't in the DB yet.

### Fetch a persisted report

```bash
curl http://localhost:8000/api/report/pypi/requests/2.31.0
```

Only works after the package has been scored (either via POST /api/score or by the score_dag).

---

## The 17 Features

**Code — what the package does:**

| Feature | What it catches |
|---|---|
| `entropy_max` | High-entropy strings — base64/obfuscated payloads |
| `has_network_in_install` | Network calls in `setup.py`/`postinstall` — exfiltration on install |
| `has_credential_access` | Reads `~/.ssh`, `~/.aws/credentials`, env vars with TOKEN/KEY/SECRET |
| `has_exec_eval` | `eval()`/`exec()` on downloaded content — second-stage payloads |
| `has_obfuscated_code` | Encoded or compressed code blocks |
| `has_os_targeting` | Checks `sys.platform` to target specific OS |
| `has_external_payload` | Downloads something and executes it |
| `install_script_lines` | Length of install hook (legit packages don't need 500-line hooks) |
| `dangerous_import_count` | Imports of `subprocess`, `socket`, `ctypes`, `os`, etc. |
| `api_category_count` | Number of *categories* of suspicious APIs used |

**Metadata — what the package claims to be:**

| Feature | What it catches |
|---|---|
| `is_typosquat` | Name is ≤2 edits from a popular package (`reqeusts`, `boto33`) |
| `typosquat_distance` | Edit distance — 1 is worse than 2 |
| `has_repo_link` | Missing repository link |
| `version_count` | Number of versions (throwaway accounts publish once) |
| `version_jump_suspicious` | Jumped from 0.1 to 9.9 to fake maturity |

**Text — what the package says:**

| Feature | What it catches |
|---|---|
| `description_length` | Empty or placeholder description |
| `readme_length` | No README or copy-pasted README |

---

## Training Dataset

| Class | Source | Count |
|---|---|---|
| malicious | pypi_malregistry (ASE 2023 research) | 10,968 |
| malicious | DataDog malware dataset | ~9,874 |
| benign | top-2000 PyPI by downloads | ~1,887 |
| benign | top-100 npm by downloads | 105 |

Only packages with features extracted (~11,600) are used for training. The remaining ~9,800 labeled malicious packages couldn't be re-downloaded (they were removed from PyPI).

### Current model

| Version | Champion | F1 | ROC-AUC |
|---|---|---|---|
| v1 | ✅ | 0.9995 | 0.9986 |
| v2 | — | 0.9982 | 0.9998 |
| v3 | — | 0.9982 | 0.9998 |

The API loads `models:/malicious-package-detector@champion` at startup. Promotion is automatic — `train_dag` only moves the `champion` alias to a new version if its F1 beats the current champion.

---

## Retraining the Model

### Via Airflow (recommended)

Trigger a manual run from the UI at http://localhost:8080, or via CLI:

```bash
curl -s -u admin:admin -X POST http://localhost:8080/api/v1/dags/train_model/dagRuns \
  -H "Content-Type: application/json" -d '{"conf":{}}'
```

### Via host venv (faster, no Airflow overhead)

```bash
cd ~/MLPro
source .venv/bin/activate

MLFLOW_TRACKING_URI=http://localhost:5000 \
MLFLOW_S3_ENDPOINT_URL=http://localhost:9000 \
AWS_ACCESS_KEY_ID=minioadmin \
AWS_SECRET_ACCESS_KEY=minioadmin \
DB_HOST=localhost DB_PORT=5432 DB_NAME=packages DB_USER=appuser DB_PASS=apppass \
python3 scripts/train_model.py
```

Retrain when:
- The benign dataset has grown significantly (run `build_dataset.py` again)
- The ingest pipeline has accumulated enough new live packages with labels
- You've made changes to feature extractors

---

## Expanding the Training Dataset

The benign set was built once and can be expanded:

```bash
cd ~/MLPro
source .venv/bin/activate

DB_HOST=localhost DB_PORT=5432 DB_NAME=packages DB_USER=appuser DB_PASS=apppass \
python3 scripts/build_dataset.py --benign-only --skip-clone
```

Flags:
- `--benign-only` — only download benign packages (skip malicious re-scan)
- `--skip-clone` — pypi_malregistry is already cloned in `data/`
- `--malicious-only` — re-process malicious packages only
- `--workers N` — parallel workers (default 8)

The script is idempotent — it skips packages already in the DB.

---

## File Structure

```
MLPro/
├── Dockerfile                   # Airflow image (apache/airflow:2.9.3 + ML packages)
├── Dockerfile.mlflow            # MLflow server (python:3.11-slim + mlflow/boto3)
├── Dockerfile.api               # FastAPI service (python:3.11-slim + all ML packages)
├── docker-compose.yml           # All 7 services wired together
├── requirements.txt             # Airflow container deps (no pinned versions — Python 3.12)
├── .env                         # AIRFLOW_UID=50000 + DB/MinIO config
│
├── init/
│   ├── init_db.sql              # packages + features schema
│   ├── add_labels.sql           # label column + new feature columns migration
│   └── add_scores.sql           # scores table migration
│
├── dags/
│   ├── ingest_dag.py            # Polls PyPI + npm → MinIO + packages table (every 15 min)
│   ├── extract_dag.py           # Runs extractors → features table (every 30 min)
│   ├── train_dag.py             # XGBoost → MLflow → champion promotion (weekly)
│   ├── score_dag.py             # Scores live packages → scores table (every 30 min)
│   ├── label_dag.py             # DEPRECATED — use build_dataset.py instead
│   ├── clients/
│   │   ├── pypi.py              # PyPI RSS + JSON API client
│   │   └── npm.py               # npm registry search + metadata client
│   ├── storage/
│   │   ├── db.py                # PostgreSQL helpers
│   │   └── object_store.py      # MinIO upload/download
│   └── extractors/
│       ├── code_features.py     # Entropy, install-script patterns, obfuscation, etc.
│       ├── metadata_features.py # Typosquat detection, version analysis
│       └── text_features.py     # Description/README signals
│
├── scripts/
│   ├── build_dataset.py         # One-time: download + label training packages
│   └── train_model.py           # Standalone training (no Airflow dependency)
│
├── api/
│   ├── main.py                  # FastAPI: /api/score, /api/report, /api/health
│   └── requirements.txt         # API container deps
│
├── grafana/
│   └── provisioning/
│       ├── datasources/postgres.yml
│       └── dashboards/
│           ├── dashboard.yml
│           └── mlpro.json
│
└── data/
    └── pypi_malregistry/        # Cloned malicious package dataset (~11k packages)
```

---

## Database Schema

```sql
-- One row per package version
packages (
    id, registry, name, version,
    author, description, homepage, repository, keywords,
    downloads_last_month,
    extraction_status,   -- 'pending' | 'done'
    label,               -- 0=benign | 1=malicious | NULL=live/unscored
    label_source         -- 'pypi_malregistry' | 'datadog' | 'top_pypi' | 'top_npm' | 'live'
)

-- One row per package (after feature extraction)
features (
    package_id,
    -- code features
    entropy_max, has_network_in_install, has_credential_access,
    has_obfuscated_code, has_exec_eval, install_script_lines,
    dangerous_import_count, has_os_targeting, has_external_payload,
    api_category_count,
    -- metadata features
    typosquat_target, typosquat_distance, is_typosquat,
    has_repo_link, version_count, version_jump_suspicious,
    -- text features
    description_length, readme_length,
    raw_features JSONB
)

-- One row per scored package
scores (
    package_id,
    score,           -- 0.0–1.0
    risk_level,      -- 'low' | 'medium' | 'high' | 'critical'
    shap_values,     -- JSONB: {feature: shap_value} for each of 17 features
    report_md,       -- human-readable markdown explanation
    model_version,   -- MLflow version that produced this score
    scored_at
)
```

---

## Architecture Decisions Worth Knowing

**MLflow uses `champion` alias, not stages.** Stages (`Production`, `Staging`) are deprecated in MLflow 3.x. Load the serving model with `models:/malicious-package-detector@champion`. The `train_dag` and `score_dag` both use this alias.

**No pinned package versions.** The Airflow image runs Python 3.12 and the API/MLflow images run Python 3.11. Pinning specific versions (e.g. `numpy==1.26.4`) breaks on these Python versions. All `requirements.txt` files use unpinned deps.

**`score_dag` only scores `label=NULL` packages.** It ignores training data (labeled packages). To score a specific package regardless of label, use `POST /api/score` — it writes the result to the scores table so `GET /api/report` works afterwards.

**`build_dataset.py` is idempotent.** It checks the DB before downloading anything. Safe to run multiple times.

**AIRFLOW_UID must be 50000.** The apache/airflow image hardcodes its user to uid 50000. Do not change this in `.env`.

**Docker volumes survive `docker compose down`.** Your data is safe. Only `docker compose down -v` deletes volumes (don't do this unless you want to start from scratch).

---

## Troubleshooting

### `model_loaded: false` in /api/health

MLflow wasn't healthy when the API container started.
```bash
docker compose restart api
curl http://localhost:8000/api/health
```

### DAG import errors in Airflow

Usually means the Airflow image is stale (ML packages not installed).
```bash
cd ~/MLPro
docker compose build airflow-webserver airflow-scheduler
docker compose up -d airflow-webserver airflow-scheduler
```

### MLflow returns 403 "Invalid Host header"

The `--allowed-hosts "*"` flag in `Dockerfile.mlflow` handles this. If you see it, the MLflow image wasn't rebuilt after that change was added.
```bash
docker compose build mlflow
docker compose up -d mlflow
```

### Postgres connection refused

Postgres isn't healthy yet. Wait for it:
```bash
until docker compose ps postgres | grep -q "healthy"; do sleep 2; done
```

### Starting completely from scratch (wipes all data)

```bash
cd ~/MLPro
docker compose down -v      # deletes ALL volumes — all data gone
docker compose build        # rebuild all images
# Then follow the normal startup sequence above
# Then re-run build_dataset.py to rebuild training data
```
