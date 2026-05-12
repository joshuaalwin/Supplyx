# MLPro — From-Scratch Setup Guide

Everything you need to go from a blank machine to a fully running stack. Follow the sections in order.

---

## Prerequisites

```bash
# Docker + Docker Compose
docker --version       # 24.x or later
docker compose version # 2.x or later

# Python 3.11+ on the host (for build_dataset.py and train_model.py)
python3 --version

# Git (to clone pypi_malregistry dataset)
git --version
```

If Docker isn't installed:
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER   # then log out and back in
```

---

## Step 1 — Clone / copy the project

```bash
cd ~
# If you have the project files already, just cd into it
cd ~/MLPro
```

Your directory must contain:
```
MLPro/
├── Dockerfile
├── Dockerfile.mlflow
├── Dockerfile.api
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── init/
│   ├── init_db.sql
│   ├── add_labels.sql
│   └── add_scores.sql
├── dags/
├── api/
├── grafana/
└── scripts/
```

---

## Step 2 — Create the .env file

```bash
cd ~/MLPro
cp .env.example .env
```

The `.env` file should contain exactly this — do not change any values unless you know what you're doing:

```env
AIRFLOW_UID=50000

DB_HOST=postgres
DB_PORT=5432
DB_NAME=packages
DB_USER=appuser
DB_PASS=apppass

MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
MINIO_BUCKET=packages

INGEST_LIMIT=50
EXTRACT_BATCH_SIZE=20
```

> **AIRFLOW_UID must be 50000.** The apache/airflow image hardcodes its internal user to uid 50000. Do not set it to your own uid.

---

## Step 3 — Set up the Python venv (host scripts only)

The Docker containers handle their own dependencies. The venv is only needed for running `build_dataset.py` and `train_model.py` directly on the host.

```bash
cd ~/MLPro
python3 -m venv .venv
source .venv/bin/activate

pip install requests psycopg2-binary mlflow xgboost scikit-learn shap pandas numpy boto3
```

For the Jupyter notebook too:
```bash
pip install jupyter matplotlib
```

---

## Step 4 — Build and start infrastructure

```bash
cd ~/MLPro

# Build all custom images (Airflow, MLflow, API)
docker compose build

# Start Postgres and MinIO first
docker compose up -d postgres minio minio-init

# Wait for Postgres to be healthy
until docker compose ps postgres | grep -q "healthy"; do sleep 3; done
echo "Postgres ready"

# Start MLflow
docker compose up -d mlflow

# Wait for MLflow to be healthy
until docker compose ps mlflow | grep -q "healthy"; do sleep 3; done
echo "MLflow ready"
```

At this point you have:
- PostgreSQL at `localhost:15432` (host-mapped; internal port 5432) — two databases: `airflow` (Airflow internals) and `packages` (your data)
- MinIO at `localhost:9000` — three buckets: `packages`, `features`, `mlflow`
- MLflow at `localhost:5000`

---

## Step 5 — What Postgres looks like after init

The three SQL files in `init/` run automatically on first container start (mounted into `/docker-entrypoint-initdb.d/`). They only run once — if the volume already exists they are skipped.

**`01_init_db.sql`** creates the app user and base schema:
```sql
CREATE USER appuser WITH PASSWORD 'apppass';
CREATE DATABASE packages OWNER appuser;

-- packages table: one row per package version
CREATE TABLE packages (
    id                   SERIAL PRIMARY KEY,
    registry             VARCHAR(10),   -- 'pypi' | 'npm'
    name                 VARCHAR(255),
    version              VARCHAR(100),
    author               VARCHAR(255),
    description          TEXT,
    homepage             VARCHAR(500),
    repository           VARCHAR(500),
    keywords             TEXT[],
    downloads_last_month INTEGER DEFAULT 0,
    object_key           VARCHAR(500),  -- MinIO key for raw archive
    ingested_at          TIMESTAMPTZ DEFAULT NOW(),
    extraction_status    VARCHAR(20) DEFAULT 'pending',  -- pending|done|failed
    UNIQUE (registry, name, version)
);

-- features table: one row per package after extraction
CREATE TABLE features (
    id                     SERIAL PRIMARY KEY,
    package_id             INTEGER REFERENCES packages(id) ON DELETE CASCADE UNIQUE,
    entropy_max            FLOAT,
    has_network_in_install BOOLEAN DEFAULT FALSE,
    has_credential_access  BOOLEAN DEFAULT FALSE,
    has_obfuscated_code    BOOLEAN DEFAULT FALSE,
    has_exec_eval          BOOLEAN DEFAULT FALSE,
    install_script_lines   INTEGER DEFAULT 0,
    dangerous_import_count INTEGER DEFAULT 0,
    account_age_days       INTEGER,
    typosquat_target       VARCHAR(255),
    typosquat_distance     INTEGER,
    has_repo_link          BOOLEAN DEFAULT FALSE,
    version_count          INTEGER DEFAULT 1,
    description_length     INTEGER DEFAULT 0,
    readme_length          INTEGER DEFAULT 0,
    raw_features           JSONB,
    extracted_at           TIMESTAMPTZ DEFAULT NOW()
);
```

**`02_add_labels.sql`** adds label columns and extra feature columns:
```sql
ALTER TABLE packages
    ADD COLUMN label        INTEGER,      -- 0=benign | 1=malicious | NULL=live
    ADD COLUMN label_source VARCHAR(50);  -- 'pypi_malregistry'|'top_pypi'|'top_npm'

ALTER TABLE features
    ADD COLUMN version_jump_suspicious BOOLEAN DEFAULT FALSE,
    ADD COLUMN has_os_targeting        BOOLEAN DEFAULT FALSE,
    ADD COLUMN has_external_payload    BOOLEAN DEFAULT FALSE,
    ADD COLUMN api_category_count      INTEGER DEFAULT 0;

ALTER TABLE packages
    ALTER COLUMN downloads_last_month TYPE BIGINT;
```

**`03_add_scores.sql`** creates the scores table:
```sql
CREATE TABLE scores (
    id            SERIAL PRIMARY KEY,
    package_id    INTEGER REFERENCES packages(id) ON DELETE CASCADE UNIQUE,
    score         FLOAT NOT NULL,        -- 0.0–1.0 malicious probability
    risk_level    VARCHAR(10) NOT NULL,  -- low|medium|high|critical
    shap_values   JSONB,                 -- {feature: shap_value}
    report_md     TEXT,                  -- markdown explanation
    model_version VARCHAR(50),
    scored_at     TIMESTAMPTZ DEFAULT NOW()
);
```

Verify the schema was created:
```bash
docker exec mlpro-postgres-1 psql -U appuser -d packages -c "\dt"
```
Expected output: `packages`, `features`, `scores`.

---

## Step 6 — Initialize Airflow

```bash
cd ~/MLPro

# Run the init container — migrates Airflow's DB and creates the admin user
docker compose up -d airflow-init

# Wait for it to finish (it exits when done)
until docker compose ps airflow-init | grep -qE "Exit|Exited"; do sleep 3; done
echo "Airflow init done"

# Check it succeeded (exit code 0)
docker compose ps airflow-init
```

This creates:
- Airflow metadata tables in the `airflow` Postgres database
- Admin user: `admin` / `admin`

---

## Step 7 — Start the rest of the stack

```bash
cd ~/MLPro
docker compose up -d airflow-webserver airflow-scheduler grafana
```

Wait for Airflow webserver:
```bash
until curl -s http://localhost:8080/health | grep -q "healthy"; do sleep 5; done
echo "Airflow webserver ready"
```

Check everything is up:
```bash
docker compose ps
```

Expected — all services Up:
```
mlpro-airflow-scheduler-1   Up
mlpro-airflow-webserver-1   Up (healthy)
mlpro-grafana-1             Up
mlpro-minio-1               Up (healthy)
mlpro-mlflow-1              Up (healthy)
mlpro-postgres-1            Up (healthy)
```

> The API is not started yet — it needs a trained model in MLflow first.

---

## Step 8 — Build the training dataset

This downloads the malicious dataset and the top-downloaded benign packages, extracts features, and writes everything to Postgres. It takes **30–60 minutes** depending on your connection.

```bash
cd ~/MLPro
source .venv/bin/activate

# Full run — clones pypi_malregistry (~800 MB) + downloads benign packages
DB_HOST=localhost DB_PORT=15432 DB_NAME=packages DB_USER=appuser DB_PASS=apppass \
python3 scripts/build_dataset.py

# If pypi_malregistry is already cloned in data/
DB_HOST=localhost DB_PORT=15432 DB_NAME=packages DB_USER=appuser DB_PASS=apppass \
python3 scripts/build_dataset.py --skip-clone
```

When it finishes it prints a summary:
```
=== Dataset summary ===
  benign     (label=0): 1,992
  malicious  (label=1): 20,845
  total                : 22,837
```

Verify in Postgres:
```bash
docker exec mlpro-postgres-1 psql -U appuser -d packages \
  -c "SELECT label, COUNT(*) FROM packages WHERE label IS NOT NULL GROUP BY label;"
```

---

## Step 9 — Train the model

```bash
cd ~/MLPro
source .venv/bin/activate

MLFLOW_TRACKING_URI=http://localhost:5000 \
MLFLOW_S3_ENDPOINT_URL=http://localhost:9000 \
AWS_ACCESS_KEY_ID=minioadmin \
AWS_SECRET_ACCESS_KEY=minioadmin \
DB_HOST=localhost DB_PORT=15432 DB_NAME=packages DB_USER=appuser DB_PASS=apppass \
python3 scripts/train_model.py
```

Takes about **1–2 minutes**. Output:
```
[train] dataset: 11609 samples  malicious=11025  benign=584
[train] metrics: {'f1': 0.9995, 'roc_auc': 0.9986, ...}
[train] promoted version 1 to champion (F1=0.9995)
```

Verify in MLflow at http://localhost:5000 — you should see the `malicious-package-detection` experiment with one run, and the model registered as `malicious-package-detector` with the `champion` alias.

---

## Step 10 — Start the API

```bash
cd ~/MLPro
docker compose up -d api
```

Wait for it:
```bash
until docker compose logs --tail=5 api 2>/dev/null | grep -q "startup complete"; do sleep 2; done
echo "API ready"
```

Verify:
```bash
curl http://localhost:8000/api/health
# → {"status":"ok","model_loaded":true}
```

If `model_loaded` is false, MLflow wasn't healthy when the API started:
```bash
docker compose restart api
```

---

## Step 11 — Configure Airflow DAGs

Open http://localhost:8080 (admin / admin) and set these DAG states, or do it via API:

```bash
# Unpause the 4 operational DAGs
for dag in ingest_packages extract_features train_model score_packages; do
  curl -s -u admin:admin -X PATCH http://localhost:8080/api/v1/dags/$dag \
    -H "Content-Type: application/json" -d '{"is_paused": false}' > /dev/null
  echo "$dag unpaused"
done

# Pause the deprecated label DAG
curl -s -u admin:admin -X PATCH http://localhost:8080/api/v1/dags/build_labeled_dataset \
  -H "Content-Type: application/json" -d '{"is_paused": true}' > /dev/null
echo "build_labeled_dataset paused"
```

Expected final DAG states:

| DAG | State |
|---|---|
| `ingest_packages` | unpaused — runs every 15 min |
| `extract_features` | unpaused — runs every 30 min |
| `train_model` | unpaused — runs weekly |
| `score_packages` | unpaused — runs every 30 min |
| `build_labeled_dataset` | **paused** (deprecated) |

---

## Step 12 — Verify end to end

```bash
# Score a benign package
curl -s -X POST http://localhost:8000/api/score \
  -H "Content-Type: application/json" \
  -d '{"registry":"pypi","name":"pluggy","version":"1.6.0"}' | python3 -m json.tool

# Score a malicious package
curl -s -X POST http://localhost:8000/api/score \
  -H "Content-Type: application/json" \
  -d '{"registry":"npm","name":"000webhost-admin","version":"0.0.1-security"}' | python3 -m json.tool

# Fetch a report (after scoring once)
curl -s http://localhost:8000/api/report/pypi/pluggy/1.6.0 | python3 -m json.tool
```

Expected: pluggy scores ~0.001 (low), 000webhost-admin scores ~0.72 (high).

---

## Step 13 — Jupyter notebook (optional)

```bash
cd ~/MLPro
source .venv/bin/activate
jupyter notebook notebooks/model_demo.ipynb --no-browser --port=8888
```

Open the URL printed in the terminal. Run all cells top to bottom with Shift+Enter.

---

## All Services at a Glance

| Service | URL | Credentials | Purpose |
|---|---|---|---|
| Airflow UI | http://localhost:8080 | admin / admin | DAG management |
| MLflow UI | http://localhost:5000 | — | Experiment tracking, model registry |
| REST API | http://localhost:8000 | — | Score packages, fetch reports |
| API docs | http://localhost:8000/docs | — | Interactive Swagger UI |
| Grafana | http://localhost:3000 | admin / admin | Dashboards |
| MinIO console | http://localhost:9001 | minioadmin / minioadmin | Object store browser |
| PostgreSQL | localhost:15432 | appuser / apppass | packages DB |

---

## Port Conflicts

If any port is already in use on your machine, edit `docker-compose.yml` and change the left side of the mapping:

```yaml
ports:
  - "5433:5432"   # host port 5433 → container port 5432
```

---

## Starting Fresh (Wipe Everything)

```bash
cd ~/MLPro

# Stop all containers and DELETE all volumes (data gone)
docker compose down -v

# Remove built images too
docker compose down -v --rmi all

# Then go back to Step 4
```

> This deletes your database, MinIO data, and trained models. Only do this if you genuinely want to start over.

---

## Troubleshooting

### `model_loaded: false`
MLflow wasn't ready when the API started. Run `docker compose restart api`.

### DAG import errors in Airflow
The Airflow image is stale — ML packages not installed.
```bash
docker compose build airflow-webserver airflow-scheduler
docker compose up -d airflow-webserver airflow-scheduler
```

### Postgres schema missing (tables don't exist)
The init SQL only runs when the volume is first created. If you started Postgres before the init files were in place:
```bash
docker compose down
docker volume rm mlpro_postgres_data
docker compose up -d postgres
```

### MLflow 403 "Invalid Host header"
The `--allowed-hosts "*"` flag in `Dockerfile.mlflow` handles this. Rebuild if needed:
```bash
docker compose build mlflow && docker compose up -d mlflow
```

### build_dataset.py — connection refused
Postgres must be running and healthy first. Check:
```bash
docker compose ps postgres
# must show (healthy)
```

### Airflow webserver not starting
Usually the init container didn't complete successfully. Check:
```bash
docker compose logs airflow-init | tail -20
```
