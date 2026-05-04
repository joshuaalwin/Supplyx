# MLPro Knowledge Base

Complete technical reference for the MLPro malicious package detection system. Read this before making any changes.

---

## 1. What This Project Does

MLPro detects malicious packages on PyPI and npm using machine learning. It continuously ingests new packages from both registries, extracts 17 static features from their code, metadata, and text, scores them with an XGBoost classifier, and produces human-readable SHAP-based explanations for every prediction.

The system runs as 7 Docker containers orchestrated by Apache Airflow, with a FastAPI REST API for on-demand scoring and a Grafana dashboard for monitoring.

---

## 2. Architecture

```
PyPI RSS / npm Search API
    |
    v  every 15 min [ingest_dag]
MinIO (raw .tar.gz archives)  +  PostgreSQL (packages table, status=pending)
    |
    v  every 30 min [extract_dag]
Feature extraction (code + metadata + text) --> PostgreSQL (features table, status=done)
    |
    v  weekly [train_dag]
XGBoost training --> MLflow (experiment tracking, model registry, champion alias)
    |
    v  every 30 min [score_dag]
Batch scoring + SHAP --> PostgreSQL (scores table: score, risk_level, shap_values, report_md)
    |
    v
FastAPI REST API (:8000)  +  Grafana dashboard (:3000)
```

---

## 3. Services

| Service | Image / Build | Port | Credentials | Purpose |
|---------|---------------|------|-------------|---------|
| postgres | postgres:15 | 5432 | appuser / apppass (DB: packages) | All application data |
| minio | minio/minio:latest | 9000 (API), 9001 (console) | minioadmin / minioadmin | S3-compatible object store for raw archives |
| minio-init | minio/mc:latest | - | - | One-shot: creates buckets (packages, features, mlflow) |
| mlflow | Dockerfile.mlflow | 5000 | - | Experiment tracking + model registry |
| api | Dockerfile.api | 8000 | - | FastAPI scoring endpoint |
| airflow-webserver | Dockerfile (Airflow 2.9.3) | 8080 | admin / admin | DAG UI |
| airflow-scheduler | Dockerfile (Airflow 2.9.3) | - | - | DAG execution |
| grafana | grafana/grafana:latest | 3000 | admin / admin | Monitoring dashboard |

Postgres runs two databases: `airflow` (Airflow metadata) and `packages` (application data). MLflow uses the `packages` DB for backend storage and MinIO `s3://mlflow/` for artifacts.

---

## 4. File Map

```
MLPro/
├── docker-compose.yml            # All 8 services defined here
├── Dockerfile                    # Airflow 2.9.3 + ML dependencies
├── Dockerfile.api                # Python 3.11 slim + FastAPI
├── Dockerfile.mlflow             # Python 3.11 slim + MLflow + boto3
├── requirements.txt              # Airflow container deps
├── .env.example                  # Environment variables template
├── .gitignore
├── start.sh                      # One-command startup script
├── README.md
├── SETUP.md                      # From-scratch walkthrough
│
├── api/
│   ├── main.py                   # FastAPI app (health, score, report endpoints)
│   └── requirements.txt          # API container deps
│
├── dags/
│   ├── ingest_dag.py             # Polls PyPI/npm, stores raw archives (every 15 min)
│   ├── extract_dag.py            # Extracts 17 features from archives (every 30 min)
│   ├── train_dag.py              # Trains XGBoost, logs to MLflow (weekly)
│   ├── score_dag.py              # Scores unscored packages with SHAP (every 30 min)
│   ├── label_dag.py              # One-shot: builds labeled dataset via Airflow
│   │
│   ├── clients/
│   │   ├── pypi.py               # PyPI RSS feed + JSON API
│   │   └── npm.py                # npm registry search + metadata
│   │
│   ├── extractors/
│   │   ├── code_features.py      # 10 code signals (entropy, exec, network, etc.)
│   │   ├── metadata_features.py  # 5 metadata signals (typosquat, versions, repo link)
│   │   └── text_features.py      # 4 text signals (description, README, phrases)
│   │
│   └── storage/
│       ├── db.py                 # PostgreSQL helpers (upsert, query, status)
│       └── object_store.py       # MinIO upload/download/exists
│
├── scripts/
│   ├── build_dataset.py          # Standalone: clone malregistry + download benign (30-60 min)
│   └── train_model.py            # Standalone: train XGBoost + log to MLflow (~2 min)
│
├── model/
│   └── champion.json             # Pre-trained XGBoost model (206 KB, works out-of-box)
│
├── init/
│   ├── init_db.sql               # Creates appuser, packages DB, packages + features tables
│   ├── add_labels.sql            # Adds label/label_source columns, extra feature columns
│   └── add_scores.sql            # Creates scores table
│
├── grafana/
│   └── provisioning/
│       ├── datasources/postgres.yml
│       └── dashboards/
│           ├── dashboard.yml
│           └── mlpro.json        # 8-panel dashboard
│
├── notebooks/
│   └── model_demo.ipynb          # Interactive SHAP plots, confusion matrix, API demo
│
└── docs/
    └── project-notes.md          # Original design document (partially outdated)
```

---

## 5. Database Schema

Three tables in the `packages` database, owned by `appuser`:

### packages

| Column | Type | Notes |
|--------|------|-------|
| id | SERIAL PK | |
| registry | VARCHAR(10) | 'pypi' or 'npm' |
| name | VARCHAR(255) | |
| version | VARCHAR(100) | |
| author | VARCHAR(255) | Nullable |
| description | TEXT | Nullable |
| homepage | VARCHAR(500) | Nullable |
| repository | VARCHAR(500) | Nullable |
| keywords | TEXT[] | PostgreSQL array |
| downloads_last_month | BIGINT | Default 0 |
| object_key | VARCHAR(500) | MinIO path for raw archive |
| ingested_at | TIMESTAMPTZ | Default NOW() |
| extraction_status | VARCHAR(20) | pending / running / done / failed |
| label | INTEGER | 0=benign, 1=malicious, NULL=live |
| label_source | VARCHAR(50) | pypi_malregistry / datadog / top_pypi / top_npm / NULL |

**Unique constraint**: `(registry, name, version)`

### features

| Column | Type | Notes |
|--------|------|-------|
| id | SERIAL PK | |
| package_id | INTEGER FK | UNIQUE, CASCADE delete |
| entropy_max | FLOAT | Highest Shannon entropy in 200-char windows |
| has_network_in_install | BOOLEAN | Network calls in setup.py/package.json |
| has_credential_access | BOOLEAN | Reads sensitive files/env vars |
| has_obfuscated_code | BOOLEAN | base64/codecs decode, long encoded strings |
| has_exec_eval | BOOLEAN | eval()/exec()/__import__()/compile() |
| install_script_lines | INTEGER | Line count of install scripts |
| dangerous_import_count | INTEGER | Count of subprocess, socket, urllib, etc. |
| has_os_targeting | BOOLEAN | sys.platform, platform.system() checks |
| has_external_payload | BOOLEAN | Download-then-execute patterns |
| api_category_count | INTEGER | Distinct suspicious API categories (0-5) |
| account_age_days | INTEGER | Always NULL (not implemented) |
| typosquat_target | VARCHAR(255) | Closest popular package name, or NULL |
| typosquat_distance | INTEGER | Edit distance to typosquat_target |
| has_repo_link | BOOLEAN | Whether a repository URL is linked |
| version_count | INTEGER | Total versions published |
| version_jump_suspicious | BOOLEAN | Major version >= 5 with <= 3 total releases |
| description_length | INTEGER | Length of description string |
| readme_length | INTEGER | Length of README file content |
| raw_features | JSONB | All features as JSON catch-all |
| extracted_at | TIMESTAMPTZ | |

### scores

| Column | Type | Notes |
|--------|------|-------|
| id | SERIAL PK | |
| package_id | INTEGER FK | UNIQUE, CASCADE delete |
| score | FLOAT | 0.0 to 1.0 malicious probability |
| risk_level | VARCHAR(10) | low / medium / high / critical |
| shap_values | JSONB | {feature_name: shap_contribution} |
| report_md | TEXT | Human-readable markdown report |
| model_version | VARCHAR(50) | MLflow model version used |
| scored_at | TIMESTAMPTZ | |

### Risk level thresholds
- **low**: score < 0.3
- **medium**: 0.3 <= score < 0.6
- **high**: 0.6 <= score < 0.8
- **critical**: score >= 0.8

---

## 6. The 17 Model Features

The model receives exactly these 17 features in this order (defined in `FEATURES` lists across train/score/API code):

```python
FEATURES = [
    "entropy_max",              # float  - max Shannon entropy over 200-char sliding windows
    "has_network_in_install",   # 0/1    - network patterns in setup.py / package.json
    "has_credential_access",    # 0/1    - reads ~/.ssh, ~/.aws, env TOKEN/SECRET/KEY
    "has_obfuscated_code",      # 0/1    - base64.b64decode, codecs.decode, long encoded strings
    "has_exec_eval",            # 0/1    - eval(), exec(), __import__(), compile()
    "install_script_lines",     # int    - total lines in install scripts
    "dangerous_import_count",   # int    - count of subprocess/socket/urllib/ctypes/pickle/etc.
    "has_os_targeting",         # 0/1    - sys.platform, platform.system(), OS string literals
    "has_external_payload",     # 0/1    - urlretrieve->exec, requests.get->eval chains
    "api_category_count",       # int    - distinct suspicious API categories (network/file/process/encryption/execution)
    "typosquat_distance",       # int    - edit distance to nearest popular package (0 if no match)
    "is_typosquat",             # 0/1    - derived: typosquat_target IS NOT NULL
    "has_repo_link",            # 0/1    - has a repository URL
    "version_count",            # int    - total published versions
    "version_jump_suspicious",  # 0/1    - major >= 5 with <= 3 total versions
    "description_length",       # int    - length of package description
    "readme_length",            # int    - length of README file
]
```

**Note**: The extractors produce additional fields not used by the model: `account_age_days` (always NULL), `typosquat_target` (string, used to derive `is_typosquat`), `suspicious_phrase_count`, `has_placeholder_description`. These are stored in the DB but not in the feature vector.

---

## 7. Feature Extraction Details

### Code features (`dags/extractors/code_features.py`)

Scans all `.py`, `.js`, `.ts` files in the package (skipping node_modules, .git, __pycache__, dist, build).

- **entropy_max**: Slides a 200-character window across every source file, computes Shannon entropy for each window, returns the maximum. High entropy indicates obfuscation or base64 blobs.
- **has_network_in_install**: Checks `setup.py`, `setup.cfg`, `package.json` for network patterns (requests, urllib, http.client, socket, fetch, axios, http URLs).
- **has_credential_access**: Regex matches across all source for `.ssh/`, `.aws/credentials`, `.npmrc`, `.netrc`, and `os.environ`/`os.getenv` accessing TOKEN/SECRET/KEY/PASS variables.
- **has_obfuscated_code**: Matches `base64.b64decode`, `codecs.decode`, base64-like strings 80+ chars, or hex escape runs 10+ chars.
- **has_exec_eval**: Matches `eval(`, `exec(`, `__import__(`, `compile(`.
- **install_script_lines**: Counts newlines in setup.py + setup.cfg + package.json.
- **dangerous_import_count**: Counts how many of 13 dangerous modules appear: subprocess, socket, urllib, urllib2, urllib3, requests, http.client, ftplib, ctypes, cffi, pickle, marshal, importlib.
- **has_os_targeting**: Matches sys.platform, platform.system(), os.name, or OS string literals ('win32', 'linux', 'darwin').
- **has_external_payload**: Matches download-then-execute patterns: `urlretrieve/urlopen/requests.get` followed by `exec/eval/compile/__import__` within 300 chars (or reverse).
- **api_category_count**: Counts how many of 5 categories appear: network, file, process, encryption, execution.

### Metadata features (`dags/extractors/metadata_features.py`)

- **typosquat_target / typosquat_distance**: Uses `difflib.SequenceMatcher` to compare the normalized package name (lowered, hyphens/underscores/dots removed) against a hardcoded list of ~26 top PyPI and ~25 top npm packages. Threshold: 85% similarity ratio. Returns the closest match and its edit distance.
- **has_repo_link**: True if the package has a repository URL longer than 5 characters.
- **version_count**: Number of published versions (from registry metadata).
- **version_jump_suspicious**: True if the major version is >= 5 but only <= 3 versions were ever published.
- **account_age_days**: Always NULL. Requires registry auth to query and was never implemented.

### Text features (`dags/extractors/text_features.py`)

- **description_length**: Character length of the package description.
- **readme_length**: Character length of the README (checks README.md, .rst, .txt, README in that order).
- **suspicious_phrase_count**: Counts matches for 5 suspicious phrases: "unofficial fork/version/port", "drop-in replacement for", "compatible with <popular>", "faster <popular>", chained install commands.
- **has_placeholder_description**: True if description is in the set: empty, "todo", "fixme", "placeholder", "test", "my package", etc.

---

## 8. Training Data

Two data paths exist for building the labeled dataset:

### Path A: `scripts/build_dataset.py` (standalone, recommended)

Runs outside Docker, writes directly to PostgreSQL.

**Malicious sources (label=1)**:
- Clones `github.com/lxyeternal/pypi_malregistry` (~800 MB, depth=1) — verified malicious PyPI packages from ASE 2023 paper
- Processes ~10,000+ .tar.gz files in parallel (8 workers default)
- Label source: `pypi_malregistry`

**Benign sources (label=0)**:
- Top 2,000 PyPI packages by 30-day downloads (from hugovk.github.io API)
- ~100 hardcoded top npm packages
- Label sources: `top_pypi`, `top_npm`

Extracts all features inline using the same extractor code from `dags/extractors/`.

**Runtime**: 30-60 minutes. **Flags**: `--skip-clone`, `--malicious-only`, `--benign-only`, `--workers N`.

### Path B: `dags/label_dag.py` (Airflow, alternative)

One-shot DAG triggered manually in Airflow UI.

**Malicious sources**: DataDog malicious-software-packages-dataset manifest (both PyPI and npm). Downloads live copies from registries — many already removed, so yields fewer samples than Path A. Label source: `datadog`.

**Benign sources**: Top 500 PyPI + ~100 npm packages.

Does NOT extract features — only ingests raw archives. Requires `extract_dag` to run afterward.

### Final dataset (from Path A)

| Class | Count | Sources |
|-------|-------|---------|
| Benign (label=0) | ~1,992 | Top PyPI + top npm |
| Malicious (label=1) | ~11,348 used for training | pypi_malregistry |
| **Total** | **~13,340** | |

**Note**: The README states ~20,842 malicious from both pypi_malregistry + DataDog, but the model was actually trained on ~13,340 total (as shown in notebook metrics). The DataDog source via `label_dag.py` is a separate path.

---

## 9. Model

### Algorithm

XGBoost binary classifier (`XGBClassifier`).

### Hyperparameters

```python
n_estimators     = 300
max_depth        = 6
learning_rate    = 0.05
subsample        = 0.8
colsample_bytree = 0.8
scale_pos_weight = n_benign / n_malicious   # handles class imbalance
eval_metric      = "logloss"
random_state     = 42
n_jobs           = -1
```

### Training procedure

1. Load all labeled rows from `packages JOIN features WHERE label IS NOT NULL`
2. All NULLs coalesced to 0 (or 1 for version_count)
3. `is_typosquat` derived as: `CASE WHEN typosquat_target IS NOT NULL THEN 1 ELSE 0 END`
4. 80/20 stratified train/test split (random_state=42)
5. Fit with eval_set on test split
6. Compute precision, recall, F1, ROC-AUC on test set
7. Compute SHAP TreeExplainer values on test set
8. Log metrics, params, SHAP importance, classification report to MLflow
9. Register model in MLflow as `malicious-package-detector`
10. Auto-promote to `champion` alias if F1 >= current champion

### Reported performance (on 80/20 split)

| Metric | Value |
|--------|-------|
| Precision | 0.9995 |
| Recall | 0.9995 |
| F1 | 0.9995 |
| ROC-AUC | 0.9986 |

From notebook analysis:
- Benign mean score: 0.0123 (std 0.0815)
- Malicious mean score: 0.9787 (std 0.1130)
- False positives: ~16 (0.8% FPR)
- False negatives: ~139 (1.2% FNR)

### Model file

`model/champion.json` (206 KB) — bundled pre-trained model. The API loads this by default on startup. If a new champion is trained via MLflow, the API can fall back to MLflow's model registry.

---

## 10. REST API

**File**: `api/main.py` | **Port**: 8000 | **Framework**: FastAPI + Uvicorn

### Endpoints

**GET /api/health**
```json
{"status": "ok", "model_loaded": true}
```

**POST /api/score**
- Request body: `{"registry": "npm", "name": "package-name", "version": "1.0.0"}`
- Returns cached score if available, otherwise:
  1. Looks up features from PostgreSQL (package must already be ingested + extracted)
  2. Runs XGBoost predict_proba
  3. Computes SHAP values for this prediction
  4. Builds markdown report with top 5 SHAP contributors
  5. Persists score to `scores` table
  6. Returns score, risk_level, report_md, model_version, cached flag
- 404 if package not in DB
- 503 if model not loaded

**GET /api/report/{registry}/{name}/{version}**
- Returns previously computed score + SHAP values + report
- 404 if not scored yet

### Model loading priority
1. `model/champion.json` (bundled file, works out-of-box)
2. MLflow registry `models:/malicious-package-detector@champion` (fallback after retraining)

---

## 11. Airflow DAGs

| DAG ID | Schedule | Purpose |
|--------|----------|---------|
| `ingest_packages` | Every 15 min | Poll PyPI RSS + npm search for new packages, download archives to MinIO, upsert metadata to PostgreSQL |
| `extract_features` | Every 30 min | Pull pending packages (batch of 20), extract 17 features, write to features table |
| `train_model` | Weekly | Load labeled data, train XGBoost, log to MLflow, auto-promote champion |
| `score_packages` | Every 30 min | Load champion from MLflow, score unscored live packages (batch of 100), write SHAP reports |
| `build_labeled_dataset` | Manual trigger only | One-shot: ingest DataDog malicious + top-500 benign for training |

All DAGs use `max_active_runs=1` and `catchup=False`.

### DAG dependency chain

```
ingest_packages --> extract_features --> score_packages
                                     --> train_model (weekly, needs labeled data)
build_labeled_dataset (manual, one-time) --> extract_features --> train_model
```

---

## 12. Registry Clients

### PyPI (`dags/clients/pypi.py`)
- **get_recent_packages(limit)**: Parses PyPI RSS feed at `pypi.org/rss/updates.xml`. Extracts package name + version from `<item><title>` tags.
- **get_package_metadata(name)**: Hits `pypi.org/pypi/{name}/json`. Returns name, version, author, description, homepage, repository (from project_urls.Source), keywords, tarball_url (prefers sdist), version_count.
- User-Agent: `mlpro-scanner/1.0 (security research)`

### npm (`dags/clients/npm.py`)
- **get_recent_packages(limit)**: Hits `registry.npmjs.org/-/v1/search?text=&sort=modified&size=N`. Returns recently modified packages.
- **get_package_metadata(name)**: Hits `registry.npmjs.org/{name}`. Returns latest version metadata, tarball_url from dist.tarball, author, description, homepage, repository, keywords, version_count.

---

## 13. Storage Layer

### PostgreSQL (`dags/storage/db.py`)
- `get_conn()`: Context manager, auto-commits on success, rolls back on exception
- `upsert_package(pkg)`: INSERT ON CONFLICT (registry, name, version) DO UPDATE. Returns package id.
- `get_pending_packages(limit)`: SELECT where extraction_status='pending', ordered by ingested_at ASC
- `set_extraction_status(id, status)`: Simple UPDATE
- `upsert_features(package_id, features)`: INSERT ON CONFLICT (package_id) DO UPDATE all feature columns

### MinIO (`dags/storage/object_store.py`)
- Singleton `Minio` client (secure=False for internal Docker network)
- `upload_bytes(bucket, key, data)`: Put object
- `download_bytes(bucket, key)`: Get object, returns bytes
- `object_exists(bucket, key)`: stat_object, returns bool
- Three buckets: `packages` (raw archives), `features` (unused currently), `mlflow` (MLflow artifacts)

---

## 14. Grafana Dashboard

Pre-provisioned dashboard (`grafana/provisioning/dashboards/mlpro.json`) with 8 panels:

1. **Total Packages Scored** — stat panel, count from scores table
2. **High/Critical Risk** — stat panel with red threshold, count where risk_level in ('high','critical')
3. **Labeled Training Samples** — stat panel, count from packages where label is not null
4. **Live Packages Ingested** — stat panel, count where label is null
5. **Risk Distribution** — pie chart: low/medium/high/critical breakdown
6. **Scored Per Day** — time series, 7-day rolling
7. **Latest High/Critical** — table with score gauge and color-coded risk
8. **Dataset: Malicious vs Benign** — bar gauge

Datasource: PostgreSQL (`appuser@postgres:5432/packages`), auto-refreshes every 5 minutes.

---

## 15. Docker Build Details

### Dockerfile (Airflow)
- Base: `apache/airflow:2.9.3`
- Installs: requests, psycopg2-binary, minio, apache-airflow-providers-postgres, mlflow, xgboost, scikit-learn, shap, pandas, numpy, boto3

### Dockerfile.api
- Base: `python:3.11-slim`
- Installs: fastapi, uvicorn, mlflow[extras], xgboost, scikit-learn, shap, pandas, numpy, boto3, psycopg2-binary
- Copies: `api/`, `dags/` (for extractor imports), `model/` (for champion.json)
- CMD: `uvicorn main:app --host 0.0.0.0 --port 8000`

### Dockerfile.mlflow
- Base: `python:3.11-slim`
- Installs: mlflow, psycopg2-binary, boto3
- CMD: `mlflow server` with PostgreSQL backend + S3 artifact root
- Hardcoded: `postgresql+psycopg2://appuser:apppass@postgres/packages`

---

## 16. Startup Sequence

### Option A: Manual (README)
```bash
cp .env.example .env
docker compose up -d postgres minio minio-init     # wait for postgres healthy
docker compose up -d mlflow                          # wait for mlflow healthy
docker compose up -d airflow-init                    # wait for exit 0
docker compose up -d airflow-webserver airflow-scheduler grafana
docker compose up -d api                             # wait for "startup complete"
curl http://localhost:8000/api/health                # verify model loaded
```

### Option B: `start.sh`
Automates the above with health-check polling and colored output.

### Training from scratch
```bash
# Start the stack first (Postgres must be up)
python3 -m venv .venv && source .venv/bin/activate
pip install requests psycopg2-binary
DB_HOST=localhost python3 scripts/build_dataset.py   # 30-60 min
MLFLOW_TRACKING_URI=http://localhost:5000 \
MLFLOW_S3_ENDPOINT_URL=http://localhost:9000 \
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
DB_HOST=localhost python3 scripts/train_model.py     # ~2 min
```

---

## 17. Known Limitations and Honest Assessment

### Inflated metrics
The F1=0.9995 comes from an 80/20 split of a dataset where malicious samples are mass-generated typosquats with shared patterns. In production (where 99%+ of packages are benign), precision and recall would be significantly lower. No cross-validation is performed.

### Static analysis only
All features are extracted from source code text. No dynamic analysis (sandbox execution, syscall tracing). Encrypted payloads, runtime-only triggers, and multi-stage attacks will evade detection.

### Typosquatting detection is narrow
Only compares against ~50 hardcoded popular packages. Uses `difflib.SequenceMatcher` at 85% threshold. Misses homoglyph attacks, creative misspellings, or impersonation via description without name similarity.

### Class imbalance handling is basic
Only uses `scale_pos_weight`. No SMOTE, undersampling, probability calibration, or threshold tuning.

### Adversarial evasion is trivial
An attacker who knows the 17 features can defeat every one: add a README (readme_length), add a description (description_length), use a unique name (typosquat), encrypt payloads (entropy, obfuscation), use legitimate-looking imports. No adversarial training or robustness testing exists.

### account_age_days is never populated
Declared in the schema but always NULL. Would require registry API auth to implement.

### No tests
Zero test files exist. No unit tests, integration tests, or model validation tests.

### Hardcoded credentials everywhere
admin/admin, minioadmin/minioadmin, appuser/apppass. Fine for local dev. The MLflow Dockerfile hardcodes the database connection string.

### project-notes.md is outdated
Lists train_dag, score_dag, MLflow, SHAP, REST API as "not yet built" — they are all built now. The architecture diagram in that file is stale.

---

## 18. Improvement Opportunities

These are the areas where the project could be strengthened:

1. **Realistic evaluation**: Test on held-out recently published packages, not the same dataset distribution. Report precision@k at realistic base rates.
2. **Cross-validation**: 5-fold stratified CV with confidence intervals instead of single 80/20 split.
3. **Threshold tuning**: Analyze precision-recall curve to find optimal operating point (default 0.5 is almost certainly suboptimal).
4. **More benign data**: The ~10:1 malicious-to-benign ratio is inverted from reality. Add more benign packages.
5. **Dynamic features**: Sandbox execution to catch runtime-only malicious behavior.
6. **Better typosquatting**: Levenshtein distance, homoglyph detection, larger reference list.
7. **Feature ablation study**: Which features actually matter? Are some redundant?
8. **Adversarial testing**: Craft packages designed to evade detection, measure model robustness.
9. **Tests**: Unit tests for extractors, integration tests for DAGs, model regression tests.
10. **Security hardening**: Parameterize credentials, add TLS, restrict MinIO access.
