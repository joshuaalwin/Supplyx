# MLPro - Real-time malicious package detection for PyPI and npm

MLPro catches malicious packages on PyPI and npm before they reach downstream users. It trains an XGBoost classifier on 13 static behavioral signals pulled from raw package archives and returns SHAP explanations with every prediction, so you know *why* something got flagged, not just that it did.

The whole thing runs in Docker Compose: ingestion, feature extraction, training, scoring, and a REST API that hands back risk assessments with readable security reports. A pre-trained model ships in the repo. You can start scoring packages without training anything.

<p align="center">
  <img src="https://github.com/joshuaalwin/Supplyx/releases/download/screenshots/ML-ArchiDiagram-Light.png" alt="Supplyx System Architecture" width="900"/>
</p>

---

## Table of contents

- [Why this matters](#why-this-matters)
- [How MLPro would have caught real attacks](#how-mlpro-would-have-caught-real-attacks)
- [How it works](#how-it-works)
- [Results](#results)
- [Adversarial hardening](#adversarial-hardening)
- [Installation](#installation)
- [Usage](#usage)
- [The 13 features](#the-13-features)
- [Architecture](#architecture)
- [Screenshots](#screenshots)
- [Dataset](#dataset)
- [Retraining](#retraining)
- [Contributing](#contributing)

---

## Why this matters

PyPI and npm serve over 30 billion downloads per month across 600,000+ packages. There is no identity verification, no mandatory code review, and no automated malware scanning at upload time.

Attackers exploit this through:

- **Typosquatting** - Publishing packages with names close to popular ones (`reqeusts` instead of `requests`), hoping developers mistype during install
- **Dependency confusion** - Registering internal package names on public registries so build systems pull the attacker's version
- **Install hook hijacking** - Hiding malicious code in `setup.py` or `postinstall` scripts that runs automatically on `pip install` or `npm install`

Today's defense is reactive. Packages get flagged hours to days after publication, only after a researcher notices or a user reports it. By then, millions of installs may have already happened.

MLPro moves detection to the point of ingestion. It analyzes packages in real time using behavioral signals that are hard to strip out without removing the malicious functionality itself.

---

## How MLPro would have caught real attacks

### event-stream (2018), 8M+ downloads
A maintainer handed off control of a popular npm library to an attacker, who injected code targeting Bitcoin wallet credentials. The payload was hidden in a dependency, but MLPro's credential access, obfuscation, and version-jump features would have caught it at publish time.

### ua-parser-js (2021), 7M weekly downloads
The attacker compromised a maintainer's npm account and pushed versions with cryptominers and credential harvesters. Three MLPro features fire here: external payload download (fetching binaries from remote servers), OS-targeting (platform-conditional execution), and network calls in install hooks.

### SolarWinds SUNBURST (2020), 18,000+ organizations
This was a build-system compromise, not a registry attack, but the injected code carries patterns MLPro detects: high-entropy payloads (obfuscated C2 communication), credential harvesting, and external payload fetching. Applied to internal package feeds, a system like this could catch similar injections.

### colors/faker (2022), 20M+ weekly downloads
A maintainer intentionally sabotaged their own packages by adding infinite loops. The version jump from stable releases to the sabotaged ones, plus the obfuscated code patterns, would trip MLPro's detector.

---

## How it works

MLPro is a four-stage pipeline orchestrated by Apache Airflow:

**1. Ingestion (every 15 minutes)**
Polls the PyPI and npm APIs for new packages, downloads their archives, and stores them in MinIO (S3-compatible object storage). Package metadata goes to PostgreSQL.

**2. Feature extraction (every 30 minutes)**
Three extractors run against raw package archives:
- **Code extractor** - Scans source files with regex and AST patterns for 8 behavioral signals (obfuscation, credential access, network exfiltration, exec/eval usage, etc.)
- **Metadata extractor** - Checks for typosquatting against the top 5,000 PyPI packages using Levenshtein distance, and flags suspicious version jumps
- **Text extractor** - Originally extracted description and readme lengths, but these were cut after adversarial auditing showed them to be collection artifacts

All 13 features are written to PostgreSQL.

**3. Training (weekly)**
XGBoost trains on 16,127 labeled packages with 400 trees, monotonic constraints on every feature, and SHAP TreeExplainer for interpretability. Models are tracked in MLflow with a champion registry. If a new model beats the current champion's F1, it gets promoted automatically.

**4. Scoring (every 30 minutes + on-demand API)**
The champion model scores unscored packages, generates SHAP explanations for what drove the prediction, assigns a risk level (critical/high/medium/low), and writes everything to PostgreSQL. A FastAPI REST API provides on-demand scoring with full security reports.

---

## Results

The champion model (v7-Robust) on a held-out test set of 3,226 packages:

| Metric | Value |
|--------|-------|
| F1 Score | 0.9013 |
| Precision | 0.9766 (97.7%) |
| Recall | 0.8368 (83.7%) |
| ROC-AUC | 0.9175 |
| Accuracy | 87.5% |

<p align="center">
  <img src="https://github.com/joshuaalwin/Supplyx/releases/download/screenshots/screenshot_confusion_matrix.png" alt="Confusion Matrix" width="450"/>
</p>

Confusion matrix breakdown:
- 1,836 true positives (malicious correctly flagged)
- 988 true negatives (benign correctly cleared)
- 44 false positives (benign incorrectly flagged)
- 358 false negatives (malicious missed)

The model is tuned for precision. When MLPro flags a package, it is correct 97.7% of the time. That matters in security contexts where false positives cause alert fatigue and erode analyst trust.

<p align="center">
  <img src="https://github.com/joshuaalwin/Supplyx/releases/download/screenshots/screenshot_roc.png" alt="ROC Curve" width="400"/>
  <img src="https://github.com/joshuaalwin/Supplyx/releases/download/screenshots/screenshot_pr.png" alt="Precision-Recall Curve" width="400"/>
</p>

### Feature importance (SHAP)

SHAP TreeExplainer shows which features drive predictions. The top three are `api_category_count`, `has_obfuscated_code`, and `dangerous_import_count`, all behavioral signals that an attacker can't trivially fake.

<p align="center">
  <img src="https://github.com/joshuaalwin/Supplyx/releases/download/screenshots/screenshot_shap_bar.png" alt="SHAP Feature Importance" width="500"/>
</p>

<p align="center">
  <img src="https://github.com/joshuaalwin/Supplyx/releases/download/screenshots/screenshot_shap_beeswarm.png" alt="SHAP Beeswarm" width="500"/>
</p>

---

## Adversarial hardening

Detection is table stakes. The real question is what happens when someone actively tries to evade the model.

### The problem

We ran a greedy L0 perturbation attack against our models. The adversary knows the full feature set and flips features one at a time to drop below the detection threshold (score < 0.3).

Our original v1 model had a 99.8% evasion rate. Just padding `description_length` from 0 to 120 characters dropped scores from 0.99 to 0.01. A complete bypass, zero changes to the actual malicious code.

Why? The malicious training data (pypi_malregistry) was collected *after* packages were removed from PyPI. Removed packages systematically had empty descriptions, no repository links, and single version counts. So the model learned "empty metadata = malicious" instead of "malicious behavior = malicious." These are collection artifacts, not threat signals.

### The fix

1. **Feature elimination** - Removed 4 collection-artifact features: `description_length`, `readme_length`, `has_repo_link`, `version_count`
2. **Monotonic constraints** - Enforced on all 13 remaining features so attackers cannot reduce risk by increasing any behavioral signal
3. **Retrained on behavioral signals only** - The model now relies on code behavior and structural metadata, nothing else

### The result

| Attack Type | v1 Baseline | v7-Robust |
|-------------|-------------|-----------|
| Text-padding (description/readme) | 99.8% evasion | 0.0% evasion |
| Metadata-claim (fake repo/versions) | 0.0% evasion | 0.2% evasion |
| Combined | 99.8% evasion | 0.2% evasion |

100% attack surface reduction on the primary evasion vector. F1 dropped from 99.9% to 90.1%, but the 99.9% was dishonest. It relied on features any attacker could defeat by adding a fake description.

<p align="center">
  <img src="https://github.com/joshuaalwin/Supplyx/releases/download/screenshots/screenshot_adversarial.png" alt="Adversarial Evasion Rates" width="500"/>
</p>

<p align="center">
  <img src="https://github.com/joshuaalwin/Supplyx/releases/download/screenshots/screenshot_score_drop_demo.png" alt="Score Drop Demo" width="500"/>
</p>

---

## Installation

### Prerequisites

- Docker and Docker Compose
- Git
- 4 GB free disk space

### Quick start

```bash
# Clone the repository
git clone https://github.com/joshuaalwin/Supplyx.git
cd Supplyx

# Create environment file
cp .env.example .env

# Start infrastructure (Postgres, MinIO)
docker compose up -d postgres minio minio-init
sleep 20

# Start MLflow (model registry)
docker compose up -d mlflow
sleep 15

# Initialize Airflow (one-time setup)
docker compose up -d airflow-init
# Wait for exit code 0
docker compose ps airflow-init

# Start all remaining services
docker compose up -d airflow-webserver airflow-scheduler grafana api
```

### Verify installation

```bash
# Check all containers are running
docker compose ps

# Test the API
curl http://localhost:8000/api/health
# {"status":"ok","model_loaded":true}
```

### Service endpoints

| Service | URL | Credentials |
|---------|-----|-------------|
| REST API | http://localhost:8000/docs | None |
| Airflow | http://localhost:8080 | admin / admin |
| MLflow | http://localhost:5000 | None |
| Grafana | http://localhost:3000 | admin / admin |
| MinIO Console | http://localhost:9001 | minioadmin / minioadmin |
| PostgreSQL | localhost:15432 | appuser / apppass (db: packages) |

### Stopping

```bash
docker compose down        # Stop containers, keep data
docker compose down -v     # Stop and delete all data (full reset)
```

---

## Usage

### Score a package

```bash
curl -X POST http://localhost:8000/api/score \
  -H "Content-Type: application/json" \
  -d '{"registry":"pypi","name":"craftvirtual","version":"10.2"}'
```

Response:

```json
{
  "score": 0.9847,
  "risk_level": "critical",
  "report_md": "## Security Report\n- api_category_count raises risk (+2.14)\n- has_obfuscated_code raises risk (+1.89)...",
  "model_version": "3",
  "cached": false
}
```

Risk levels: `low` (< 0.3), `medium` (0.3-0.6), `high` (0.6-0.8), `critical` (>= 0.8)

### Retrieve a cached report

```bash
curl http://localhost:8000/api/report/pypi/craftvirtual/10.2
```

### Airflow DAGs

Four automated DAGs run on schedule:

| DAG | Schedule | Purpose |
|-----|----------|---------|
| `ingest_packages` | Every 15 min | Poll PyPI/npm, download archives |
| `extract_features` | Every 30 min | Run extractors, write features to DB |
| `score_packages` | Every 30 min | Score unscored packages with SHAP |
| `train_model` | Weekly | Retrain XGBoost, promote if improved |

---

## The 13 features

Every feature has a monotonic constraint, which prevents the model from learning exploitable correlations. Each feature can only push risk in one direction.

| # | Feature | Constraint | What it detects |
|---|---------|-----------|-----------------|
| 1 | `entropy_max` | +1 | Base64/obfuscated payloads (Shannon entropy > 5.5 bits/byte) |
| 2 | `has_network_in_install` | +1 | Network calls during pip install (exfiltration) |
| 3 | `has_credential_access` | +1 | Reads ~/.aws, ~/.ssh, environment tokens |
| 4 | `has_exec_eval` | +1 | eval()/exec() co-located with decode or download calls |
| 5 | `has_obfuscated_code` | +1 | Long base64 strings, hex-encoded payloads, PowerShell -EncodedCommand |
| 6 | `has_os_targeting` | +1 | Platform-conditional execution gating a suspicious payload |
| 7 | `has_external_payload` | +1 | Downloads and executes a remote file in one operation |
| 8 | `install_script_lines` | +1 | Abnormally long install hooks |
| 9 | `dangerous_import_count` | +1 | ctypes, cffi, marshal, or network imports in install scripts |
| 10 | `api_category_count` | +1 | Combinations of shell/exfil/dynamic-exec/persistence APIs |
| 11 | `is_typosquat` | +1 | Package name within 2 edits of a top-5000 package |
| 12 | `typosquat_distance` | 0 | Levenshtein distance to closest popular package (0 = on the list) |
| 13 | `version_jump_suspicious` | +1 | Version jumped from 0.x to 9.x (version spoofing) |

### Eliminated features (post-audit)

Four features were removed after two rounds of adversarial auditing:

Round 1: `description_length` and `readme_length` were collection artifacts. Malicious packages scraped post-removal had empty descriptions, so the model learned a spurious correlation that any attacker could beat by adding a fake description.

Round 2: `has_repo_link` and `version_count` showed near-perfect separation (92.5% vs 0% repo links; avg 88 vs 1 version count) but were trivially evadable. An attacker can just claim a fake repository URL in setup.py.

---

## Architecture

```
PyPI / npm APIs
      |  every 15 min         [Airflow: ingest_packages]
      v
MinIO (raw archives) + PostgreSQL (packages table)
      |  every 30 min         [Airflow: extract_features]
      v
3 Extractors (Code + Metadata + Text) -> PostgreSQL (features table)
      |  weekly                [Airflow: train_model]
      v
XGBoost (13 features, monotonic) -> MLflow Registry (champion model)
      |  every 30 min         [Airflow: score_packages]
      v
SHAP Explanations -> PostgreSQL (scores table)
      |
      v
FastAPI :8000 (REST API)  +  Grafana :3000 (ML Dashboard)
```

### Tech stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Orchestration | Apache Airflow | DAG scheduling and monitoring |
| Model Training | XGBoost + SHAP | Classification with explainability |
| Model Registry | MLflow | Experiment tracking and champion management |
| Object Storage | MinIO | S3-compatible archive and artifact storage |
| Database | PostgreSQL | Packages, features, scores, model metrics |
| API | FastAPI | On-demand scoring with SHAP reports |
| Dashboard | Grafana | 32-panel ML observability dashboard |
| Deployment | Docker Compose | 7 containers, single-command startup |

---

## Screenshots

### Grafana ML dashboard

<p align="center">
  <img src="https://github.com/joshuaalwin/Supplyx/releases/download/screenshots/Grafana-1.png" alt="Grafana Dashboard - Model Performance" width="800"/>
</p>

<p align="center">
  <img src="https://github.com/joshuaalwin/Supplyx/releases/download/screenshots/Grafana-2.png" alt="Grafana Dashboard - Scoring and Risk" width="800"/>
</p>

### Airflow DAGs

<p align="center">
  <img src="https://github.com/joshuaalwin/Supplyx/releases/download/screenshots/Airflow-DAGs.png" alt="Airflow DAGs" width="800"/>
</p>

### MLflow model registry

<p align="center">
  <img src="https://github.com/joshuaalwin/Supplyx/releases/download/screenshots/MLFlow-Screenshots.png" alt="MLflow Model Registry" width="800"/>
</p>

### Feature distributions

<p align="center">
  <img src="https://github.com/joshuaalwin/Supplyx/releases/download/screenshots/screenshot_feature_distribution.png" alt="Feature Distributions - Malicious vs Benign" width="700"/>
</p>

### Score distribution

<p align="center">
  <img src="https://github.com/joshuaalwin/Supplyx/releases/download/screenshots/screenshot_score_dist.png" alt="Score Distribution" width="500"/>
</p>

---

## Dataset

The model was trained on 16,127 labeled packages from two publicly available sources:

| Class | Source | Count |
|-------|--------|-------|
| Malicious | [pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) - verified malicious packages removed by PyPI | 10,968 |
| Benign | Top 5,000 PyPI packages by download count | ~4,659 |
| Benign | Top 500 npm packages by download count | ~500 |

The dataset is not included in the repo (1.2 GB). To build it:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install requests psycopg2-binary mlflow xgboost scikit-learn shap pandas numpy boto3

# Postgres must be running
DB_HOST=localhost DB_PORT=15432 DB_NAME=packages DB_USER=appuser DB_PASS=apppass \
  python3 scripts/build_dataset.py
```

Build time is around 30-60 minutes depending on network speed.

---

## Retraining

After building the dataset:

```bash
source .venv/bin/activate

MLFLOW_TRACKING_URI=http://localhost:5000 \
MLFLOW_S3_ENDPOINT_URL=http://localhost:9000 \
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
DB_HOST=localhost DB_PORT=15432 DB_NAME=packages DB_USER=appuser DB_PASS=apppass \
  python3 scripts/train_model.py
```

Training takes about 2 minutes. If the new model's F1 beats the current champion, it gets promoted automatically.

To deploy the new model to the API:

```bash
MLFLOW_TRACKING_URI=http://localhost:5000 \
MLFLOW_S3_ENDPOINT_URL=http://localhost:9000 \
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
  python3 -c "
import mlflow
mlflow.set_tracking_uri('http://localhost:5000')
m = mlflow.xgboost.load_model('models:/malicious-package-detector@champion')
m.save_model('model/champion.json')
print('Model exported')
"

docker compose up -d --build api
```

### Evaluation scripts

```bash
# Generate metrics, ROC/PR curves, confusion matrix, SHAP plots
python3 scripts/eval_model.py

# Run adversarial evasion tests (v1 vs v7)
python3 scripts/eval_adversarial.py

# Live demo of v1 score collapse vs v7 robustness
python3 scripts/demo_evasion.py

# Publish metrics to Postgres for Grafana dashboard
python3 scripts/publish_metrics.py
```

---

## Jupyter notebook

For interactive exploration of the model, SHAP plots, and scoring:

```bash
source .venv/bin/activate
pip install jupyter matplotlib

jupyter notebook notebooks/model_demo.ipynb
```

A separate notebook (`notebooks/ml_screenshots.ipynb`) generates all presentation-quality plots.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## Authors

- Joshua Alwin - [GitHub](https://github.com/joshuaalwin)
- Nimal Kurien Thomas

ENPM604, Software Project Management, University of Maryland, May 2026

---

## License

This project is for academic purposes as part of ENPM604 at the University of Maryland.
