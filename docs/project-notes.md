# ML-Powered Malicious Package Detection — Project Notes

## What this system does

Detects malicious packages on PyPI and npm by analyzing their code, metadata, and description text using ML. Instead of just flagging threats, it produces structured, explainable reports that tell users *why* a package is considered risky (SHAP-based feature attribution).

---

## How we know which packages are evil (ground truth)

**Positive class (malicious):**
- Packages already removed by PyPI/npm for malware
- OSV.dev malicious package advisories
- GitHub Advisory Database
- MalOSS dataset and Backstabber's Knife Collection (labeled research datasets)
- Phylum, Socket.dev, Checkmarx published reports

**Negative class (benign):**
- Top 5,000 most-downloaded packages on each registry with long track records

---

## Detection signals

### Code features
- High Shannon entropy strings → base64-encoded payloads, obfuscated code
- Network calls inside install scripts (`setup.py`, `postinstall`) → exfiltration on `pip install`
- Reading sensitive paths: `~/.ssh`, `~/.aws/credentials`, env vars with TOKEN/KEY/SECRET
- `eval()` / `exec()` on downloaded content → second-stage payload
- Subprocess calls in install hooks

### Metadata features
- New author account with no prior packages → throwaway account
- Package name edit-distance ≤ 2 from a popular package → typosquatting
- Version jumps (1.0 → 9.9 in one release) → faking maturity
- No linked repository, no maintainer

### Text features
- README copies another package's description verbatim
- Claims to be "unofficial fork of X" or "drop-in replacement for X"
- Empty or placeholder description

### Why ML instead of rules
Rules catch obvious cases. ML learns *combinations* — a new account alone is fine, network calls alone are fine, but `new account + network in install + reads ~/.aws + copies requests description` → high confidence malicious. XGBoost learns the decision boundary from labeled data; SHAP explains which features drove each individual prediction.

---

## Architecture

```
PyPI/npm APIs
    ↓  every 15 min  [ingest_dag]
MinIO (raw archives)  +  PostgreSQL (packages table, status=pending)
    ↓  every 30 min  [extract_dag]
code_features + metadata_features + text_features
    ↓
PostgreSQL (features table, status=done)
    ↓  weekly  [train_dag — NOT YET BUILT]
MLflow (XGBoost + text classifier, experiment tracking, model registry)
    ↓  on new packages  [score_dag — NOT YET BUILT]
SHAP values → Report Builder → structured JSON/Markdown report
    ↓
REST API (risk score + report)  +  Webhook alerts  +  Grafana dashboard
```

---

## Stack

| Component | Technology |
|---|---|
| Orchestration | Apache Airflow 2.9 (LocalExecutor) |
| Object store | MinIO (S3-compatible) |
| Database | PostgreSQL 15 |
| ML tracking | MLflow (not yet built) |
| Monitoring | Grafana |
| Explainability | SHAP (not yet built) |

---

## What is built (data pipeline)

### File structure
```
MLPro/
├── Dockerfile                        # extends apache/airflow:2.9.3
├── docker-compose.yml                # all services
├── requirements.txt
├── .env.example
├── init/
│   └── init_db.sql                   # packages + features schema
└── dags/
    ├── ingest_dag.py                 # DAG: polls PyPI + npm, stores archives
    ├── extract_dag.py                # DAG: runs 3 extractors, writes features
    ├── clients/
    │   ├── pypi.py                   # PyPI RSS + JSON API client
    │   └── npm.py                    # npm registry search + metadata client
    ├── storage/
    │   ├── db.py                     # PostgreSQL helpers (upsert, query)
    │   └── object_store.py           # MinIO upload/download
    └── extractors/
        ├── code_features.py          # entropy, install-script patterns, obfuscation
        ├── metadata_features.py      # typosquat detection, version analysis
        └── text_features.py          # description/README NLP signals
```

### Services
| Service | Port | Credentials |
|---|---|---|
| Airflow UI | 8080 | admin / admin |
| Grafana | 3000 | admin / admin |
| MinIO console | 9001 | minioadmin / minioadmin |
| PostgreSQL | 5432 | appuser / apppass (packages DB) |

### To start
```bash
cd ~/MLPro
cp .env.example .env
docker compose up --build
```
Enable both DAGs in the Airflow UI. `ingest_packages` runs every 15 min, `extract_features` runs every 30 min.

### Database schema
```
packages (id, registry, name, version, author, description, homepage,
          repository, keywords, downloads_last_month, object_key,
          ingested_at, extraction_status)

features (id, package_id, entropy_max, has_network_in_install,
          has_credential_access, has_obfuscated_code, has_exec_eval,
          install_script_lines, dangerous_import_count,
          account_age_days, typosquat_target, typosquat_distance,
          has_repo_link, version_count, description_length,
          readme_length, raw_features JSONB, extracted_at)
```

---

## What is NOT yet built

1. **MLflow integration** — model training DAG (weekly), experiment tracking, model registry (staging → prod)
2. **ML model** — XGBoost on structured features + text classifier on description/README
3. **SHAP explainability** — per-prediction feature attribution
4. **Score DAG** — batch scoring of extracted features against the trained model
5. **Report Builder** — structured JSON/Markdown report explaining *why* a package is risky
6. **REST API** — query endpoint for risk scores + reports
7. **Webhook alerts** — notify on high-risk packages
8. **Grafana dashboards** — model metrics (Precision/Recall/F1/AUC), drift detection, ops throughput
9. **account_age_days** — needs registry auth to query author's first publish date; currently NULL

---

## Next steps (in order)

1. Build the labeled training dataset (pull from OSV.dev + MalOSS, extract features for known-malicious packages)
2. Train baseline XGBoost model, track with MLflow
3. Add SHAP explanation layer
4. Build score DAG + report builder
5. Wire up Grafana dashboards
