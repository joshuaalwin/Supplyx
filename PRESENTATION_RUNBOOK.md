# Presentation Runbook

Quick reference for screenshots, live demos, and Q&A. Read this in order on demo day.

## Pre-demo checklist

```bash
# Confirm everything is up
docker compose ps        # all services Up + healthy
curl -s http://localhost:8000/api/health   # {"status":"ok","model_loaded":true}
curl -s http://localhost:5000/api/2.0/mlflow/registered-models/list | python3 -m json.tool
PGPASSWORD=apppass psql -h localhost -p 15432 -U appuser -d packages -c "SELECT label, COUNT(*) FROM packages GROUP BY label;"
```

If anything is down:
```bash
docker compose up -d
until curl -sf http://localhost:8000/api/health | grep -q '"model_loaded":true'; do sleep 2; done
```

---

## Screenshots — capture order

### 1. System architecture (slide 6 backup)
- Browser: `file:///home/t3rminux/Desktop/UMD/ENPM604/Final-Project/Supplyx/system-design.html`
- Full-page screenshot

### 2. Airflow UI (slide 11)
- http://localhost:8080 (admin / admin)
- DAG list view — show 4 unpaused DAGs (ingest_packages, extract_features, score_packages, train_model) + paused `build_labeled_dataset`
- Click any DAG → graph view → screenshot

### 3. MLflow UI (slide 9)
- http://localhost:5000
- Experiments → `malicious-package-detection` → click the latest run
- Metrics panel (f1/precision/recall/roc_auc) — screenshot
- Models → `malicious-package-detector` → champion alias badge — screenshot

### 4. MinIO console
- http://localhost:9001 (minioadmin / minioadmin)
- Buckets: `packages`, `features`, `mlflow` — screenshot

### 5. Grafana
- http://localhost:3000 (admin / admin)
- Dashboard `MLPro` — screenshot. If empty, run a few `/api/score` calls first (see below) to populate the `scores` table.

### 6. FastAPI Swagger
- http://localhost:8000/docs
- Screenshot of the three endpoints expanded

### 7. Live `/api/score` response (slide 9 backup, slide 12)
- See "Live demo commands" below — capture the JSON response

### 8. SHAP plots (slide 9)
- Open `notebooks/model_demo.ipynb` in Jupyter
- Run all cells top-to-bottom
- Right-click each plot → save image:
  - Score distribution
  - Confusion matrix
  - SHAP bar
  - SHAP beeswarm
  - SHAP waterfall (malicious + benign)
- OR use the pre-rendered ones in `eval/`:
  - `eval/confusion_matrix.png`
  - `eval/roc_curve.png`
  - `eval/pr_curve.png`
  - `eval/shap_summary_bar.png`
  - `eval/shap_summary_beeswarm.png`
  - `eval/feature_distribution.png`

### 9. Evasion bar chart (slide 10)
- `eval/evasion_rate_v1_vs_v7.png` (from `scripts/eval_adversarial.py`)

### 10. Adversarial score-drop demo (slide 10)
- Run `.venv/bin/python scripts/demo_evasion.py` — screenshot the terminal output

---

## Live demo commands

### Score a known malicious package
```bash
curl -X POST http://localhost:8000/api/score \
  -H "Content-Type: application/json" \
  -d '{"registry":"pypi","name":"craftvirtual","version":"10.2"}' | jq
```
Expected: `risk_level: critical`, score > 0.8, SHAP report citing obfuscated code + dangerous imports.

### Score a benign package
```bash
curl -X POST http://localhost:8000/api/score \
  -H "Content-Type: application/json" \
  -d '{"registry":"pypi","name":"requests","version":"2.32.5"}' | jq
```
Expected: `risk_level: low`, score < 0.3.

### Fetch a cached report
```bash
curl -s http://localhost:8000/api/report/pypi/craftvirtual/10.2 | jq
```

---

## Slide 10 "score-drop" live demo (most impactful)

```bash
.venv/bin/python scripts/demo_evasion.py
```

Talking points while it runs:
1. "Here's a real malicious package — `craftvirtual`. v1 baseline flags it CRITICAL at 0.99."
2. "The attacker controls the metadata. They pad description_length from 0 to 120."
3. "v1's score drops to ~0.006 → classified LOW. The attack succeeded with **cosmetic** changes."
4. "v7-Robust doesn't even look at description_length. Score is unchanged. **The attack fails.**"

---

## Anticipated Q&A

**Q: How is `scale_pos_weight` computed?**
A: `n_benign / n_malicious`. In our case ~0.49 (≈5.4k/11k). XGBoost's documented imbalance knob — multiplies positive-class gradient contribution by that ratio.

**Q: How would you handle a model decay over time?**
A: `train_model` DAG runs weekly. F1-gated champion promotion in MLflow — new model only replaces champion if F1 ≥ current. Grafana panel watches risk-level distribution over time as drift signal.

**Q: What about evasion through changing the install behaviour (not just metadata)?**
A: That's a strictly harder attack — the adversary now has to ship code that LOOKS benign to our static patterns while still doing the malicious thing. We don't claim resistance to that. The slide 10 win is closing the trivial "pad your description" attack — which closed 100% bypass at v1.

**Q: What about novel features your patterns don't catch (e.g. Unicode confusables)?**
A: Fair. Our monotonic-constraint and feature-elimination work doesn't help against new attack classes — only against trivial evasion of known features. Future work: pre-install behavioural tracing.

**Q: Class imbalance — why benign so much smaller than malicious?**
A: That's the real-world distribution. PyPI/npm have ~600k benign packages but we only need a representative sample of typical behaviour. Verified-malicious datasets are smaller and harder to collect — pypi_malregistry took an ASE 2023 paper to curate.

**Q: How do you handle false positives?**
A: Precision 0.96+ at threshold 0.5. The threshold is tunable per deployment context. Security advisories use 0.8+ (only-flag-critical); CI/CD blockers might use 0.95+ to minimize developer friction.

---

## If something breaks during the demo

| Symptom | Quick fix |
|---|---|
| API returns 503 "Model not loaded" | `docker compose restart api` and wait 10s |
| API returns 404 on a package | Trigger ingest manually in Airflow OR pick a package we know is in DB |
| Grafana empty | Run `for p in craftvirtual selfpingrampep py-studyram; do curl -X POST http://localhost:8000/api/score -d "{\"registry\":\"pypi\",\"name\":\"$p\",\"version\":\"latest\"}" -H 'Content-Type: application/json'; done` (some may 404 but fine) |
| MLflow link broken | http://localhost:5000 (not :5000/mlflow) — older docs may say otherwise |
| PostgreSQL connect refused on `:5432` | We remapped to `:15432`. Use that. |
