# MLPro Presentation Narration — 5 Minutes

## Slide Order

| # | Slide | Speaker | Time |
|---|-------|---------|------|
| 1 | Title | Josh | 10s |
| 2 | Table of Contents | Josh | 10s |
| 3 | Threat Landscape (divider) | Josh | 3s |
| 4 | Supply Chain Attack Crisis | Josh | 40s |
| 5 | System Architecture (divider) | Josh | 3s |
| 6 | Pipeline Detail | Josh | 35s |
| 7 | Feature Engineering | Josh | 40s |
| 8 | Model & Hardening (divider) | Nimal | 3s |
| 9 | Model Performance + MLflow | Nimal | 35s |
| 10 | Confusion Matrix (screenshot) | Nimal | 15s |
| 11 | SHAP Feature Importance (screenshot) | Nimal | 15s |
| 12 | Adversarial Audit | Nimal | 35s |
| 13 | Adversarial Evasion (screenshot) | Nimal | 10s |
| 14 | Operations | Nimal | 20s |
| 15 | Grafana Dashboard (screenshot) | Nimal | 10s |
| 16 | Closing / Hero | Nimal | 10s |

**Josh: ~2:20 | Nimal: ~2:33**

---

## JOSH — Slides 1-7 (~2:20)

### Slide 1 — Title (10s)
"Hi everyone, I'm Josh, this is Nimal. We built MLPro — a real-time malicious package detector for PyPI and npm registries."

### Slide 2 — Table of Contents (10s)
"Quick roadmap: we'll cover the threat landscape, our system architecture and feature engineering, then Nimal walks you through model results and adversarial hardening."

### Slide 3 — Threat Landscape divider (3s)
"So first — why does this matter?"

### Slide 4 — Supply Chain Attack Crisis (40s)
"npm and PyPI see over 30 billion downloads a month across 600,000 packages — with zero identity verification and zero mandatory code review. Attackers exploit this through typosquatting, dependency confusion, and install hook hijacking. event-stream stole Bitcoin wallets from 8 million downloads. SolarWinds compromised 18,000 organizations. ua-parser-js deployed cryptominers to 7 million weekly users. The common thread — these were all flagged hours to days after publication. By then, millions of installs already happened. We wanted to catch them before that."

### Slide 5 — System Architecture divider (3s)
"Here's how we built it."

### Slide 6 — Pipeline Detail (35s)
"Four-stage microservices pipeline, fully containerized in Docker Compose. Ingestion polls PyPI and npm every 15 minutes, downloads archives into MinIO. Extraction runs three specialized extractors — code analysis with regex and AST patterns, metadata for typosquatting detection, and text features. Training runs weekly with XGBoost, tracked in MLflow with a champion model registry. Serving is a FastAPI REST API that returns a risk score with SHAP explanations — all persisted to Postgres and visualized in Grafana."

### Slide 7 — Feature Engineering (40s)
"We engineered 13 static features — all genuine behavioral signals. Eight code features: Shannon entropy for obfuscated payloads, network calls in install hooks, credential harvesting patterns, exec/eval usage, obfuscation detection, OS-targeting, external payload fetching, and install script length. Three metadata features: typosquat flag, Levenshtein distance to popular packages, and suspicious version jumps. Plus two aggregate counts — dangerous imports and API category usage. We originally had 17 features, but our adversarial audit exposed 4 as collection artifacts — description length, readme length, repo link, and version count. Removing them dropped our F1 from 99.9% to an honest 90.1%, but made the model actually robust. Nimal will show you why that matters."

*Hand off to Nimal*

---

## NIMAL — Slides 8-16 (~2:33)

### Slide 8 — Model & Hardening divider (3s)
"Thanks Josh. Let me show you what the model actually achieves."

### Slide 9 — Model Performance (35s)
"Our champion model is v7-Robust — XGBoost with 400 trees, 13 features, and monotonic constraints on every feature. F1 score of 0.9013, precision at 97.7% — meaning when we flag a package as malicious, we're right 97.7% of the time. That's critical in security contexts where false positives cause alert fatigue. Recall is 83.7%, ROC-AUC is 0.9175. Trained on 16,127 labeled packages — about 10,900 malicious and 5,200 benign — with scale_pos_weight handling the class imbalance. On the right you can see our MLflow registry tracking the champion model."

### Slide 10 — Confusion Matrix screenshot (15s)
"Here's the confusion matrix on our test set. 1,836 true positives, 988 true negatives, only 44 false positives and 358 false negatives. The model is strongly biased toward precision — we'd rather miss a few than cry wolf."

### Slide 11 — SHAP Feature Importance screenshot (15s)
"SHAP analysis shows what drives predictions. The top three features are api_category_count, has_obfuscated_code, and dangerous_import_count — all genuine behavioral signals. No collection artifacts, no gameable metadata."

### Slide 12 — Adversarial Audit (35s)
"This is where it gets interesting. We ran a greedy L-zero perturbation attack — the adversary knows our feature set and tries to flip features one at a time to drop below our detection threshold. Our original v1 model had a 99.8% evasion rate. Just padding description length from 0 to 120 characters dropped scores from 0.99 to 0.01 — a complete bypass with zero functional changes to the malicious code. That's because v1 learned a spurious correlation: malicious packages collected post-removal had empty descriptions, so the model learned 'no description equals malicious.' We fixed this in three steps: eliminated the 4 collection-artifact features, enforced monotonic constraints so attackers can't reduce risk by increasing any feature, and the result — v7-Robust has a 0% evasion rate on the text-padding attack. 100% attack surface reduction."

### Slide 13 — Adversarial Evasion screenshot (10s)
"Here's the comparison — v1 at 99.8% evasion versus v7 at 0%. The metadata-claim attack is also near zero for both models."

### Slide 14 — Operations (20s)
"The whole system runs as a Docker Compose stack — five Airflow DAGs orchestrating ingestion, extraction, scoring, and retraining. Three REST API endpoints: POST score for on-demand scoring with SHAP explanations, GET report for cached results, and a health check. All backed by PostgreSQL, MinIO for artifact storage, and MLflow for model versioning."

### Slide 15 — Grafana Dashboard screenshot (10s)
"And here's our Grafana observability dashboard — live model metrics, SHAP feature rankings, adversarial test results, score distributions, and a risk level breakdown. Everything updates in real time as packages are scored."

### Slide 16 — Closing / Hero (10s)
"To wrap up — 16,000 training packages, 13 hardened features, F1 of 0.90, 97.7% precision, and 100% attack surface reduction. Production-ready and adversarially hardened. Happy to take questions."

---

## Quick Reference — Key Numbers

| Metric | Value |
|--------|-------|
| F1 | 0.9013 |
| Precision | 0.9766 (97.7%) |
| Recall | 0.8368 |
| ROC-AUC | 0.9175 |
| Features | 13 (was 17, 4 eliminated) |
| Training set | 16,127 (10,968 mal + 5,159 ben) |
| scale_pos_weight | 0.4704 |
| v1 text-padding evasion | 99.8% |
| v7 text-padding evasion | 0.0% |
| Attack reduction | 100% |
| Confusion: TP/TN/FP/FN | 1836 / 988 / 44 / 358 |

## Q&A Prep — Likely Questions

**"Why not use deep learning?"**
> Static features + XGBoost gives us interpretability via SHAP. Security analysts need to know *why* something was flagged, not just that it was. Also, our feature set is 13 dimensions — deep learning would overfit.

**"What about false negatives?"**
> 358 FN out of 2,194 malicious in test set (16.3% miss rate). These are mostly packages with minimal behavioral signals — no obfuscation, no install hooks. We'd need dynamic analysis (sandboxing) to catch those, which is future work.

**"How do you handle new attack techniques?"**
> Weekly retraining on newly labeled packages. Monotonic constraints ensure the model can't be tricked by adding "legitimate-looking" features. The feature set itself targets fundamental attack behaviors that are hard to avoid.

**"What's the latency for scoring?"**
> Sub-second. XGBoost inference + SHAP explanation is ~50ms. The API caches results so repeat queries are instant.

**"Why did you remove those 4 features?"**
> They were collection artifacts — malicious packages were scraped after removal from registries, so they systematically had empty descriptions and no repo links. The model learned "empty metadata = malicious" which any attacker can trivially defeat by adding a fake description.
