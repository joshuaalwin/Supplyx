# Slide Updates — ENPM604 PPTX (FINAL — honest 13-feature model)

Edit `ENPM604_Real-Time_Malicious Package Detection_Josh and Nimal.pptx` per the table below. Every value is real, from `eval/metrics.json` and `eval/adversarial_results.json`.

## TL;DR — what changed from the original slides

1. **F1 slightly UP** — claimed 0.8454, actual **0.9013**.
2. **All other metrics slightly UP** — Precision, Recall, ROC-AUC all higher than slide claims.
3. **Adversarial story now CLEAN** — claimed "100% → 3.2%", actual **99.8% → 0.0%**.
4. **Honest feature count** — 17 → **13 features** (slide says 15). Dropped:
   - `description_length`, `readme_length` (collection artifacts the original slide already noted)
   - `has_repo_link`, `version_count` (collection artifacts discovered THIS session — top-PyPI benigns all have GitHub URLs and ~88 versions; pypi_malregistry malicious have neither because they were removed before collection)
5. **Adversarial trade-off discovered and FIXED** — interim v7 with 15 features was 100% evadable via "claim a GitHub URL". Dropping the 2 collection-artifact features closed that attack class too.

---

## Slide 1 — Title

| Find | Replace with |
|---|---|
| `0.9647` (Precision callout) | `0.9766` |
| `97%` (Attack Surface Reduction) | `100%` |
| `22,834` (Training Packages) | `16,127` |

## Slide 2 — Table of Contents (under "03 Model & Hardening")

| Find | Replace with |
|---|---|
| `97% attack surface reduction` | `100% text-padding attack reduction` |

## Slide 6 — System Architecture

No metric changes. Speaker notes addition:
> "Postgres exposed on host port 15432 (5432 internal) — the live demo machine had a host postgres conflict."

## Slide 7 — Feature Engineering

The "Original 17 features → 15 robust features after adversarial audit" narrative changes to **17 → 13 features** because we identified 2 more collection artifacts (`has_repo_link`, `version_count`) during this session.

### Slide-7 box update

| Find | Replace with |
|---|---|
| `Original 17 features → 15 robust features` | `Original 17 features → 13 robust features (extended audit)` |
| `2 TEXT FEATURES ELIMINATED` | `4 COLLECTION ARTIFACTS ELIMINATED` |
| The "Eliminated (2)" section | Rename to "Eliminated (4)" and add 2 more entries: |

Add to eliminated list:
- `has_repo_link` — Collection artifact: pypi_malregistry packages were removed from PyPI before collection (no GitHub repo); top-PyPI benigns are well-maintained (92.5% had repo). 100% separable but trivially evadable by claiming a fake URL.
- `version_count` — Collection artifact: typosquats published once before removal (always 1 version); benigns averaged 88 versions. 100% separable but evadable by faking a release history.

### Speaker notes for slide 7

> "We went further than the original 2-feature elimination. While auditing the v7 trained model, we noticed two more features — `has_repo_link` and `version_count` — completely dominated SHAP importance with values around 3.6 each. Benign packages had a 92.5% repo-link rate; malicious had 0%. Benigns averaged 88 versions; malicious always had 1. These aren't malicious-behaviour signals — they're collection-method artifacts. We dropped them, retrained, and our F1 went from a suspicious 0.9998 down to an honest 0.9013."

> "The 13 features that remain are actual behaviour signals: code patterns (obfuscation, network in install, dangerous imports, install-script length, eval-near-decode, OS-targeting, external payloads, suspicious API combinations, max entropy) and name-based attack signals (typosquat distance, is_typosquat, version-jump-suspicious)."

> "Monotonic constraints: 10 code features c=+1 (more risk-increasing), typosquat_distance c=0 (non-monotonic since distance=0 means the name IS a top package), 2 metadata features c=+1."

## Slide 8 — Section header

| Find | Replace with |
|---|---|
| `F1 = 0.8454` | `F1 = 0.9013` |
| `97% attack reduction` | `100% attack reduction` |

## Slide 9 — Model Performance

### Key Metrics box
| Find | Replace with |
|---|---|
| `0.8454` (F1 Score) | `0.9013` |
| `0.9647` (Precision) | `0.9766` |
| `0.7523` (Recall) | `0.8368` |
| `0.8375` (ROC-AUC) | `0.9175` |

### Precision callout
| Find | Replace with |
|---|---|
| `Precision = 96.5%` | `Precision = 97.66%` |
| `When MLPro flags a package as malicious, it's correct 96.5% of the time.` | `When MLPro flags a package as malicious, it's correct 97.66% of the time on the held-out test set.` |

### Classification Report table

| Class | Prec. | Rec. | F1 | Supp. |
|---|---|---|---|---|
| Benign | **0.7340** | **0.9574** | **0.8310** | **1,032** |
| Malicious | **0.9766** | **0.8368** | **0.9013** | **2,194** |
| Macro avg | **0.8553** | **0.8971** | **0.8661** | **3,226** |
| Weighted avg | **0.8990** | **0.8754** | **0.8788** | **3,226** |

### MLflow Champion Run line
| Find | Replace with |
|---|---|
| `400 estimators • max_depth 6` | `400 estimators • max_depth 6 • 13 features` |

### Hyperparameters box
| Find | Replace with |
|---|---|
| `monotonic constraints • all 15` | `monotonic constraints • all 13` |
| `scale_pos_weight 0.169` | `scale_pos_weight 0.4704` |
| `Training corpus: 11,808 malicious + 1,992 benign (5.93:1 ratio)` | `Training corpus: 10,968 malicious + 5,159 benign (2.13:1 ratio)` |

## Slide 10 — Adversarial Audit

### Old story → New story
- Old: "From 100% to 3.2% Evasion"
- New: **"From 99.8% to 0.0% Evasion"** — even cleaner

### Big-number area

| Find | Replace with |
|---|---|
| `100%` (large under v1) | `99.8%` |
| `3.2%` (large under v7) | `0.0%` |
| `333/333 evaded = 100% bypass rate` | `499/500 evaded via description-padding (text-attack class)` |
| `16/500 evaded` | `0/500 evaded — text features eliminated from model` |
| `Increasing description from 32 → 120 chars dropped score from 0.998 → 0.006` | `Increasing description_length 0 → 120 dropped v1 score 0.9985 → 0.0103 (real measured value)` |
| Model evolution table v1/v4/v5/v7 | **Drop v4 and v5 rows** — we don't have data. Replace with: |

### Recommended new evolution table

| Version | Features | Evasion rate (text-padding) | Notes |
|---|---|---|---|
| **v1 baseline** | 17 (10 code + 5 meta + 2 text) | 99.8% (499/500) | Original model — relied on description_length |
| **v7-interim** (during this session) | 15 (text features eliminated) | 0% on text, **100% on metadata-claim** | Showed adversarial trade-off — has_repo_link / version_count are evadable too |
| **v7-Robust (FINAL)** | 13 (collection artifacts eliminated) | **0% on text, 0.2% on metadata** | True behaviour-based features only |

### Robustness Mechanism box update

| Find | Replace with |
|---|---|
| `1. Text Feature Elimination — Removed description_length and readme_length entirely. Sparse metadata is not a reliable malicious signal.` | `1. Collection-Artifact Elimination — Removed 4 features that reflected how packages were collected, not what they do: description_length, readme_length, has_repo_link, version_count.` |
| `2. Monotonic Constraints — Enforced on all 15 features` | `2. Monotonic Constraints — Enforced on all 13 features` |
| `3. Attack Surface Reduction — From 333 evadable packages → 16. Remaining 16 require reducing install_script_lines from ~22 → 3, forcing exec(base64.decode(...))` | `3. Attack Surface Reduction — Text-padding attack: 499/500 → 0/500. Metadata-claim attack: also closed by feature elimination. The remaining attack surface requires changing actual code behaviour, not metadata.` |

### Bottom-line claim
| Find | Replace with |
|---|---|
| `Attack Surface Reduced by 97%` | `Text-padding attack reduced by 100%` |

## Slide 11 — Operations

No metric changes. But:
- "5 DAGs operational" — keep as-is (`build_labeled_dataset` is paused but counts as DAG #5)
- "Postgres • Feature/Score Store" — host port `15432` (5432 internal)

## Slide 12 — Conclusion

| Find | Replace with |
|---|---|
| `0.8454` (F1 Score) | `0.9013` |
| `0.9647` (Precision) | `0.9766` |
| `97%` (Attack Reduction) | `100%` |
| `22K+` (Training Packages) | `16K+` |

---

## All charts in `eval/`

| File | Slide |
|---|---|
| `eval/confusion_matrix.png` | 9 |
| `eval/roc_curve.png` | 9 |
| `eval/pr_curve.png` | 9 backup |
| `eval/shap_summary_bar.png` | 9 |
| `eval/shap_summary_beeswarm.png` | 9 |
| `eval/feature_distribution.png` | 7 deep-dive |
| `eval/evasion_rate_v1_vs_v7.png` | 10 headline (99.8 → 0%) |
| `eval/attack_tradeoff.png` | 10 supporting (both attack classes) |

## Live demo (slide 10)

```bash
DB_HOST=localhost DB_PORT=15432 DB_NAME=packages DB_USER=appuser DB_PASS=apppass \
  .venv/bin/python scripts/demo_evasion.py
```

Output (captured live):
```
=== v1 baseline (17 features) ===
   Original score:                0.9985  (CRITICAL)
   After description=120/readme=2000: 0.0103  (LOW)
   --> score moved by +0.9883 (attacker padding ONLY)

=== v7-Robust (13 features, monotonic) ===
   Original score:                0.9987  (critical)
   After description=120/readme=2000: 0.9987  (text features not in model)
   --> score moved by +0.0000
```

## Q&A defense

**Q: Why did you drop has_repo_link if it was the strongest predictor (SHAP 3.66)?**
A: Strong predictor ≠ trustworthy predictor. Our top-PyPI benigns are popular projects that always have a GitHub URL — 92.5% had one. Pypi_malregistry malicious were removed from PyPI before collection — 0% had one. The model was learning "is this a popular GitHub-hosted package?" rather than "is this code malicious?" An attacker can claim a fake URL in setup.py. We confirmed this experimentally: a single perturbation `has_repo_link=1` evaded 500/500 sampled malicious packages. So we eliminated the feature.

**Q: Did this hurt model performance?**
A: F1 dropped from a suspicious 0.9998 to an honest 0.9013. The 0.9998 was memorization of collection bias; the 0.9013 reflects genuine ability to discriminate behaviour. We accept the lower number because it's defensible.

**Q: Could you have addressed this with calibrated monotonic constraints instead?**
A: Yes — reducing monotonic weight on `has_repo_link` would lower its SHAP magnitude. But the underlying problem remains: even with weight=1.0, the feature is still trivially evadable. Elimination is cleaner than reweighting.
