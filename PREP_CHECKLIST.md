# Demo-Day Prep Checklist

Time-boxed parallel work. Total ~60 min. Do these in ANY order while the dataset rebuild finishes (~25 min remaining).

---

## Task 1 — PPTX edit prep (10 min)

**Goal:** When metrics drop, blast through edits in <10 min instead of hunting.

1. Open PPTX: `ENPM604_Real-Time_Malicious Package Detection_Josh and Nimal.pptx`
2. Open `SLIDE_UPDATES.md` in a side panel
3. On EACH slide listed in SLIDE_UPDATES.md, **right-click → Add Comment** with text "EDIT: <metric>"
   - Slides to mark: **1, 2, 8, 9, 10, 11, 12** (7 slides)
   - Slide 9 has the most edits (10 fields) — mark each separately
4. Saves you cursor-hunting later

Time: 10 min.

---

## Task 2 — Screenshot the malicious setup.py (5 min) — **HIGH IMPACT**

This is THE visual that makes the audience gasp. A real malicious package on PyPI doing `subprocess.Popen('powershell -EncodedCommand cABvAH...')`.

Steps:
1. Open a terminal
2. Run:
   ```bash
   cat data/pypi_malregistry/level_1/craftvirtual/craftvirtual-10.2/setup.py
   ```
3. Screenshot the terminal (full output is ~15 lines, fits in one screen)
4. Or use code-editor: `code data/pypi_malregistry/level_1/craftvirtual/craftvirtual-10.2/setup.py`
5. Save as `screenshots/malicious-setup-py.png`

Slot for this: **slide 4** (after threat assessment) or **slide 10** (adversarial audit context — "this is what v1 was supposed to catch").

---

## Task 3 — Pre-take infrastructure screenshots (15 min)

These don't depend on the retrained model. Capture them now.

```bash
mkdir -p screenshots
```

### 3a. Airflow UI
- URL: http://localhost:8080 (admin / admin)
- DAG list view — full page screenshot
- Click `score_packages` → graph view → screenshot
- Click `train_model` → graph view → screenshot
- File names: `screenshots/airflow-dags-list.png`, `airflow-score-graph.png`, `airflow-train-graph.png`
- Slot: **slide 11**

### 3b. MinIO console
- URL: http://localhost:9001 (minioadmin / minioadmin)
- Login → Object Browser → show 3 buckets (`packages`, `features`, `mlflow`)
- Screenshot the buckets list
- Click `mlflow` bucket → show artifacts subdirs if any
- File: `screenshots/minio-buckets.png`
- Slot: **slide 6 or 11**

### 3c. System design HTML
- Open in browser: `file:///home/t3rminux/Desktop/UMD/ENPM604/Final-Project/Supplyx/system-design.html`
- Full-page screenshot (Ctrl+Shift+I → "Capture full size screenshot" in Chrome devtools, OR use Firefox screenshot tool)
- File: `screenshots/system-design.png`
- Slot: **slide 6** (or replace whatever's already there)

### 3d. PostgreSQL feature data
- Terminal:
  ```bash
  PGPASSWORD=apppass psql -h localhost -p 15432 -U appuser -d packages -c "\dt"
  PGPASSWORD=apppass psql -h localhost -p 15432 -U appuser -d packages -c "SELECT label, COUNT(*) FROM packages GROUP BY label;"
  ```
- Screenshot
- File: `screenshots/postgres-tables.png`
- Slot: **slide 6 backup**

---

## Task 4 — Draft slide-7 speaker notes (10 min)

This is the feature-engineering slide. The story has TWO layers:
- **Original story (on slide):** "We eliminated 2 text features after adversarial audit"
- **NEW story (this session):** "We then rewrote the remaining 13 feature extractors to fix patterns matching legitimate code"

Talking points (paraphrase, don't read):

1. *"Our v1 model used 17 static features. The adversarial audit showed two of them — description_length and readme_length — were collection artifacts. We eliminated them."*

2. *"Looking at the next-generation extractor, we went further. The original patterns were too permissive — they matched perfectly normal code in popular packages."*

3. **Show one example:**
   *"Original `has_exec_eval` detected any `eval()` or `exec()` call. That fires on jinja2, sympy, ipython — all legitimate template engines. We changed it to require co-occurrence with a decode or download call within 400 characters."*

4. **Monotonic constraints:**
   *"With 15 features now, we encoded prior knowledge as monotonic constraints: 10 code features with c=+1, has_repo_link and version_count with c=-1, typosquat_distance c=0. The model is forced to learn the correct direction. An adversary can't make a malicious package look less malicious by just increasing a code-behaviour feature."*

5. **The Q&A defense:**
   *"If you want to evade us, you have to change actual code behaviour — not metadata. That's a strictly harder problem for the attacker."*

---

## Task 5 — Draft slide-10 speaker notes (10 min)

This is the adversarial audit slide. The strongest part of the project.

Talking points:

1. *"We modeled this as a white-box adversary. They know our feature set. They want a real malicious package to score below 0.3."*

2. *"For v1, the attack was trivial. Pad your `description_length` from 0 to 120 characters. Your malicious package's score drops from 0.998 to 0.006."*

3. **Live demo (slide 10):**
   ```bash
   .venv/bin/python scripts/demo_evasion.py
   ```
   Run this. Read the output as it happens.

4. *"For v7-Robust, we removed those features entirely. The same attack does nothing — the model doesn't even see description_length."*

5. *"Across 500 sampled malicious packages, v1 was bypassed [X]% of the time. v7-Robust drops to [Y]%."*

6. **Q&A — anticipated**: "Can the adversary just change code behaviour?" → *"Yes — but that's a strictly harder problem. They lose the cosmetic attack vector that worked at 100% in v1."*

7. **Q&A — anticipated**: "Why didn't you catch description_length being inverted before launch?" → *"Because it wasn't inverted — it was a strong but spurious signal. pypi_malregistry packages had no description because they'd been removed. So 'no description' correlated with 'malicious' in our dataset. The model learned a collection artifact instead of a behaviour. That's the whole point of adversarial auditing — it forces you to ask 'what is the model actually learning?'"*

---

## Task 6 — Open notebook in Jupyter (5 min)

```bash
.venv/bin/jupyter notebook notebooks/model_demo.ipynb &
```

- Wait for browser to open
- Run cell 1 (imports)
- Cell 2 (load champion) will fail — no MLflow champion yet. Skip.
- DON'T run further cells. They need the model.
- Just leave the notebook open — saves time later.

---

## Task 7 — Read extractor rewrite (15 min) — defensive prep

Two files to understand:

### `dags/extractors/code_features.py`
Read the module docstring at the top — it summarizes every change. Then skim the patterns:
- `_NETWORK_PATTERNS` — function-call syntax required
- `_EXEC_NEAR_DECODE` — eval/exec must be near decode/download
- `_OBFUSCATION_PATTERNS` — base64 strings of 200+ chars
- `_OS_GATED_PATTERNS` — platform check WITH suspicious payload nearby
- `_EXTERNAL_PAYLOAD_PATTERNS` — single-line, no newlines between download and exec
- `_API_CATEGORIES` — each category needs a SUSPICIOUS combination, not bare imports
- `DANGEROUS_IMPORTS` — narrowed to `{ctypes, cffi, marshal}`
- `_INSTALL_TIME_DANGEROUS_IMPORTS` — broader set BUT only counted if in install scripts

### `dags/extractors/metadata_features.py`
Just the `_is_real_repo_url()` whitelist. Repo URL must match `github.com / gitlab.com / bitbucket.org / git.sr.ht / sourcehut.org / codeberg.org`.

This is your Q&A armor.

---

## Time budget

| Task | Time |
|---|---|
| 1. PPTX prep marks | 10 min |
| 2. craftvirtual setup.py screenshot | 5 min |
| 3a-d. Infrastructure screenshots | 15 min |
| 4. Slide-7 notes | 10 min |
| 5. Slide-10 notes | 10 min |
| 6. Notebook open | 5 min |
| 7. Extractor rewrite reading | 15 min |
| **TOTAL** | **~70 min** |

You have ~30 min of build remaining, then training+eval is another ~5 min. So focus on tasks **2, 4, 5** first (highest impact). Tasks 1, 3, 7 if time permits.

---

## When build finishes — what I'll do automatically

The autopilot watcher (`bk2jvdioc`) will fire when `Dataset summary` prints. It runs the full chain:

1. Dump dataset → `data/backup/dataset_*.{sql,csv}.gz`
2. Discrimination audit → `logs/discrimination_audit.log`
3. Train v7-Robust → `logs/train.log`
4. Export `model/champion.json`
5. Tag MLflow alias `v7-robust`
6. TRUNCATE scores
7. Run eval_model.py → `eval/*.png` and `eval/metrics.json`
8. Run eval_adversarial.py → `eval/adversarial_results.json`, `eval/evasion_rate_v1_vs_v7.png`
9. Run demo_evasion.py → `logs/demo_evasion.log`
10. Final summary → `logs/final_summary.log`

You'll get a notification when it's done. Then we apply the metric values to SLIDE_UPDATES.md.
