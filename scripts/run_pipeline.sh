#!/usr/bin/env bash
# Post-build autopilot — runs after build_dataset.py prints "Dataset summary".
# Dumps dataset, audits discrimination, trains, evals, exports model, tags alias.
set -uo pipefail
cd "$(dirname "$0")/.."

export DB_HOST=localhost DB_PORT=15432 DB_NAME=packages DB_USER=appuser DB_PASS=apppass
export MLFLOW_TRACKING_URI=http://localhost:5000
export MLFLOW_S3_ENDPOINT_URL=http://localhost:9000
export AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin

PYTHON=".venv/bin/python"

log() { echo "[$(date +%H:%M:%S)] $*"; }

log "=== Phase D: dump dataset ==="
./scripts/dump_dataset.sh 2>&1 | tail -20

log "=== Phase γ: discrimination audit ==="
PGPASSWORD=apppass psql -h localhost -p 15432 -U appuser -d packages -c "
SELECT p.label, COUNT(*) AS n,
  ROUND(100.0*AVG(f.has_obfuscated_code::int),1)    AS pct_obf,
  ROUND(100.0*AVG(f.has_network_in_install::int),1) AS pct_net_install,
  ROUND(100.0*AVG(f.has_exec_eval::int),1)          AS pct_exec_eval,
  ROUND(100.0*AVG(f.has_credential_access::int),1)  AS pct_cred,
  ROUND(100.0*AVG(f.has_os_targeting::int),1)       AS pct_os_targeting,
  ROUND(100.0*AVG(f.has_external_payload::int),1)   AS pct_external,
  ROUND(100.0*AVG(f.has_repo_link::int),1)          AS pct_repo,
  ROUND(100.0*AVG(f.version_jump_suspicious::int),1) AS pct_vjump,
  AVG(f.dangerous_import_count)::numeric(5,2) AS dic_mean,
  AVG(f.api_category_count)::numeric(5,2)     AS apc_mean,
  AVG(f.install_script_lines)::numeric(7,2)   AS isl_mean,
  AVG(f.version_count)::numeric(5,2)          AS vc_mean,
  AVG(f.entropy_max)::numeric(5,3)            AS ent_mean
FROM features f JOIN packages p ON p.id=f.package_id
WHERE p.label IS NOT NULL GROUP BY p.label ORDER BY p.label;" 2>&1 | tee logs/discrimination_audit.log

log "=== Phase E: train v7-Robust ==="
$PYTHON scripts/train_model.py 2>&1 | tee logs/train.log

log "=== Phase F: export champion.json + tag MLflow alias v7-robust ==="
$PYTHON -c "
import mlflow
mlflow.set_tracking_uri('http://localhost:5000')
m = mlflow.xgboost.load_model('models:/malicious-package-detector@champion')
m.save_model('model/champion.json')
client = mlflow.MlflowClient()
champ = client.get_model_version_by_alias('malicious-package-detector', 'champion')
client.set_registered_model_alias('malicious-package-detector', 'v7-robust', champ.version)
print(f'exported v{champ.version} to model/champion.json and tagged v7-robust')
"

log "=== Phase H: TRUNCATE scores ==="
PGPASSWORD=apppass psql -h localhost -p 15432 -U appuser -d packages -c "TRUNCATE scores;" 2>&1

log "=== Phase I: eval_model ==="
$PYTHON scripts/eval_model.py 2>&1 | tee logs/eval.log

log "=== Phase J: adversarial eval ==="
$PYTHON scripts/eval_adversarial.py 2>&1 | tee logs/eval_adversarial.log

log "=== Phase J': demo_evasion (specific package) ==="
$PYTHON scripts/demo_evasion.py 2>&1 | tee logs/demo_evasion.log

log "=== Final metric summary for SLIDE_UPDATES.md ==="
$PYTHON -c "
import json
m = json.load(open('eval/metrics.json'))
a = json.load(open('eval/adversarial_results.json'))
print(f'F1:         {m[\"f1\"]:.4f}')
print(f'Precision:  {m[\"precision\"]:.4f}')
print(f'Recall:     {m[\"recall\"]:.4f}')
print(f'ROC-AUC:    {m[\"roc_auc\"]:.4f}')
print(f'Training:   {m[\"n_malicious\"]:,} mal + {m[\"n_benign\"]:,} ben = {m[\"n_total\"]:,}')
print(f'spw:        {m[\"scale_pos_weight\"]}')
print(f'v1 evasion: {a[\"v1_baseline\"][\"evaded\"]}/{a[\"v1_baseline\"][\"flagged\"]} = {a[\"v1_baseline\"][\"rate\"]:.1%}')
print(f'v7 evasion: {a[\"v7_robust\"][\"evaded\"]}/{a[\"v7_robust\"][\"flagged\"]} = {a[\"v7_robust\"][\"rate\"]:.1%}')
print(f'reduction:  {a[\"reduction_pct\"]:.1f}%')
print()
print('=== classification report ===')
print(open('eval/classification_report.txt').read())
" 2>&1 | tee logs/final_summary.log

log "=== DONE ==="
log "Inspect: eval/ logs/final_summary.log SLIDE_UPDATES.md"
