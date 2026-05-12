#!/usr/bin/env bash
# Dump the labeled dataset to data/backup/ after build_dataset.py completes.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT_DIR="data/backup"
STAMP="$(date +%Y%m%d_%H%M%S)"

echo "[dump] pg_dump packages+features..."
docker exec supplyx-postgres-1 pg_dump -U appuser -d packages \
  --table=packages --table=features --table=scores --no-owner --no-privileges \
  | gzip > "$OUT_DIR/dataset_packages_features_${STAMP}.sql.gz"

echo "[dump] CSV export of labeled training matrix..."
PGPASSWORD=apppass psql -h localhost -p 15432 -U appuser -d packages -c "\
  COPY (
    SELECT p.registry, p.name, p.version, p.label,
           COALESCE(f.entropy_max,0)             AS entropy_max,
           COALESCE(f.has_network_in_install,false)::int AS has_network_in_install,
           COALESCE(f.has_credential_access,false)::int  AS has_credential_access,
           COALESCE(f.has_obfuscated_code,false)::int    AS has_obfuscated_code,
           COALESCE(f.has_exec_eval,false)::int          AS has_exec_eval,
           COALESCE(f.install_script_lines,0)            AS install_script_lines,
           COALESCE(f.dangerous_import_count,0)          AS dangerous_import_count,
           COALESCE(f.has_os_targeting,false)::int       AS has_os_targeting,
           COALESCE(f.has_external_payload,false)::int   AS has_external_payload,
           COALESCE(f.api_category_count,0)              AS api_category_count,
           COALESCE(f.typosquat_distance,0)              AS typosquat_distance,
           CASE WHEN f.typosquat_target IS NOT NULL THEN 1 ELSE 0 END AS is_typosquat,
           COALESCE(f.has_repo_link,false)::int          AS has_repo_link,
           COALESCE(f.version_count,1)                   AS version_count,
           COALESCE(f.version_jump_suspicious,false)::int AS version_jump_suspicious,
           COALESCE(f.description_length,0)              AS description_length,
           COALESCE(f.readme_length,0)                   AS readme_length
    FROM packages p
    JOIN features f ON f.package_id = p.id
    WHERE p.label IS NOT NULL
  ) TO STDOUT WITH CSV HEADER" | gzip > "$OUT_DIR/dataset_labeled_${STAMP}.csv.gz"

echo "[dump] summary:"
PGPASSWORD=apppass psql -h localhost -p 15432 -U appuser -d packages -c "
  SELECT label, COUNT(*) FROM packages WHERE label IS NOT NULL GROUP BY label;"
ls -lh "$OUT_DIR/"
