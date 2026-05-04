import json
import os
from contextlib import contextmanager

import psycopg2
import psycopg2.extras


def _dsn() -> str:
    return (
        f"host={os.environ.get('DB_HOST', 'postgres')} "
        f"port={os.environ.get('DB_PORT', '5432')} "
        f"dbname={os.environ.get('DB_NAME', 'packages')} "
        f"user={os.environ.get('DB_USER', 'appuser')} "
        f"password={os.environ.get('DB_PASS', 'apppass')}"
    )


@contextmanager
def get_conn():
    conn = psycopg2.connect(_dsn())
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def upsert_package(pkg: dict) -> int:
    pkg = {"label": None, "label_source": None, **pkg}
    sql = """
        INSERT INTO packages
            (registry, name, version, author, description,
             homepage, repository, keywords, downloads_last_month, object_key,
             label, label_source)
        VALUES
            (%(registry)s, %(name)s, %(version)s, %(author)s, %(description)s,
             %(homepage)s, %(repository)s, %(keywords)s, %(downloads_last_month)s,
             %(object_key)s, %(label)s, %(label_source)s)
        ON CONFLICT (registry, name, version) DO UPDATE SET
            author               = EXCLUDED.author,
            description          = EXCLUDED.description,
            object_key           = EXCLUDED.object_key,
            label                = COALESCE(EXCLUDED.label, packages.label),
            label_source         = COALESCE(EXCLUDED.label_source, packages.label_source),
            ingested_at          = NOW()
        RETURNING id
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, pkg)
            return cur.fetchone()[0]


def get_pending_packages(limit: int = 50) -> list[dict]:
    sql = """
        SELECT id, registry, name, version, object_key, description
        FROM   packages
        WHERE  extraction_status = 'pending'
        ORDER  BY ingested_at ASC
        LIMIT  %s
    """
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (limit,))
            return [dict(row) for row in cur.fetchall()]


def set_extraction_status(package_id: int, status: str) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE packages SET extraction_status = %s WHERE id = %s",
                (status, package_id),
            )


def upsert_features(package_id: int, features: dict) -> None:
    row = {**features, "package_id": package_id}
    if isinstance(row.get("raw_features"), dict):
        row["raw_features"] = json.dumps(row["raw_features"])

    sql = """
        INSERT INTO features
            (package_id, entropy_max, has_network_in_install, has_credential_access,
             has_obfuscated_code, has_exec_eval, install_script_lines,
             dangerous_import_count, account_age_days, typosquat_target,
             typosquat_distance, has_repo_link, version_count,
             description_length, readme_length,
             version_jump_suspicious, has_os_targeting,
             has_external_payload, api_category_count,
             raw_features)
        VALUES
            (%(package_id)s, %(entropy_max)s, %(has_network_in_install)s,
             %(has_credential_access)s, %(has_obfuscated_code)s, %(has_exec_eval)s,
             %(install_script_lines)s, %(dangerous_import_count)s,
             %(account_age_days)s, %(typosquat_target)s, %(typosquat_distance)s,
             %(has_repo_link)s, %(version_count)s,
             %(description_length)s, %(readme_length)s,
             %(version_jump_suspicious)s, %(has_os_targeting)s,
             %(has_external_payload)s, %(api_category_count)s,
             %(raw_features)s)
        ON CONFLICT (package_id) DO UPDATE SET
            entropy_max              = EXCLUDED.entropy_max,
            has_network_in_install   = EXCLUDED.has_network_in_install,
            has_credential_access    = EXCLUDED.has_credential_access,
            has_obfuscated_code      = EXCLUDED.has_obfuscated_code,
            has_exec_eval            = EXCLUDED.has_exec_eval,
            install_script_lines     = EXCLUDED.install_script_lines,
            dangerous_import_count   = EXCLUDED.dangerous_import_count,
            account_age_days         = EXCLUDED.account_age_days,
            typosquat_target         = EXCLUDED.typosquat_target,
            typosquat_distance       = EXCLUDED.typosquat_distance,
            has_repo_link            = EXCLUDED.has_repo_link,
            version_count            = EXCLUDED.version_count,
            description_length       = EXCLUDED.description_length,
            readme_length            = EXCLUDED.readme_length,
            version_jump_suspicious  = EXCLUDED.version_jump_suspicious,
            has_os_targeting         = EXCLUDED.has_os_targeting,
            has_external_payload     = EXCLUDED.has_external_payload,
            api_category_count       = EXCLUDED.api_category_count,
            raw_features             = EXCLUDED.raw_features,
            extracted_at             = NOW()
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, row)
