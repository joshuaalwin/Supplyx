import os
from datetime import datetime, timedelta

import requests
from airflow import DAG
from airflow.operators.python import PythonOperator

from clients.npm import get_package_metadata as npm_meta
from clients.npm import get_recent_packages as npm_recent
from clients.pypi import get_package_metadata as pypi_meta
from clients.pypi import get_recent_packages as pypi_recent
from storage.db import upsert_package
from storage.object_store import object_exists, upload_bytes

BUCKET = os.environ.get("MINIO_BUCKET", "packages")
LIMIT = int(os.environ.get("INGEST_LIMIT", "50"))
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024  # 50 MB hard cap

default_args = {
    "owner": "mlpro",
    "retries": 2,
    "retry_delay": timedelta(minutes=5),
}


def _download(url: str) -> bytes | None:
    if not url:
        return None
    try:
        resp = requests.get(url, timeout=60, stream=True)
        resp.raise_for_status()
        data = resp.content
        return data if len(data) <= MAX_ARCHIVE_BYTES else None
    except Exception:
        return None


def ingest_registry(registry: str, **_) -> None:
    recent_fn = pypi_recent if registry == "pypi" else npm_recent
    meta_fn = pypi_meta if registry == "pypi" else npm_meta

    candidates = recent_fn(limit=LIMIT)
    ingested = 0

    for ref in candidates:
        name, version = ref["name"], ref["version"]
        object_key = f"{registry}/{name}/{version}/archive"

        try:
            meta = meta_fn(name)
            if not meta:
                continue

            if not object_exists(BUCKET, object_key):
                raw = _download(meta.get("tarball_url"))
                if raw:
                    upload_bytes(BUCKET, object_key, raw)

            upsert_package(
                {
                    "registry": registry,
                    "name": name,
                    "version": version,
                    "author": meta.get("author"),
                    "description": meta.get("description"),
                    "homepage": meta.get("homepage"),
                    "repository": meta.get("repository"),
                    "keywords": meta.get("keywords", []),
                    "downloads_last_month": meta.get("downloads_last_month", 0),
                    "object_key": object_key,
                }
            )
            ingested += 1
        except Exception as exc:
            print(f"[ingest] {registry}/{name}@{version} failed: {exc}")

    print(f"[ingest] {registry}: {ingested}/{len(candidates)} ingested")


with DAG(
    dag_id="ingest_packages",
    default_args=default_args,
    description="Poll PyPI and npm for new packages and store raw archives",
    schedule_interval="*/15 * * * *",
    start_date=datetime(2025, 1, 1),
    catchup=False,
    max_active_runs=1,
    tags=["ingestion"],
) as dag:

    t_pypi = PythonOperator(
        task_id="ingest_pypi",
        python_callable=ingest_registry,
        op_kwargs={"registry": "pypi"},
    )

    t_npm = PythonOperator(
        task_id="ingest_npm",
        python_callable=ingest_registry,
        op_kwargs={"registry": "npm"},
    )

    [t_pypi, t_npm]  # run in parallel
