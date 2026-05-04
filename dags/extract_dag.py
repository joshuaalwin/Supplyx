import io
import os
import tarfile
import tempfile
import zipfile
from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.python import PythonOperator

from extractors.code_features import extract_code_features
from extractors.guarddog_features import extract_guarddog_features
from extractors.metadata_features import extract_metadata_features
from extractors.text_features import extract_text_features
from storage.db import get_pending_packages, set_extraction_status, upsert_features
from storage.object_store import download_bytes

BUCKET = os.environ.get("MINIO_BUCKET", "packages")
BATCH = int(os.environ.get("EXTRACT_BATCH_SIZE", "20"))

default_args = {
    "owner": "mlpro",
    "retries": 1,
    "retry_delay": timedelta(minutes=2),
}


def _unpack(data: bytes, dest: str) -> None:
    buf = io.BytesIO(data)
    # Detect format by magic bytes
    if data[:2] in (b"\x1f\x8b", b"BZh") or data[:5] == b"ustar":
        with tarfile.open(fileobj=buf) as tf:
            tf.extractall(dest)
    elif data[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(buf) as zf:
            zf.extractall(dest)
    else:
        # Fallback: try tarfile regardless
        with tarfile.open(fileobj=buf) as tf:
            tf.extractall(dest)


def _package_root(tmpdir: str) -> str:
    """Return the first subdirectory inside the extracted archive, or tmpdir itself."""
    entries = [
        os.path.join(tmpdir, e)
        for e in os.listdir(tmpdir)
        if os.path.isdir(os.path.join(tmpdir, e))
    ]
    return entries[0] if entries else tmpdir


def extract_features_batch(**_) -> None:
    packages = get_pending_packages(limit=BATCH)
    if not packages:
        print("[extract] nothing pending")
        return

    for pkg in packages:
        pkg_id = pkg["id"]
        name = pkg["name"]
        version = pkg["version"]
        registry = pkg["registry"]
        object_key = pkg.get("object_key")

        if not object_key:
            set_extraction_status(pkg_id, "failed")
            continue

        set_extraction_status(pkg_id, "running")

        try:
            raw = download_bytes(BUCKET, object_key)

            with tempfile.TemporaryDirectory() as tmpdir:
                _unpack(raw, tmpdir)
                pkg_dir = _package_root(tmpdir)

                pkg_meta = {
                    "name": name,
                    "version": version,
                    "registry": registry,
                    "description": pkg.get("description"),
                }

                code_f = extract_code_features(pkg_dir)
                meta_f = extract_metadata_features(pkg_meta)
                text_f = extract_text_features(pkg_dir, pkg_meta)
                guarddog_f = extract_guarddog_features(pkg_dir, registry)

            upsert_features(
                pkg_id,
                {
                    **code_f,
                    **meta_f,
                    **text_f,
                    "raw_features": {
                        **code_f, **meta_f, **text_f,
                        "guarddog": guarddog_f,
                    },
                },
            )
            set_extraction_status(pkg_id, "done")
            print(f"[extract] done  {registry}/{name}@{version}")

        except Exception as exc:
            print(f"[extract] failed {registry}/{name}@{version}: {exc}")
            set_extraction_status(pkg_id, "failed")


with DAG(
    dag_id="extract_features",
    default_args=default_args,
    description="Extract code, metadata, and text features from ingested packages",
    schedule_interval="*/30 * * * *",
    start_date=datetime(2025, 1, 1),
    catchup=False,
    max_active_runs=1,
    tags=["extraction"],
) as dag:

    PythonOperator(
        task_id="extract_features_batch",
        python_callable=extract_features_batch,
    )
