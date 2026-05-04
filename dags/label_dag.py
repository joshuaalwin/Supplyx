"""
One-shot DAG: build the labeled training dataset.

Malicious class (label=1):
  - DataDog malicious-software-packages-dataset manifest (PyPI + npm)
  - Downloads live copies from the registry; skips packages already removed

Benign class (label=0):
  - Top-500 PyPI packages by 30-day download count
  - Top-500 npm packages by popularity score

After this DAG completes, trigger extract_features to populate the features table.
"""
import os
from datetime import datetime, timedelta

import requests
from airflow import DAG
from airflow.operators.python import PythonOperator

from storage.db import upsert_package
from storage.object_store import object_exists, upload_bytes

BUCKET = os.environ.get("MINIO_BUCKET", "packages")
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024  # 50 MB cap per archive

_DATADOG_BASE = (
    "https://raw.githubusercontent.com/DataDog/"
    "malicious-software-packages-dataset/main/samples"
)

default_args = {
    "owner": "mlpro",
    "retries": 1,
    "retry_delay": timedelta(minutes=5),
}


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------

def _fetch_datadog_manifest(registry: str) -> list[dict]:
    url = f"{_DATADOG_BASE}/{registry}/manifest.json"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _pypi_info(name: str, version: str | None) -> tuple[str | None, str | None, dict]:
    """Return (tarball_url, resolved_version, info_dict)."""
    url = (
        f"https://pypi.org/pypi/{name}/{version}/json"
        if version
        else f"https://pypi.org/pypi/{name}/json"
    )
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 404:
            return None, None, {}
        resp.raise_for_status()
        data = resp.json()
        info = data.get("info", {})
        resolved = info.get("version") or version or "unknown"
        for u in data.get("urls", []):
            if u.get("filename", "").endswith(".tar.gz"):
                return u["url"], resolved, info
        urls = data.get("urls", [])
        if urls:
            return urls[0]["url"], resolved, info
        return None, resolved, info
    except Exception:
        return None, None, {}


def _npm_info(name: str, version: str | None) -> tuple[str | None, str | None, dict]:
    """Return (tarball_url, resolved_version, info_dict)."""
    encoded = name.replace("/", "%2F")
    url = (
        f"https://registry.npmjs.org/{encoded}/{version}"
        if version
        else f"https://registry.npmjs.org/{encoded}/latest"
    )
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 404:
            return None, None, {}
        resp.raise_for_status()
        data = resp.json()
        resolved = data.get("version") or version or "unknown"
        tarball = data.get("dist", {}).get("tarball")
        return tarball, resolved, data
    except Exception:
        return None, None, {}


def _npm_author(info: dict) -> str | None:
    author = info.get("author")
    if isinstance(author, dict):
        return author.get("name")
    if isinstance(author, str):
        return author
    maintainers = info.get("maintainers") or []
    if maintainers:
        m = maintainers[0]
        return m.get("name") if isinstance(m, dict) else str(m)
    return None


def _npm_repo(info: dict) -> str | None:
    repo = info.get("repository")
    if isinstance(repo, dict):
        return repo.get("url")
    return repo


def _download_archive(url: str) -> bytes | None:
    try:
        resp = requests.get(url, timeout=60, stream=True)
        resp.raise_for_status()
        data = resp.content
        return data if len(data) <= MAX_ARCHIVE_BYTES else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# DAG tasks
# ---------------------------------------------------------------------------

def ingest_malicious(registry: str, **_) -> None:
    entries = _fetch_datadog_manifest(registry)
    ok = skip = 0

    for entry in entries:
        if isinstance(entry, str):
            name, version = entry, None
        else:
            name = entry.get("name", "")
            version = entry.get("version")

        if registry == "pypi":
            tarball_url, resolved_version, info = _pypi_info(name, version)
        else:
            tarball_url, resolved_version, info = _npm_info(name, version)

        if not tarball_url or not resolved_version:
            skip += 1
            continue

        object_key = f"{registry}/{name}/{resolved_version}/archive"
        try:
            if not object_exists(BUCKET, object_key):
                raw = _download_archive(tarball_url)
                if not raw:
                    skip += 1
                    continue
                upload_bytes(BUCKET, object_key, raw)

            if registry == "pypi":
                pkg = {
                    "registry": "pypi",
                    "name": name,
                    "version": resolved_version,
                    "author": info.get("author"),
                    "description": info.get("summary"),
                    "homepage": info.get("home_page"),
                    "repository": None,
                    "keywords": [],
                    "downloads_last_month": 0,
                    "object_key": object_key,
                    "label": 1,
                    "label_source": "datadog",
                }
            else:
                pkg = {
                    "registry": "npm",
                    "name": name,
                    "version": resolved_version,
                    "author": _npm_author(info),
                    "description": info.get("description"),
                    "homepage": info.get("homepage"),
                    "repository": _npm_repo(info),
                    "keywords": (info.get("keywords") or [])[:20],
                    "downloads_last_month": 0,
                    "object_key": object_key,
                    "label": 1,
                    "label_source": "datadog",
                }

            upsert_package(pkg)
            ok += 1
        except Exception as exc:
            print(f"[label] malicious {registry}/{name}: {exc}")
            skip += 1

    print(f"[label] malicious {registry}: {ok} ingested, {skip} skipped (removed/too large)")


def ingest_benign_pypi(**_) -> None:
    url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    rows = resp.json().get("rows", [])[:500]

    ok = skip = 0
    for row in rows:
        name = row.get("project", "")
        if not name:
            continue
        tarball_url, version, info = _pypi_info(name, None)
        if not tarball_url or not version:
            skip += 1
            continue
        object_key = f"pypi/{name}/{version}/archive"
        try:
            if not object_exists(BUCKET, object_key):
                raw = _download_archive(tarball_url)
                if not raw:
                    skip += 1
                    continue
                upload_bytes(BUCKET, object_key, raw)

            upsert_package({
                "registry": "pypi",
                "name": name,
                "version": version,
                "author": info.get("author"),
                "description": info.get("summary"),
                "homepage": info.get("home_page"),
                "repository": None,
                "keywords": [],
                "downloads_last_month": min(row.get("download_count", 0), 9_000_000_000),
                "object_key": object_key,
                "label": 0,
                "label_source": "top_pypi",
            })
            ok += 1
        except Exception as exc:
            print(f"[label] benign pypi/{name}: {exc}")
            skip += 1

    print(f"[label] benign pypi: {ok} ingested, {skip} skipped")


_TOP_NPM = [
    "lodash", "express", "react", "react-dom", "axios", "moment", "webpack",
    "typescript", "eslint", "jest", "next", "vue", "chalk", "commander",
    "dotenv", "uuid", "debug", "async", "underscore", "bluebird", "body-parser",
    "cors", "morgan", "helmet", "nodemon", "prettier", "semver", "yargs", "glob",
    "minimist", "mkdirp", "rimraf", "through2", "readable-stream", "rxjs",
    "core-js", "regenerator-runtime", "tslib", "classnames", "prop-types",
    "redux", "immer", "zustand", "mobx", "socket.io", "fastify", "koa",
    "sequelize", "mongoose", "knex", "pg", "mysql2", "redis", "ioredis",
    "multer", "sharp", "cheerio", "puppeteer", "playwright", "supertest",
    "mocha", "chai", "sinon", "nyc", "rollup", "vite", "esbuild", "parcel",
    "sass", "postcss", "tailwindcss", "styled-components", "graphql",
    "joi", "yup", "zod", "passport", "jsonwebtoken", "bcrypt", "crypto-js",
    "node-fetch", "got", "superagent", "ws", "date-fns", "luxon", "dayjs",
    "lodash-es", "ramda", "winston", "pino", "pm2", "husky", "lint-staged",
    "lerna", "nx", "turbo", "vitest", "enzyme", "fp-ts", "io-ts", "busboy",
    "formidable", "pdf-lib", "xlsx", "jimp", "cross-env", "concurrently",
]


def ingest_benign_npm(**_) -> None:
    ok = skip = 0
    for name in _TOP_NPM:
        tarball_url, version, info = _npm_info(name, None)
        if not tarball_url or not version:
            skip += 1
            continue
        object_key = f"npm/{name}/{version}/archive"
        try:
            if not object_exists(BUCKET, object_key):
                raw = _download_archive(tarball_url)
                if not raw:
                    skip += 1
                    continue
                upload_bytes(BUCKET, object_key, raw)

            upsert_package({
                "registry": "npm",
                "name": name,
                "version": version,
                "author": _npm_author(info),
                "description": info.get("description"),
                "homepage": info.get("homepage"),
                "repository": _npm_repo(info),
                "keywords": (info.get("keywords") or [])[:20],
                "downloads_last_month": 0,
                "object_key": object_key,
                "label": 0,
                "label_source": "top_npm",
            })
            ok += 1
        except Exception as exc:
            print(f"[label] benign npm/{name}: {exc}")
            skip += 1

    print(f"[label] benign npm: {ok} ingested, {skip} skipped")


with DAG(
    dag_id="build_labeled_dataset",
    default_args=default_args,
    description="One-shot: ingest DataDog malicious packages + benign top-500 for ML training",
    schedule_interval=None,
    start_date=datetime(2025, 1, 1),
    catchup=False,
    tags=["ml", "labeling"],
) as dag:

    t_mal_pypi = PythonOperator(
        task_id="ingest_malicious_pypi",
        python_callable=ingest_malicious,
        op_kwargs={"registry": "pypi"},
    )

    t_mal_npm = PythonOperator(
        task_id="ingest_malicious_npm",
        python_callable=ingest_malicious,
        op_kwargs={"registry": "npm"},
    )

    t_benign_pypi = PythonOperator(
        task_id="ingest_benign_pypi",
        python_callable=ingest_benign_pypi,
    )

    t_benign_npm = PythonOperator(
        task_id="ingest_benign_npm",
        python_callable=ingest_benign_npm,
    )

    [t_mal_pypi, t_mal_npm, t_benign_pypi, t_benign_npm]
