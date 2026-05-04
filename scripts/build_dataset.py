#!/usr/bin/env python3
"""
Build labeled training dataset for malicious package detection.

Malicious (label=1): pypi_malregistry — ~9,500 verified malicious PyPI packages
                     https://github.com/lxyeternal/pypi_malregistry
                     Source: "An Empirical Study of Malicious Code In PyPI Ecosystem" (ASE 2023)
Benign   (label=0): top-2000 PyPI + ~100 npm packages from live registries

Run from ~/MLPro:
    pip install requests psycopg2-binary
    python3 scripts/build_dataset.py
    python3 scripts/build_dataset.py --skip-clone      # repo already cloned
    python3 scripts/build_dataset.py --malicious-only
    python3 scripts/build_dataset.py --benign-only
    python3 scripts/build_dataset.py --workers 16      # default 8
"""
import argparse
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import psycopg2
import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ROOT = Path(__file__).parent.parent
MALREG_DIR = ROOT / "data" / "pypi_malregistry"
MALREG_REPO = "https://github.com/lxyeternal/pypi_malregistry"
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024  # 50 MB

DB = {
    "host":     os.environ.get("DB_HOST", "localhost"),
    "port":     int(os.environ.get("DB_PORT", "5432")),
    "dbname":   os.environ.get("DB_NAME", "packages"),
    "user":     os.environ.get("DB_USER", "appuser"),
    "password": os.environ.get("DB_PASS", "apppass"),
}

TOP_NPM = [
    "lodash", "express", "react", "react-dom", "axios", "moment", "webpack",
    "typescript", "eslint", "jest", "next", "vue", "chalk", "commander",
    "dotenv", "uuid", "debug", "async", "underscore", "bluebird", "body-parser",
    "cors", "morgan", "helmet", "nodemon", "prettier", "semver", "yargs", "glob",
    "minimist", "mkdirp", "rimraf", "through2", "readable-stream", "rxjs",
    "core-js", "regenerator-runtime", "tslib", "classnames", "prop-types",
    "redux", "immer", "zustand", "socket.io", "fastify", "koa",
    "sequelize", "mongoose", "knex", "pg", "mysql2", "redis", "ioredis",
    "multer", "sharp", "cheerio", "puppeteer", "playwright", "supertest",
    "mocha", "chai", "sinon", "nyc", "rollup", "vite", "esbuild",
    "sass", "postcss", "tailwindcss", "styled-components", "graphql",
    "joi", "yup", "zod", "passport", "jsonwebtoken", "bcrypt",
    "node-fetch", "got", "ws", "date-fns", "luxon", "dayjs",
    "lodash-es", "ramda", "winston", "pino", "pm2", "husky",
    "lerna", "nx", "vitest", "fp-ts", "io-ts", "busboy",
    "pdf-lib", "xlsx", "jimp", "cross-env", "concurrently",
]

# ---------------------------------------------------------------------------
# Import extractors from dags/
# ---------------------------------------------------------------------------

sys.path.insert(0, str(ROOT / "dags"))
from extractors.code_features import extract_code_features
from extractors.metadata_features import extract_metadata_features
from extractors.text_features import extract_text_features

# ---------------------------------------------------------------------------
# DB helpers — new connection per call (thread-safe)
# ---------------------------------------------------------------------------

def _conn():
    return psycopg2.connect(**DB)


def is_done(registry: str, name: str, version: str) -> bool:
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM packages WHERE registry=%s AND name=%s AND version=%s "
                "AND extraction_status='done'",
                (registry, name, version),
            )
            return cur.fetchone() is not None


def save(
    registry: str, name: str, version: str,
    author: str | None, description: str | None,
    homepage: str | None, repository: str | None,
    keywords: list, downloads: int,
    label: int, label_source: str,
    features: dict,
) -> None:
    raw_features = json.dumps({
        k: v for k, v in features.items()
        if not isinstance(v, (dict, list))
    })
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO packages
                    (registry, name, version, author, description, homepage,
                     repository, keywords, downloads_last_month,
                     extraction_status, label, label_source)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'done',%s,%s)
                ON CONFLICT (registry, name, version) DO UPDATE SET
                    label             = COALESCE(EXCLUDED.label, packages.label),
                    label_source      = COALESCE(EXCLUDED.label_source, packages.label_source),
                    extraction_status = 'done'
                RETURNING id
            """, (registry, name, version, author, description, homepage,
                  repository, keywords, downloads, label, label_source))
            pkg_id = cur.fetchone()[0]

            cur.execute("""
                INSERT INTO features (
                    package_id,
                    entropy_max, has_network_in_install, has_credential_access,
                    has_obfuscated_code, has_exec_eval, install_script_lines,
                    dangerous_import_count, has_os_targeting, has_external_payload,
                    api_category_count,
                    account_age_days, typosquat_target, typosquat_distance,
                    has_repo_link, version_count, version_jump_suspicious,
                    description_length, readme_length, raw_features
                ) VALUES (
                    %(package_id)s,
                    %(entropy_max)s, %(has_network_in_install)s, %(has_credential_access)s,
                    %(has_obfuscated_code)s, %(has_exec_eval)s, %(install_script_lines)s,
                    %(dangerous_import_count)s, %(has_os_targeting)s, %(has_external_payload)s,
                    %(api_category_count)s,
                    %(account_age_days)s, %(typosquat_target)s, %(typosquat_distance)s,
                    %(has_repo_link)s, %(version_count)s, %(version_jump_suspicious)s,
                    %(description_length)s, %(readme_length)s, %(raw_features)s
                )
                ON CONFLICT (package_id) DO UPDATE SET
                    entropy_max             = EXCLUDED.entropy_max,
                    has_network_in_install  = EXCLUDED.has_network_in_install,
                    has_credential_access   = EXCLUDED.has_credential_access,
                    has_obfuscated_code     = EXCLUDED.has_obfuscated_code,
                    has_exec_eval           = EXCLUDED.has_exec_eval,
                    install_script_lines    = EXCLUDED.install_script_lines,
                    dangerous_import_count  = EXCLUDED.dangerous_import_count,
                    has_os_targeting        = EXCLUDED.has_os_targeting,
                    has_external_payload    = EXCLUDED.has_external_payload,
                    api_category_count      = EXCLUDED.api_category_count,
                    typosquat_target        = EXCLUDED.typosquat_target,
                    typosquat_distance      = EXCLUDED.typosquat_distance,
                    has_repo_link           = EXCLUDED.has_repo_link,
                    version_count           = EXCLUDED.version_count,
                    version_jump_suspicious = EXCLUDED.version_jump_suspicious,
                    description_length      = EXCLUDED.description_length,
                    readme_length           = EXCLUDED.readme_length,
                    raw_features            = EXCLUDED.raw_features,
                    extracted_at            = NOW()
            """, {**features, "package_id": pkg_id, "raw_features": raw_features})


# ---------------------------------------------------------------------------
# Archive helpers
# ---------------------------------------------------------------------------

def _unpack(data: bytes, dest: str) -> None:
    buf = io.BytesIO(data)
    if data[:2] in (b"\x1f\x8b", b"BZh") or data[:5] == b"ustar":
        with tarfile.open(fileobj=buf) as tf:
            tf.extractall(dest)
    elif data[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(buf) as zf:
            zf.extractall(dest)
    else:
        with tarfile.open(fileobj=buf) as tf:
            tf.extractall(dest)


def _pkg_root(tmpdir: str) -> str:
    entries = [
        os.path.join(tmpdir, e)
        for e in os.listdir(tmpdir)
        if os.path.isdir(os.path.join(tmpdir, e))
    ]
    return entries[0] if entries else tmpdir


# ---------------------------------------------------------------------------
# Malicious: process one .tar.gz from pypi_malregistry
# Repo layout: {name}/{version}/{name}-{version}.tar.gz
# ---------------------------------------------------------------------------

def process_tarball(tar_path: Path) -> str:
    version = tar_path.parent.name
    name = tar_path.parent.parent.name

    if is_done("pypi", name, version):
        return f"skip  exists: {name}@{version}"

    try:
        data = tar_path.read_bytes()
        if len(data) > MAX_ARCHIVE_BYTES:
            return f"skip  too large: {name}@{version}"

        with tempfile.TemporaryDirectory() as tmpdir:
            _unpack(data, tmpdir)
            pkg_dir = _pkg_root(tmpdir)
            pkg_meta = {"name": name, "version": version, "registry": "pypi"}
            features = {
                **extract_code_features(pkg_dir),
                **extract_metadata_features(pkg_meta),
                **extract_text_features(pkg_dir, pkg_meta),
            }

        save(
            registry="pypi", name=name, version=version,
            author=None, description=None, homepage=None,
            repository=None, keywords=[], downloads=0,
            label=1, label_source="pypi_malregistry",
            features=features,
        )
        return f"ok    {name}@{version}"
    except Exception as exc:
        return f"fail  {name}@{version}: {exc}"


# ---------------------------------------------------------------------------
# Malicious ingestion
# ---------------------------------------------------------------------------

def ingest_malicious(workers: int) -> None:
    print("\n=== Malicious packages (pypi_malregistry) ===")
    tarballs = list(MALREG_DIR.rglob("*.tar.gz"))
    total = len(tarballs)
    if total == 0:
        print("  No .tar.gz files found — did the clone succeed?")
        return
    print(f"  {total:,} archives — processing with {workers} workers")

    ok = skip = fail = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(process_tarball, p): p for p in tarballs}
        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            if result.startswith("ok"):
                ok += 1
            elif result.startswith("skip"):
                skip += 1
            else:
                fail += 1
                if fail <= 20:
                    print(f"  {result}")
            if i % 500 == 0 or i == total:
                print(f"  [{i:,}/{total:,}]  ok={ok:,}  skip={skip:,}  fail={fail:,}")

    print(f"  Done — {ok:,} ingested, {skip:,} skipped, {fail:,} failed")


# ---------------------------------------------------------------------------
# Benign: PyPI top-500
# ---------------------------------------------------------------------------

def ingest_benign_pypi() -> None:
    print("\n=== Benign PyPI (top-2000) ===")
    rows = requests.get(
        "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json",
        timeout=30,
    ).json().get("rows", [])[:2000]

    ok = skip = 0
    for row in rows:
        name = row.get("project", "")
        if not name:
            continue
        try:
            resp = requests.get(f"https://pypi.org/pypi/{name}/json", timeout=15)
            if resp.status_code != 200:
                skip += 1
                continue
            data = resp.json()
            info = data["info"]
            version = info["version"]
            if is_done("pypi", name, version):
                skip += 1
                continue
            tarball_url = next(
                (u["url"] for u in data.get("urls", []) if u["filename"].endswith(".tar.gz")),
                None,
            )
            if not tarball_url:
                skip += 1
                continue
            raw = requests.get(tarball_url, timeout=60).content
            if len(raw) > MAX_ARCHIVE_BYTES:
                skip += 1
                continue
            with tempfile.TemporaryDirectory() as tmpdir:
                _unpack(raw, tmpdir)
                pkg_dir = _pkg_root(tmpdir)
                pkg_meta = {
                    "name": name, "version": version,
                    "registry": "pypi", "description": info.get("summary"),
                }
                features = {
                    **extract_code_features(pkg_dir),
                    **extract_metadata_features(pkg_meta),
                    **extract_text_features(pkg_dir, pkg_meta),
                }
            save(
                registry="pypi", name=name, version=version,
                author=info.get("author"), description=info.get("summary"),
                homepage=info.get("home_page"), repository=None,
                keywords=[], downloads=min(row.get("download_count", 0), 9_000_000_000),
                label=0, label_source="top_pypi",
                features=features,
            )
            ok += 1
            if ok % 50 == 0:
                print(f"  {ok} done")
        except Exception as exc:
            print(f"  fail pypi/{name}: {exc}")
            skip += 1
    print(f"  Done — {ok} ingested, {skip} skipped")


# ---------------------------------------------------------------------------
# Benign: npm
# ---------------------------------------------------------------------------

def ingest_benign_npm() -> None:
    print("\n=== Benign npm ===")
    ok = skip = 0
    for name in TOP_NPM:
        try:
            encoded = name.replace("/", "%2F")
            resp = requests.get(
                f"https://registry.npmjs.org/{encoded}/latest", timeout=15
            )
            if resp.status_code != 200:
                skip += 1
                continue
            info = resp.json()
            version = info.get("version", "unknown")
            if is_done("npm", name, version):
                skip += 1
                continue
            tarball = info.get("dist", {}).get("tarball")
            if not tarball:
                skip += 1
                continue
            raw = requests.get(tarball, timeout=60).content
            if len(raw) > MAX_ARCHIVE_BYTES:
                skip += 1
                continue
            with tempfile.TemporaryDirectory() as tmpdir:
                _unpack(raw, tmpdir)
                pkg_dir = _pkg_root(tmpdir)
                pkg_meta = {
                    "name": name, "version": version,
                    "registry": "npm", "description": info.get("description"),
                }
                features = {
                    **extract_code_features(pkg_dir),
                    **extract_metadata_features(pkg_meta),
                    **extract_text_features(pkg_dir, pkg_meta),
                }
            author = info.get("author")
            save(
                registry="npm", name=name, version=version,
                author=author.get("name") if isinstance(author, dict) else author,
                description=info.get("description"),
                homepage=info.get("homepage"), repository=None,
                keywords=(info.get("keywords") or [])[:20], downloads=0,
                label=0, label_source="top_npm",
                features=features,
            )
            ok += 1
        except Exception as exc:
            print(f"  fail npm/{name}: {exc}")
            skip += 1
    print(f"  Done — {ok} ingested, {skip} skipped")


# ---------------------------------------------------------------------------
# Clone
# ---------------------------------------------------------------------------

def clone_repo() -> None:
    MALREG_DIR.parent.mkdir(parents=True, exist_ok=True)
    if (MALREG_DIR / ".git").exists():
        print(f"Repo already at {MALREG_DIR} — skipping clone")
        return
    print(f"Cloning pypi_malregistry → {MALREG_DIR}  (may take a few minutes)...")
    subprocess.run(
        ["git", "clone", "--depth=1", MALREG_REPO, str(MALREG_DIR)],
        check=True,
    )
    print("Clone complete.")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary() -> None:
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT label, COUNT(*) FROM packages
                WHERE label IS NOT NULL
                GROUP BY label ORDER BY label
            """)
            rows = cur.fetchall()
    print("\n=== Dataset summary ===")
    total = sum(c for _, c in rows)
    for label, count in rows:
        label_name = "benign" if label == 0 else "malicious"
        print(f"  {label_name:10s} (label={label}): {count:,}")
    print(f"  {'total':10s}          : {total:,}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Build labeled training dataset")
    parser.add_argument("--workers", type=int, default=8,
                        help="parallel workers for malicious ZIPs (default 8)")
    parser.add_argument("--skip-clone", action="store_true",
                        help="skip git clone (repo already present)")
    parser.add_argument("--malicious-only", action="store_true")
    parser.add_argument("--benign-only", action="store_true")
    args = parser.parse_args()

    if not args.skip_clone:
        clone_repo()

    if not args.benign_only:
        ingest_malicious(workers=args.workers)

    if not args.malicious_only:
        ingest_benign_pypi()
        ingest_benign_npm()

    print_summary()


if __name__ == "__main__":
    main()
