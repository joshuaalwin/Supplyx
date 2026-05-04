-- Runs as the airflow superuser on container first start

CREATE USER appuser WITH PASSWORD 'apppass';
CREATE DATABASE packages OWNER appuser;

\connect packages appuser

CREATE TABLE packages (
    id                   SERIAL PRIMARY KEY,
    registry             VARCHAR(10)  NOT NULL,          -- 'pypi' | 'npm'
    name                 VARCHAR(255) NOT NULL,
    version              VARCHAR(100) NOT NULL,
    author               VARCHAR(255),
    description          TEXT,
    homepage             VARCHAR(500),
    repository           VARCHAR(500),
    keywords             TEXT[],
    downloads_last_month INTEGER      DEFAULT 0,
    object_key           VARCHAR(500),                   -- MinIO key for raw archive
    ingested_at          TIMESTAMPTZ  DEFAULT NOW(),
    extraction_status    VARCHAR(20)  DEFAULT 'pending', -- pending | running | done | failed
    UNIQUE (registry, name, version)
);

CREATE TABLE features (
    id                      SERIAL PRIMARY KEY,
    package_id              INTEGER REFERENCES packages(id) ON DELETE CASCADE UNIQUE,
    -- code
    entropy_max             FLOAT,
    has_network_in_install  BOOLEAN DEFAULT FALSE,
    has_credential_access   BOOLEAN DEFAULT FALSE,
    has_obfuscated_code     BOOLEAN DEFAULT FALSE,
    has_exec_eval           BOOLEAN DEFAULT FALSE,
    install_script_lines    INTEGER DEFAULT 0,
    dangerous_import_count  INTEGER DEFAULT 0,
    -- metadata
    account_age_days        INTEGER,
    typosquat_target        VARCHAR(255),
    typosquat_distance      INTEGER,
    has_repo_link           BOOLEAN DEFAULT FALSE,
    version_count           INTEGER DEFAULT 1,
    -- text
    description_length      INTEGER DEFAULT 0,
    readme_length           INTEGER DEFAULT 0,
    -- catch-all for extra signals
    raw_features            JSONB,
    extracted_at            TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_packages_status   ON packages(extraction_status);
CREATE INDEX idx_packages_registry ON packages(registry, name);
CREATE INDEX idx_features_pkg      ON features(package_id);
