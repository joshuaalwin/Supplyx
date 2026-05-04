-- Run against the packages DB (appuser) after initial schema is created
\connect packages appuser

ALTER TABLE packages
    ADD COLUMN IF NOT EXISTS label        INTEGER,       -- 0=benign  1=malicious  NULL=live/unlabeled
    ADD COLUMN IF NOT EXISTS label_source VARCHAR(50);   -- 'datadog' | 'top_pypi' | 'top_npm' | 'live'

ALTER TABLE features
    ADD COLUMN IF NOT EXISTS version_jump_suspicious BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS has_os_targeting        BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS has_external_payload    BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS api_category_count      INTEGER DEFAULT 0;

ALTER TABLE packages
    ALTER COLUMN downloads_last_month TYPE BIGINT;

CREATE INDEX IF NOT EXISTS idx_packages_label ON packages(label);
