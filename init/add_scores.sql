-- Scores table: model output per package
\connect packages appuser

CREATE TABLE IF NOT EXISTS scores (
    id             SERIAL PRIMARY KEY,
    package_id     INTEGER REFERENCES packages(id) ON DELETE CASCADE UNIQUE,
    score          FLOAT        NOT NULL,        -- 0.0–1.0 malicious probability
    risk_level     VARCHAR(10)  NOT NULL,        -- low | medium | high | critical
    shap_values    JSONB,                        -- {feature: shap_value}
    report_md      TEXT,                         -- human-readable markdown report
    model_version  VARCHAR(50),                  -- MLflow model version used
    scored_at      TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scores_risk    ON scores(risk_level);
CREATE INDEX IF NOT EXISTS idx_scores_package ON scores(package_id);
