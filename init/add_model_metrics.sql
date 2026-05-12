-- Model evaluation metrics tables — populated by scripts/publish_metrics.py
-- after each training run. Powers the Grafana ML dashboard.
\c packages

CREATE TABLE IF NOT EXISTS model_metrics (
    id              SERIAL PRIMARY KEY,
    model_version   VARCHAR(20)        NOT NULL,
    model_label     VARCHAR(50),
    f1              DOUBLE PRECISION,
    precision_score DOUBLE PRECISION,
    recall          DOUBLE PRECISION,
    roc_auc         DOUBLE PRECISION,
    accuracy        DOUBLE PRECISION,
    tn              INTEGER,
    fp              INTEGER,
    fn              INTEGER,
    tp              INTEGER,
    n_total         INTEGER,
    n_train         INTEGER,
    n_test          INTEGER,
    n_malicious     INTEGER,
    n_benign        INTEGER,
    scale_pos_weight DOUBLE PRECISION,
    n_features      INTEGER,
    n_estimators    INTEGER,
    recorded_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS model_shap (
    id              SERIAL PRIMARY KEY,
    model_version   VARCHAR(20)        NOT NULL,
    feature_name    VARCHAR(100)       NOT NULL,
    importance      DOUBLE PRECISION   NOT NULL,
    recorded_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS model_adversarial (
    id              SERIAL PRIMARY KEY,
    model_version   VARCHAR(20)        NOT NULL,
    attack_class    VARCHAR(50)        NOT NULL,
    model_label     VARCHAR(50)        NOT NULL,
    flagged         INTEGER,
    evaded          INTEGER,
    rate            DOUBLE PRECISION,
    recorded_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_model_metrics_recorded_at ON model_metrics(recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_model_shap_recorded_at ON model_shap(recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_model_adversarial_recorded_at ON model_adversarial(recorded_at DESC);
