-- Alert-throttle schema. The project has no Flyway/Liquibase (schema is
-- hibernate ddl-auto=update), so this plain SQL file is executed idempotently
-- at startup by ThrottleSchemaInitializer. Every statement is IF NOT EXISTS /
-- additive, so re-running is always safe.

-- One row per (trusted source, detector, target) sliding window.
-- The composite PK is what makes the single-statement upsert in
-- AlertThrottleService safe: concurrent INSERT .. ON CONFLICT DO UPDATE
-- statements on the same key serialize on this primary-key row lock.
CREATE TABLE IF NOT EXISTS alert_throttle_state (
    source_ip     INET,
    detector_type VARCHAR(64),
    target_ip     INET,
    window_start  TIMESTAMPTZ NOT NULL,
    event_count   INT         NOT NULL DEFAULT 1,
    escalated     BOOLEAN     NOT NULL DEFAULT FALSE,
    PRIMARY KEY (source_ip, detector_type, target_ip)
);

-- Dedupe support on the raw alerts table: a SUPPRESS decision folds the
-- repeat into the most recent matching open alert instead of inserting a
-- new row. Rows that pre-date these columns count as a single occurrence.
ALTER TABLE IF EXISTS alerts
    ADD COLUMN IF NOT EXISTS occurrence_count INT NOT NULL DEFAULT 1;

ALTER TABLE IF EXISTS alerts
    ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ;
