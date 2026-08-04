-- AI triage sidecar table. The project has no Flyway/Liquibase (schema is
-- hibernate ddl-auto=update), so this plain SQL file is executed idempotently
-- at startup by TriageSchemaInitializer, mirroring alert_throttle_schema.sql.
-- Every statement is IF NOT EXISTS, so re-running (or racing Hibernate's own
-- ddl-auto=update creation of the same table from TriageVerdictEntity) is
-- always safe either way round.
CREATE TABLE IF NOT EXISTS triage_verdict (
    id              BIGSERIAL PRIMARY KEY,
    source_ip       VARCHAR(64)  NOT NULL,
    threat_type     VARCHAR(64)  NOT NULL,
    confidence      INT          NOT NULL,
    classification  VARCHAR(32)  NOT NULL,
    reasoning       VARCHAR(500),
    recommendation  VARCHAR(300),
    model           VARCHAR(32),
    analysed_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_triage_ip_type UNIQUE (source_ip, threat_type)
);

CREATE INDEX IF NOT EXISTS idx_triage_analysed_at ON triage_verdict (analysed_at DESC);
