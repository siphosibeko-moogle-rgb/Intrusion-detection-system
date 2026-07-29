-- Fixes SQLState 42804 on INSERT INTO case_timeline: the live column
-- event_kind was created as a custom enum type (timeline_event_kind),
-- but CaseTimelineEntry.eventKind is a plain Java String and Hibernate
-- binds it as varchar. Postgres does not implicitly cast varchar -> enum,
-- so every insert (e.g. ForensicCaseService.assign -> update -> save)
-- fails. The entity was always a String by design (see the class
-- javadoc: enums are painful to migrate) — only the DB drifted from it,
-- most likely from a manually-created table that predates ddl-auto=update
-- ever seeing this table. spring.jpa.hibernate.ddl-auto=update will not
-- alter an existing column's type, so this has to be fixed here.
--
-- Confirmed before writing this: timeline_event_kind's 8 labels
-- (CASE_OPENED, ALERT_LINKED, STATUS_CHANGED, NOTE_ADDED, ANALYST_ACTION,
-- IP_WHITELISTED, IP_BLOCKED, CASE_CLOSED) match the Java-side values
-- exactly, the type is used nowhere else, and case_timeline currently
-- has 0 rows — so this is a same-day, no-downtime, no-data-loss change.
--
-- Apply with:
--   docker exec -i ids_db psql -U <DB_USERNAME> -d ids_db < db/case_timeline_event_kind_fix_2026-07.sql

BEGIN;

ALTER TABLE case_timeline
    ALTER COLUMN event_kind TYPE varchar(50)
    USING event_kind::text;

DROP TYPE timeline_event_kind;

COMMIT;
