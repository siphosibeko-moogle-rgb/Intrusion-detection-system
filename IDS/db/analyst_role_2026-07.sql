-- Consolidates roles (July 2026): the backend now only recognizes ADMIN and
-- ANALYST — the USER and VIEWER roles have been removed from the code
-- (AuthController/WebAuthController registration defaults, and the
-- userDetailsService blank-role fallback, all now mint ANALYST). This
-- rewrites any existing rows still carrying the old role strings (or a
-- blank/NULL role) so no orphaned USER/VIEWER role remains in the table.
--
-- Idempotent: safe to run more than once — after the first run no row will
-- match the WHERE clause.
--
-- Apply with:
--   docker exec -i ids_db psql -U <DB_USERNAME> -d ids_db < db/analyst_role_2026-07.sql

BEGIN;

UPDATE users
SET role = 'ANALYST'
WHERE role IN ('USER', 'VIEWER') OR role IS NULL OR role = '';

COMMIT;
