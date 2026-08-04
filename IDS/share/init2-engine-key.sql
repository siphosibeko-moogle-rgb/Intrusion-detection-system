-- Seeds one ACTIVE engine ingest key, owned by the admin user "Tiron bby",
-- so the friend's engine can authenticate without going through the web
-- approval flow (Request key -> admin approves on /admin/agents).
--
-- Matches EngineKeyService.approve(): keys are looked up by SHA-256(rawKey)
-- hex, and the raw key is never stored, only its hash + an 8-char prefix.
--   RAW key:    piQLNx4vEFAmJ1IaMC1993hv9x8IpyQ7ij9J7orJGp8
--   key_prefix: piQLNx4v          (first 8 chars of the raw key)
--   key_hash:   sha256(raw key) hex, verified against `sha256sum` before
--               this file was written.
--
-- IMPORTANT — why this can be a no-op on the very first boot:
-- This file is mounted (alongside db/IDS_db.sql) into Postgres's
-- /docker-entrypoint-initdb.d/, so on a *fresh* volume it runs once, during
-- the db container's first-ever startup — before the backend container has
-- ever run. Two things this INSERT needs do not exist at that point:
--   1. The `engine_keys` table itself. It is not created by db/IDS_db.sql —
--      it's created by Hibernate (spring.jpa.hibernate.ddl-auto=update) the
--      first time the backend application context starts.
--   2. The 'Tiron bby' row in `users`. It's created by AdminBootstrap, a
--      Spring ApplicationRunner that also only runs on backend startup.
-- So on a brand-new volume, this script detects both cases and logs a
-- NOTICE instead of erroring, then does nothing. Once the backend has
-- booted successfully once (schema migrated, admin created), re-run this
-- exact file by hand — see share/README.md for the one-line command.
DO $$
DECLARE
    admin_id INTEGER;
BEGIN
    IF to_regclass('public.engine_keys') IS NULL THEN
        RAISE NOTICE 'init2-engine-key.sql: engine_keys table does not exist yet '
            '(created by the backend on first startup, not by the schema SQL). '
            'Skipping seed — re-run this script after the backend has started once.';
        RETURN;
    END IF;

    SELECT user_id INTO admin_id FROM users WHERE username = 'Tiron bby';
    IF admin_id IS NULL THEN
        RAISE NOTICE 'init2-engine-key.sql: admin user "Tiron bby" does not exist yet '
            '(created by AdminBootstrap on first backend startup). '
            'Skipping seed — re-run this script after the backend has started once.';
        RETURN;
    END IF;

    INSERT INTO engine_keys
        (id, owner_id, name, key_hash, key_prefix, status, created_at, approved_at)
    VALUES (
        gen_random_uuid(),
        admin_id,
        'Friend test engine',
        '6ee43605ad727f3d7af3e714f1e43115d25ff7af3cf0a02ba3373ffa83d7640b',
        'piQLNx4v',
        'ACTIVE',
        NOW(),
        NOW()
    )
    ON CONFLICT (key_hash) DO NOTHING;

    RAISE NOTICE 'init2-engine-key.sql: engine key seeded (or already present) for "Tiron bby".';
END $$;
