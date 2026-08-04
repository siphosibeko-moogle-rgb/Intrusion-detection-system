# Quick start

Full details, Windows/Mac steps, and troubleshooting are in `README.md`.
This is just the commands, in order — the exact sequence that was tested
and confirmed working (login + engine-key auth both verified end to end).

Run everything below from inside `share/`.

## 1. Build the jars (once, from the `IDS/` project root)

```
cd ..
mvn -pl backend,engine package
cd share
```

Skip this if `../backend/target/backend-1.0.0.jar` and
`../engine/target/engine-1.0.0.jar` already exist and are current.

## 2. Start the stack (Linux — db + backend + engine)

```
docker compose -f friend-compose.linux.yml --env-file .env up -d --build
```

Windows/Mac: use `friend-compose.desktop.yml` instead (db + backend only —
see `README.md` for running the engine natively).

## 3. Wait for the backend to finish its first boot

```
docker compose -f friend-compose.linux.yml logs -f backend
```

Watch for this line, then `Ctrl+C` out of the log tail:

```
Bootstrap: created initial ADMIN account 'Tiron bby'
```

## 4. Seed the engine key (one time, after step 3)

The very first boot creates the `engine_keys` table and the admin user, but
runs too late for the Postgres init scripts to seed the key automatically
(see `init2-engine-key.sql` for why). So seed it once, now:

```
docker compose -f friend-compose.linux.yml exec -T db \
  psql -U ids_user -d ids_db < init2-engine-key.sql
```

Expect:

```
NOTICE:  init2-engine-key.sql: engine key seeded (or already present) for "Tiron bby".
```

If instead you see "does not exist yet" notices, the backend isn't done
booting — go back to step 3.

## 5. Log in

Open the desktop client and log in as:

- Username: `Tiron bby` (with the space)
- Password: `AIMAN`

The engine (already running from step 2) authenticates as the same user
and should start showing up in the desktop client shortly after.

## Sanity-check without the desktop client

```
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"Tiron bby","password":"AIMAN"}'
```

Expect a 200 with a JWT and `"role":"ADMIN"`.

## Stopping

```
docker compose -f friend-compose.linux.yml down
```

Add `-v` to also wipe the database volume (next start will be a fresh
volume again — repeat step 4 after the backend's first boot).
