# IDS friend test bundle

Everything you need to run the IDS on **one machine**: PostgreSQL + the
backend + the live-capture engine, and log in with the desktop client.

- Login: **`Tiron bby`** (with a space) / **`AIMAN`**
- The engine authenticates as that same user, plus a pre-seeded ingest key
  — no web approval step needed.

This `share/` folder must stay where it is, alongside `backend/`, `engine/`,
`db/`, etc. — it builds from that source, it doesn't replace it.

In a hurry? `LAUNCH.md` has just the launch commands, no explanation.

Pick your path below depending on your OS.

---

## LINUX — everything in Docker

1. Build the jars once (from the `IDS/` project root, one level up from here):
   ```
   mvn -pl backend,engine package
   ```
2. From inside `share/`:
   ```
   docker compose -f friend-compose.linux.yml --env-file .env up -d --build
   ```
3. Watch it come up:
   ```
   docker compose -f friend-compose.linux.yml logs -f backend
   ```
4. Open the desktop client (build/run `IDS/desktop` separately) and log in
   as `Tiron bby` / `AIMAN`.

The engine uses `network_mode: host` so it can see real traffic on this
machine and reach the backend at `http://localhost:8080`. It needs
`NET_RAW`/`NET_ADMIN` + `apparmor:unconfined`, both already set in
`friend-compose.linux.yml`.

If auto-detect (`IDS_CAPTURE_IFACE=all` in `.env`) picks the wrong NIC, set
`IDS_CAPTURE_IFACE` in `.env` to a specific interface name (`ip a` to list
them) and re-run `docker compose ... up -d`.

---

## WINDOWS / MAC — native engine, Docker for db + backend only

Docker Desktop can't do raw packet capture against your real interfaces the
way Linux host networking can, so here the engine runs natively and only
`db` + `backend` are containers.

1. Install [Npcap](https://npcap.com/#download) — check **"WinPcap API
   compatible mode"** during install.
2. Build the jars once (from the `IDS/` project root):
   ```
   mvn -pl backend,engine package
   ```
3. From inside `share/`:
   ```
   docker compose -f friend-compose.desktop.yml --env-file .env up -d --build
   ```
4. Confirm the backend is up and you can log in via the desktop client as
   `Tiron bby` / `AIMAN` before starting the engine — the engine's own login
   will fail loudly if the admin account or backend aren't ready yet.
5. Run the engine (PowerShell, from inside `share/`):
   ```
   .\run-engine-native.ps1
   ```
   On Mac, run the equivalent by hand instead of the `.ps1`:
   ```
   export IDS_ENGINE_USER="Tiron bby"
   export IDS_ENGINE_PASS="AIMAN"
   export IDS_ENGINE_KEY="piQLNx4vEFAmJ1IaMC1993hv9x8IpyQ7ij9J7orJGp8"
   java -jar ../engine/target/engine-1.0.0.jar all http://localhost:8080
   ```
   (Packet capture on macOS may need `sudo` for the `java` invocation.)

---

## Why the engine key might not work on the very *first* boot

`init2-engine-key.sql` seeds the ACTIVE engine key by inserting straight
into the `engine_keys` table. But that table doesn't exist until the
backend has started at least once — it's created by Hibernate
(`ddl-auto=update`), not by the schema SQL. Likewise, the `Tiron bby` user
row doesn't exist until the backend's admin-bootstrap step has run once.
Both of those only happen the *first time the backend container starts* —
which is necessarily after Postgres has already finished running its
one-time init scripts on a fresh volume.

So: on a completely fresh volume, `init2-engine-key.sql` runs, finds neither
the table nor the user yet, logs a `NOTICE`, and does nothing (it will not
error your DB init). This is expected, not a bug.

**Fix — re-run the seed once, after the backend's first successful boot:**

```
docker compose -f friend-compose.linux.yml exec -T db \
  psql -U ids_user -d ids_db < init2-engine-key.sql
```

(swap `friend-compose.linux.yml` for `friend-compose.desktop.yml` on
Windows/Mac). Check the backend logs first to confirm you see
`Bootstrap: created initial ADMIN account 'Tiron bby'` — if you don't see
that line yet, the backend hasn't finished starting, and re-running the
seed will just log the same "does not exist yet" notices again.

You only need to do this once. After it succeeds you'll see:
```
NOTICE:  init2-engine-key.sql: engine key seeded (or already present) for "Tiron bby".
```

---

## No alerts showing up?

- **Engine login failing** — check engine logs for the `/api/auth/login`
  call. `IDS_ENGINE_USER`/`IDS_ENGINE_PASS` in `.env` must be `Tiron bby` /
  `AIMAN` exactly, and the admin account must already exist (see above).
- **Engine logs in fine but nothing shows up in the desktop client** — the
  ingest key probably hasn't been seeded yet. Run the manual re-seed command
  above, then restart the engine (`docker compose ... restart engine` on
  Linux, or just re-run `run-engine-native.ps1`).
- **Wrong network interface (Linux)** — `all` auto-detects, but on a
  multi-NIC box it can guess wrong. Set `IDS_CAPTURE_IFACE` in `.env` to a
  specific interface and restart the engine.
- **No admin traffic to alert on** — the IDS needs to actually see packets.
  Generate some traffic on the same machine/network segment (a browser
  session, `ping`, `curl` to a few hosts) and give it a minute; some
  detections (e.g. beaconing) need repeated activity to trigger.
- **Backend healthcheck never turns healthy** — `docker compose -f
  friend-compose.linux.yml logs backend` and check for a datasource
  connection error; confirm `db` is healthy first
  (`docker compose ... ps`).

---

## Files in this bundle

| File | Purpose |
|---|---|
| `.env` | Real credentials/config for both compose files — spaced admin username, engine key, JWT secret placeholder (replace it). |
| `db/IDS_db.sql` | Copy of the real schema, used as the Postgres init script. |
| `init2-engine-key.sql` | Seeds the ACTIVE engine ingest key for `Tiron bby` (see timing note above). |
| `friend-compose.linux.yml` | db + backend + engine, engine on host networking. |
| `friend-compose.desktop.yml` | db + backend only — engine runs natively via `run-engine-native.ps1` (Windows) or by hand (Mac). |
| `run-engine-native.ps1` | Windows native engine launcher. |
