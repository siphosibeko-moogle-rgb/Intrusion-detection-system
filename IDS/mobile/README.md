# IDS Monitor — Android client

A **read-only** "quick glance" companion to the JavaFX desktop console.
It is a third client of the existing Spring Boot backend, alongside `desktop`.
It contains **no** engine code, **no** backend code, and requires **no**
backend changes.

## Two screens

| Screen | Endpoint | Poll |
|---|---|---|
| Status  | `GET /api/dashboard/health`   | 5s |
| Threats | `GET /api/alerts/flagged-ips` | 10s |

Plus `POST /api/auth/login` for the JWT.

There is no write path anywhere in this app. `ApiClient` exposes only `login()`
and two GETs — no post/put/patch/delete helper exists, so a write cannot be
added by accident.

## Open it in Android Studio, not Eclipse

Open the `mobile/` folder as its own project. Do **not** add it to the
engine/backend/desktop Maven reactor: those are plain JVM modules, this one
needs the Android Gradle Plugin. The only coupling is the HTTP API.

## Setting the backend URL

The default is `http://10.0.2.2:8080` — the **emulator's** alias for your host
machine's loopback.

On a **physical phone**, `localhost` means the phone itself, so that default
will never work. Enter your dev machine's LAN IP on the login screen
(e.g. `http://192.168.1.20:8080`). The URL is persisted in SharedPreferences;
the JWT and password are not persisted at all.

## Known caveat, surfaced in the UI

`DashboardController.health()` has no real sensor heartbeat. `packetCapture`
and `liveFeed` are inferred from *how long ago the last alert arrived*
(OK < 5min, WARN < 30min, else ERROR). **A genuinely quiet network is
indistinguishable from a dead capture engine.** The Status screen prints this
caveat rather than letting a green dot imply more than it means.

The fix, when you want it, is small and belongs on the engine side: have the
engine POST `/api/dashboard/heartbeat` every 10s using the same `X-Engine-Key`
auth `AlertController` already validates, and key liveness off `last_seen_at`
on `EngineKey` instead of off alert recency. Then this screen can show one row
per real sensor.

## Security notes

- `network_security_config.xml` permits cleartext HTTP so the app works against
  your current `http://` backend. **Delete it once the backend serves HTTPS.**
  Shipping JWTs in cleartext across a network you are port-mirroring is a real
  exposure — the mirror you configured on the TL-SG108E would capture the token.
- No credentials or tokens are written to disk. Killing the app forces re-login.
  That is deliberate for a device that gets lost or seized.

## Threading contract

`Poller` owns one daemon thread per screen. `start()` in `onResume()`,
`stop()` in `onPause()`. `start()` calls `stop()` first, so double-start cannot
leak — the same class of bug that bit the desktop client on re-login. Uses
`scheduleWithFixedDelay`, not `AtFixedRate`, so a slow or unreachable backend
self-throttles instead of building a backlog of overdue calls.

## Build

```
./gradlew :app:assembleDebug
```

(Run from `mobile/`. Android Studio will generate the Gradle wrapper on first
open if it is absent.)
