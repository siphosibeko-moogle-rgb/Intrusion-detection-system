# AI Triage Sweep — Hardening Test Guide

Verifies the fix in `AiTriageSweepScheduler`/`AlertSummaryRepository` that stops
a malformed `alert_summary` row (NULL `packet_count`/`window_ms`) from
permanently wedging the sweep. See `AlertSummaryKeyProjection` for the
mechanism: the candidate scan uses a closed projection that can never fail to
hydrate, and the full-entity fetch (which can fail) happens per-candidate
inside its own try/catch.

## 1. Enable the feature and bring the stack up

```bash
cd /home/twon/Desktop/intrusion-detection-system/IDS
echo "IDS_AI_TRIAGE_ENABLED=true" >> .env
echo "IDS_AI_TRIAGE_SWEEP_MS=10000" >> .env   # faster ticks for testing
docker compose up -d --build db backend
docker compose logs -f backend   # watch until "Started BackendApplication"
```
(`Ctrl+C` out of the log tail once it's up — the container keeps running.)

## 2. Get a JWT

```bash
curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"<your admin user>","password":"<your admin pass>"}'
```
Save the `token` field as `$TOKEN`.

## 3. Seed the exact scenario that used to break the sweep

Malformed row first (NULL `packet_count`/`window_ms`), then a healthy row right
after it with a *newer* `last_seen`, so both land in the same sweep batch:

```bash
docker compose exec db psql -U ids_user -d ids_db -c "
INSERT INTO alert_summary
  (source_ip, threat_type, severity, source_mac, dest_ip, dest_mac,
   protocol, request_type, details, occurrence_count, first_seen, last_seen)
VALUES
  ('10.99.9.1','MALFORMED_TEST','HIGH','aa:aa:aa:aa:aa:01','10.0.0.5','bb:bb:bb:bb:bb:01',
   'TCP','SCAN','test',5, now(), now()),
  ('10.99.9.2','HEALTHY_TEST','HIGH','aa:aa:aa:aa:aa:02','10.0.0.5','bb:bb:bb:bb:bb:02',
   'TCP','SCAN','test',5, now(), now() + interval '1 second')
ON CONFLICT DO NOTHING;
"
```
(Note the malformed insert deliberately omits `packet_count`/`window_ms` —
they're nullable columns.)

## 4. Wait one sweep tick (~10s), then check

```bash
sleep 12
curl -s -o /dev/null -w "malformed -> %{http_code}\n" \
  -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/triage/10.99.9.1/MALFORMED_TEST
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/triage/10.99.9.2/HEALTHY_TEST | jq .
```
Expect: malformed → `404` (never got a verdict). Healthy → `200` with a full
verdict body.

## 5. Confirm the WARN and check it didn't loop

```bash
docker compose logs backend | grep "10.99.9.1/MALFORMED_TEST"
```
Expect exactly **one**
`[AiTriage] Sweep failed for 10.99.9.1/MALFORMED_TEST: ...` line, no stack
trace, no repeats across subsequent ticks.

## 6. Prove the high-water mark advanced (not just this batch)

Seed one more row on a *later* tick and confirm it still analyzes normally:

```bash
docker compose exec db psql -U ids_user -d ids_db -c "
INSERT INTO alert_summary
  (source_ip, threat_type, severity, source_mac, dest_ip, dest_mac,
   protocol, request_type, details, packet_count, window_ms, occurrence_count, first_seen, last_seen)
VALUES
  ('10.99.9.3','FOLLOWUP_TEST','HIGH','aa:aa:aa:aa:aa:03','10.0.0.5','bb:bb:bb:bb:bb:03',
   'TCP','SCAN','test',0,0,5, now(), now());
"
sleep 12
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/triage/10.99.9.3/FOLLOWUP_TEST | jq .
docker compose logs backend | grep -c "10.99.9.1/MALFORMED_TEST"   # should still be 1
```
If the follow-up row triages successfully and the malformed-row WARN count is
still `1`, the fix is confirmed working — the sweep skipped the bad row
cleanly and moved on for good, rather than getting stuck retrying it every
tick.

## 7. Cleanup

```bash
docker compose exec db psql -U ids_user -d ids_db -c "
DELETE FROM triage_verdict WHERE source_ip LIKE '10.99.9.%';
DELETE FROM alert_summary WHERE source_ip LIKE '10.99.9.%';
"
```
And revert `.env` if you don't want the feature left on:
```bash
sed -i '/IDS_AI_TRIAGE_ENABLED/d;/IDS_AI_TRIAGE_SWEEP_MS/d' .env
docker compose up -d backend
```
