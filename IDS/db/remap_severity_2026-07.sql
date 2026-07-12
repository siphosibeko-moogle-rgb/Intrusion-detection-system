-- Re-maps HISTORICAL alert rows to the severity scale introduced July 2026.
-- New alerts already arrive on the new scale (engine rule v2.0); this brings
-- rows written under the old scale in line so dashboards/reports are
-- consistent.
--
-- Idempotent: each UPDATE is scoped to (threat_type, old severity), so
-- running it twice changes nothing the second time. Rows that don't match
-- an old-scale value (e.g. already-new rows) are untouched.
--
-- Apply with:
--   docker exec -i ids_db psql -U <DB_USERNAME> -d ids_db < db/remap_severity_2026-07.sql
--
-- NOTE deliberately NOT remapped:
--   - NMAP_NULL/FIN/XMAS_SCAN stay HIGH (crafted-flag scans kept HIGH).
--   - GRATUITOUS_ARP rows at CRITICAL stay CRITICAL (those were gateway
--     impersonation — still CRITICAL on the new scale).

BEGIN;

-- SYN scan: recon, not compromise (HIGH → MEDIUM)
UPDATE alerts        SET severity = 'MEDIUM' WHERE threat_type = 'NMAP_SYN_SCAN'     AND severity = 'HIGH';
UPDATE alert_summary SET severity = 'MEDIUM' WHERE threat_type = 'NMAP_SYN_SCAN'     AND severity = 'HIGH';

-- Port sweep: unambiguous probing but still recon (CRITICAL → HIGH)
UPDATE alerts        SET severity = 'HIGH'   WHERE threat_type = 'NMAP_PORT_SWEEP'   AND severity = 'CRITICAL';
UPDATE alert_summary SET severity = 'HIGH'   WHERE threat_type = 'NMAP_PORT_SWEEP'   AND severity = 'CRITICAL';

-- Non-gateway gratuitous ARP: routine network behavior (MEDIUM → LOW)
UPDATE alerts        SET severity = 'LOW'    WHERE threat_type = 'GRATUITOUS_ARP'    AND severity = 'MEDIUM';
UPDATE alert_summary SET severity = 'LOW'    WHERE threat_type = 'GRATUITOUS_ARP'    AND severity = 'MEDIUM';

-- FTP session existing: policy observation (MEDIUM → LOW)
UPDATE alerts        SET severity = 'LOW'    WHERE threat_type = 'FTP_SESSION'       AND severity = 'MEDIUM';
UPDATE alert_summary SET severity = 'LOW'    WHERE threat_type = 'FTP_SESSION'       AND severity = 'MEDIUM';

-- SCP/SFTP transfer: routine admin activity, kept for correlation (MEDIUM → INFO)
UPDATE alerts        SET severity = 'INFO'   WHERE threat_type = 'SCP_SFTP_TRANSFER' AND severity = 'MEDIUM';
UPDATE alert_summary SET severity = 'INFO'   WHERE threat_type = 'SCP_SFTP_TRANSFER' AND severity = 'MEDIUM';

-- New-device events: common and benign on their own (MEDIUM → LOW).
-- WhitelistViolationDetector's IP path was still hardcoding MEDIUM (the
-- LOW floor can only raise, not lower) — fixed at the call site July 2026;
-- these bring the rows it wrote in line with the ARP path's LOW.
UPDATE alerts        SET severity = 'LOW'    WHERE threat_type = 'UNKNOWN_IP'        AND severity = 'MEDIUM';
UPDATE alert_summary SET severity = 'LOW'    WHERE threat_type = 'UNKNOWN_IP'        AND severity = 'MEDIUM';
UPDATE alerts        SET severity = 'LOW'    WHERE threat_type = 'UNKNOWN_MAC'       AND severity = 'MEDIUM';
UPDATE alert_summary SET severity = 'LOW'    WHERE threat_type = 'UNKNOWN_MAC'       AND severity = 'MEDIUM';

COMMIT;

-- Sanity check afterwards:
--   SELECT threat_type, severity, count(*) FROM alerts
--   GROUP BY 1, 2 ORDER BY 1, 2;
