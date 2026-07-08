package com.ids.detectors;

import com.ids.alerts.AlertManager;
import com.ids.models.PacketContext;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;
import com.ids.network.NetworkWhitelist;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Detects SQL injection attempts in HTTP request URIs and bodies.
 *
 * Signature-based, modeled on the OWASP ModSecurity CRS rule groups:
 * - TAUTOLOGY ' OR '1'='1 (auth bypass)
 * - UNION_SELECT UNION SELECT ... (data extraction)
 * - STACKED_QUERY ; DROP TABLE ... (destructive)
 * - TIME_BASED_BLIND SLEEP(), WAITFOR DELAY (blind exfiltration)
 * - COMMENT_TRUNCATION '-- , ')-- (query truncation)
 * - SCHEMA_ENUMERATION information_schema (recon)
 * - DB_COMMAND_EXEC xp_cmdshell (RCE via DB)
 *
 * Call analyze(ctx, httpPayload) — the same reconstructed HTTP request
 * string already used by HttpAnomalyDetector. The URI query string and
 * the request body are both URL-decoded before matching, because
 * attackers routinely percent-encode quotes/spaces/parens to dodge
 * naive string checks (e.g. %27%20OR%201=1 -> ' OR 1=1).
 *
 * FALSE POSITIVE / COVERAGE NOTES:
 * - No response correlation: every alert here means "someone sent
 *   SQL-injection-shaped bytes," not "an injection succeeded." A CRITICAL
 *   alert against a properly parameterized backend and the same alert
 *   against a raw-string-concatenation legacy app carry very different
 *   real urgency — this detector can't tell you which you're looking at.
 * - Any platform where users legitimately paste code/SQL as text
 *   (developer forums, ticketing systems, bug-bounty submission forms)
 *   will trigger this on people typing SQL as an example, not attacking
 *   with it. That's inherent to signature-based SQLi detection, not a bug.
 * - Same HTTPS blind spot as HttpAnomalyDetector: needs a plaintext HTTP
 *   request line, so it's blind on port 443 for the same reason.
 * - FIX: now skips known trusted scanners (your own sqlmap/Burp/DAST
 *   runs) via NetworkWhitelist.isTrustedScanner() — previously every
 *   request from your own authorized security testing fired every rule.
 */
public class SqlInjectionDetector implements Detector {

    private static final long COOLDOWN_MS = 10_000L;

    private enum Rule {

        TAUTOLOGY(
            Pattern.compile(
                "['\"]\\s*(or|and)\\s*['\"]?\\s*[\\w.]+\\s*(=|like|>|<)\\s*['\"]?\\s*[\\w.]+",
                Pattern.CASE_INSENSITIVE),
            Severity.HIGH, "Boolean-based tautology (authentication bypass attempt)"),

        UNION_SELECT(
            Pattern.compile("\\bunion\\b(\\s+all)?\\s+select\\b", Pattern.CASE_INSENSITIVE),
            Severity.CRITICAL, "UNION-based injection (data extraction attempt)"),

        STACKED_QUERY(
            Pattern.compile(";\\s*(drop|delete|insert|update|alter|truncate|exec|execute)\\b",
                Pattern.CASE_INSENSITIVE),
            Severity.CRITICAL, "Stacked query (destructive statement appended)"),

        TIME_BASED_BLIND(
            Pattern.compile("\\b(sleep|benchmark|pg_sleep)\\s*\\(|waitfor\\s+delay",
                Pattern.CASE_INSENSITIVE),
            Severity.CRITICAL, "Time-based blind injection"),

        COMMENT_TRUNCATION(
            Pattern.compile("['\")]\\s*(--|\\#|/\\*)", Pattern.CASE_INSENSITIVE),
            Severity.HIGH, "Query truncation via SQL comment"),

        SCHEMA_ENUMERATION(
            Pattern.compile("\\b(information_schema|sysobjects|syscolumns|pg_catalog)\\b",
                Pattern.CASE_INSENSITIVE),
            Severity.HIGH, "Database schema enumeration"),

        DB_COMMAND_EXEC(
            Pattern.compile("\\b(xp_cmdshell|sp_executesql|exec\\s*\\()", Pattern.CASE_INSENSITIVE),
            Severity.CRITICAL, "Database command execution attempt");

        final Pattern pattern;
        final Severity severity;
        final String description;

        Rule(Pattern pattern, Severity severity, String description) {
            this.pattern = pattern;
            this.severity = severity;
            this.description = description;
        }
    }

    // per "RULE:srcIP": last alert timestamp
    private final Map<String, Long> lastAlerts = new ConcurrentHashMap<>();

    private final AlertManager alertManager;
    private final NetworkWhitelist whitelist;

    public SqlInjectionDetector(AlertManager alertManager, NetworkWhitelist whitelist) {
        this.alertManager = alertManager;
        this.whitelist = whitelist;
    }

    public void analyze(PacketContext ctx, String httpPayload) {

        if (!ctx.isTcp()) return;

        int port = ctx.getDstPort();
        if (port != 80 && port != 8080 && port != 8000 && port != 443) return;

        if (httpPayload == null || httpPayload.isEmpty()) return;

        String srcIP = ctx.getSrcIp();
        String dstIP = ctx.getDstIp();
        String srcMac = ctx.getSrcMac();
        String dstMac = ctx.getDstMac();
        long now = ctx.getTimestamp();

        if (srcIP == null) return;

        // FIX: skip known, authorized security-testing tools before doing
        // any regex work — a single sqlmap/Burp scan can send thousands of
        // requests that would otherwise fire every rule in this file.
        if (whitelist.isTrustedScanner(srcIP)) return;

        String requestLine = firstLine(httpPayload);
        String uri = extractUri(requestLine);
        String query = extractQueryString(uri);
        String body = extractBody(httpPayload);

        String decodedQuery = urlDecode(query);
        String decodedBody = urlDecode(body);

        // One combined haystack: a payload split across query string and
        // body (common with multi-step forms) is still caught.
        String inspect = (decodedQuery == null ? "" : decodedQuery)
            + " " + (decodedBody == null ? "" : decodedBody);

        if (inspect.isBlank()) return;

        for (Rule rule : Rule.values()) {
            if (rule.pattern.matcher(inspect).find()) {
                raise(rule.name() + ":" + srcIP, ThreatType.SQL_INJECTION,
                    srcIP, srcMac, dstIP, dstMac, 1, now,
                    rule.description + " from " + srcIP + " on " + uri,
                    rule.severity, port);
                // No break: each rule has its own cooldown key, so a
                // payload tripping multiple categories raises multiple
                // distinct alerts — that correlation is valuable signal.
            }
        }
    }

    // ── helpers ─────────────────────────────────────────────────────

    private void raise(String key, ThreatType type,
                        String srcIP, String srcMac, String dstIP, String dstMac,
                        int count, long now, String details, Severity sev, int port) {
        Long last = lastAlerts.get(key);
        if (last != null && (now - last) < COOLDOWN_MS) return;
        lastAlerts.put(key, now);
        alertManager.raise(new ThreatEvent(
            type, srcIP, srcMac, dstIP, dstMac,
            count, 0L, details, sev, "TCP", "HTTP", port
        ));
    }

    private String firstLine(String payload) {
        int idx = payload.indexOf('\n');
        return (idx > 0 ? payload.substring(0, idx) : payload).trim();
    }

    private String extractUri(String requestLine) {
        String[] parts = requestLine.split(" ");
        return parts.length >= 2 ? parts[1] : null;
    }

    private String extractQueryString(String uri) {
        if (uri == null) return null;
        int idx = uri.indexOf('?');
        return idx >= 0 ? uri.substring(idx + 1) : null;
    }

    private String extractBody(String payload) {
        int idx = payload.indexOf("\r\n\r\n");
        if (idx < 0) idx = payload.indexOf("\n\n");
        if (idx < 0) return null;
        String body = payload.substring(idx + (payload.charAt(idx) == '\r' ? 4 : 2));
        return body.isBlank() ? null : body;
    }

    private String urlDecode(String s) {
        if (s == null) return null;
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s; // malformed % sequence — fall back to raw text
        }
    }

    @Override
    public void cleanup() {
        long now = System.currentTimeMillis();
        lastAlerts.entrySet().removeIf(e -> (now - e.getValue()) > COOLDOWN_MS * 4);
    }
}