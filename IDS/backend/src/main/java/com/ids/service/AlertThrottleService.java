package com.ids.service;

import com.ids.config.ThrottleProperties;
import com.ids.model.Alert;
import com.ids.repository.MyWhitelistRepository;
import com.ids.repository.OrgWhitelistRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * Throttle-with-escalation for alerts from WHITELISTED (trusted) sources.
 *
 * Trusted hosts are never silenced outright: repeats inside the sliding
 * window are collapsed (SUPPRESS folds them into the open alert's
 * occurrence count), and the moment the rate crosses the per-detector
 * threshold, exactly ONE escalated HIGH alert is emitted — a trusted host
 * suddenly tripping the same detector many times is itself a signal of
 * possible compromise. Non-whitelisted sources bypass throttling entirely.
 */
@Service
public class AlertThrottleService {

    private static final Logger log = LoggerFactory.getLogger(AlertThrottleService.class);

    /**
     * The entire read-modify-write for one throttle key is this ONE statement.
     *
     * Why a single statement instead of SELECT-then-UPDATE in Java:
     * ingestion is multi-threaded (one request thread per engine POST), so a
     * Java read-modify-write would let two threads read the same event_count
     * and both write count+1 — a classic lost update, which would both
     * under-count and (worse) let two threads each observe "count reached
     * threshold" and emit TWO escalation alerts. With INSERT .. ON CONFLICT
     * DO UPDATE, Postgres takes the primary-key row lock before evaluating
     * the SET expressions, so concurrent calls on the same
     * (source_ip, detector_type, target_ip) key execute strictly one after
     * another and every increment lands: N calls always yield event_count=N.
     *
     * The three CASE expressions all hinge on the same staleness test
     * (window older than the detector's configured window):
     *   - stale  -> restart the window: window_start=now(), count=1, escalated=FALSE
     *   - fresh  -> count+1; escalated flips TRUE only on the call where the
     *               count first EQUALS the threshold and it wasn't already set.
     *
     * Why escalation fires exactly once per window: within a window the count
     * increments by exactly 1 per (serialized) call, so precisely one call
     * transitions the count onto the threshold value — that call flips
     * escalated and is the only one that can RETURN
     * (event_count = threshold AND escalated). Every later call in the same
     * window returns a higher count, and the flag itself blocks any re-flip
     * until the window resets it to FALSE.
     *
     * RETURNING exposes the post-update row, which is enough to classify:
     *   event_count = 1                         -> fresh insert or window reset  -> EMIT_LOW
     *   escalated AND event_count = threshold   -> THIS call flipped the flag    -> ESCALATE
     *   anything else                           -> inside a window, below/past    -> SUPPRESS
     */
    private static final String UPSERT_SQL = """
        INSERT INTO alert_throttle_state AS ts
            (source_ip, detector_type, target_ip, window_start, event_count, escalated)
        VALUES (?::inet, ?, ?::inet, now(), 1, FALSE)
        ON CONFLICT (source_ip, detector_type, target_ip) DO UPDATE SET
            window_start = CASE WHEN now() - ts.window_start > make_interval(secs => ?)
                                THEN now()
                                ELSE ts.window_start END,
            event_count  = CASE WHEN now() - ts.window_start > make_interval(secs => ?)
                                THEN 1
                                ELSE ts.event_count + 1 END,
            escalated    = CASE WHEN now() - ts.window_start > make_interval(secs => ?)
                                THEN FALSE
                                WHEN NOT ts.escalated AND ts.event_count + 1 = ?
                                THEN TRUE
                                ELSE ts.escalated END
        RETURNING event_count, escalated
        """;

    private final JdbcTemplate           jdbc;
    private final MyWhitelistRepository  myWhitelist;
    private final OrgWhitelistRepository orgWhitelist;
    private final ThrottleProperties     props;

    public AlertThrottleService(JdbcTemplate jdbc,
                                MyWhitelistRepository myWhitelist,
                                OrgWhitelistRepository orgWhitelist,
                                ThrottleProperties props) {
        this.jdbc         = jdbc;
        this.myWhitelist  = myWhitelist;
        this.orgWhitelist = orgWhitelist;
        this.props        = props;
    }

    public ThrottleDecision evaluate(Alert alert) {
        String sourceIp = alert.getSourceIp();
        String detector = alert.getThreatType();

        // No usable throttle key -> normal path, and never touch the DB.
        if (sourceIp == null || sourceIp.isBlank() || detector == null || detector.isBlank())
            return ThrottleDecision.EMIT_LOW;

        // Reuse the existing whitelist mechanism: the user's trusted hosts
        // plus approved organisation IPs. Only these are throttled.
        if (!isWhitelisted(sourceIp))
            return ThrottleDecision.EMIT_LOW;

        double windowSecs = props.getWindow(detector).toMillis() / 1000.0;
        int    threshold  = props.getThreshold(detector);
        String targetIp   = (alert.getDestIp() == null || alert.getDestIp().isBlank())
                          ? "0.0.0.0"   // PK column can't be null; sentinel for "no target"
                          : alert.getDestIp();

        try {
            Map<String, Object> row = jdbc.queryForMap(UPSERT_SQL,
                    sourceIp, detector, targetIp,
                    windowSecs, windowSecs, windowSecs, threshold);

            int     count     = ((Number)  row.get("event_count")).intValue();
            boolean escalated = (Boolean)  row.get("escalated");

            if (count == 1)                          return ThrottleDecision.EMIT_LOW;
            if (escalated && count == threshold)     return ThrottleDecision.ESCALATE;
            return ThrottleDecision.SUPPRESS;
        } catch (DataAccessException e) {
            // Fail OPEN: a throttle malfunction (bad inet literal, DB hiccup)
            // must never silence a real alert from a trusted host.
            log.warn("Throttle evaluation failed for {}/{} — emitting alert unthrottled",
                     sourceIp, detector, e);
            return ThrottleDecision.EMIT_LOW;
        }
    }

    private boolean isWhitelisted(String ip) {
        return myWhitelist.existsByIp(ip) || orgWhitelist.existsByIpAndApprovedTrue(ip);
    }

    /**
     * Bounds the state table: any row idle for more than twice the largest
     * configured window can no longer influence a decision (the staleness
     * CASE would reset it anyway), so it is safe to drop.
     */
    @Scheduled(fixedDelayString = "PT15M")
    public void purgeStaleState() {
        double horizonSecs = props.maxWindow().toMillis() / 1000.0 * 2;
        int purged = jdbc.update(
            "DELETE FROM alert_throttle_state WHERE now() - window_start > make_interval(secs => ?)",
            horizonSecs);
        if (purged > 0) log.debug("Purged {} stale throttle rows", purged);
    }
}
