package com.ids.service;

import com.ids.config.ThrottleProperties;
import com.ids.model.Alert;
import com.ids.repository.MyWhitelistRepository;
import com.ids.repository.OrgWhitelistRepository;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Exercises the real ON CONFLICT upsert against a live Postgres. Enabled only
 * when IDS_TEST_DB_URL is set (plus IDS_TEST_DB_USER / IDS_TEST_DB_PASS),
 * e.g. against the docker-compose db:
 *
 *   IDS_TEST_DB_URL=jdbc:postgresql://localhost:5432/ids_db \
 *   IDS_TEST_DB_USER=... IDS_TEST_DB_PASS=... mvn -pl backend test
 *
 * The Postgres-specific SQL (INET, ON CONFLICT .. RETURNING, make_interval)
 * cannot run on an in-memory H2, and faking it would defeat the point: the
 * whole guarantee under test lives in Postgres's row-lock semantics.
 */
@EnabledIfEnvironmentVariable(named = "IDS_TEST_DB_URL", matches = ".+")
class AlertThrottleServicePostgresTest {

    private static final String TRUSTED_IP = "10.99.99.1";
    private static final int    THRESHOLD  = 5;

    private static JdbcTemplate jdbc;
    private AlertThrottleService service;

    @BeforeAll
    static void connectAndApplySchema() {
        DriverManagerDataSource ds = new DriverManagerDataSource(
            System.getenv("IDS_TEST_DB_URL"),
            System.getenv("IDS_TEST_DB_USER"),
            System.getenv("IDS_TEST_DB_PASS"));
        jdbc = new JdbcTemplate(ds);
        // Same plain SQL file the app runs at startup — idempotent.
        new ResourceDatabasePopulator(
            new ClassPathResource("db/alert_throttle_schema.sql")).execute(ds);
    }

    @BeforeEach
    void freshStateAndService() {
        jdbc.update("DELETE FROM alert_throttle_state");

        MyWhitelistRepository  my  = mock(MyWhitelistRepository.class);
        OrgWhitelistRepository org = mock(OrgWhitelistRepository.class);
        when(my.existsByIp(TRUSTED_IP)).thenReturn(true);

        service = new AlertThrottleService(jdbc, my, org,
            new ThrottleProperties(
                new ThrottleProperties.Policy(Duration.ofMinutes(10), THRESHOLD),
                Map.of()));
    }

    private static Alert trustedAlert(String detector) {
        Alert a = new Alert();
        a.setSourceIp(TRUSTED_IP);
        a.setThreatType(detector);
        a.setDestIp("10.99.99.200");
        return a;
    }

    @Test
    void sequenceWithinWindow_firstEmits_middleSuppresses_thresholdEscalatesExactlyOnce() {
        Alert a = trustedAlert("PORT_SCAN");

        assertEquals(ThrottleDecision.EMIT_LOW, service.evaluate(a), "1st event opens the window");
        for (int i = 2; i < THRESHOLD; i++) {
            assertEquals(ThrottleDecision.SUPPRESS, service.evaluate(a), "event " + i + " is deduped");
        }
        assertEquals(ThrottleDecision.ESCALATE, service.evaluate(a),
                     "the threshold-th event escalates");
        assertEquals(ThrottleDecision.SUPPRESS, service.evaluate(a),
                     "past the threshold, the escalated flag blocks any re-escalation");
        assertEquals(ThrottleDecision.SUPPRESS, service.evaluate(a));

        assertEquals(THRESHOLD + 2, (int) jdbc.queryForObject(
            "SELECT event_count FROM alert_throttle_state", Integer.class));
    }

    @Test
    void expiredWindowResetsToEmitLow() {
        Alert a = trustedAlert("BRUTE_FORCE");
        service.evaluate(a);
        service.evaluate(a); // count = 2 inside the window

        // Backdate the window past the 10m limit instead of sleeping.
        jdbc.update("UPDATE alert_throttle_state SET window_start = now() - interval '11 minutes'");

        assertEquals(ThrottleDecision.EMIT_LOW, service.evaluate(a),
                     "a stale window resets: count back to 1, escalated back to false");
        Map<String, Object> row = jdbc.queryForMap(
            "SELECT event_count, escalated FROM alert_throttle_state");
        assertEquals(1, ((Number) row.get("event_count")).intValue());
        assertEquals(Boolean.FALSE, row.get("escalated"));
    }

    @Test
    void nonWhitelistedSourceCreatesNoStateRow() {
        Alert a = new Alert();
        a.setSourceIp("203.0.113.77"); // mocks return false for anything but TRUSTED_IP
        a.setThreatType("PORT_SCAN");

        assertEquals(ThrottleDecision.EMIT_LOW, service.evaluate(a));
        assertEquals(0, (int) jdbc.queryForObject(
            "SELECT count(*) FROM alert_throttle_state", Integer.class));
    }

    /**
     * N threads hammer the same key simultaneously. If the upsert were a
     * read-then-write in Java, threads would overwrite each other's
     * increments (final count < N) and several could observe the threshold
     * crossing (multiple ESCALATEs). The single-statement upsert serializes
     * on the row lock, so we require BOTH: exactly one ESCALATE and a final
     * event_count of exactly N — no lost updates.
     */
    @Test
    void concurrentEvaluationsProduceExactlyOneEscalateAndNoLostUpdates() throws Exception {
        final int N = 32;
        Alert a = trustedAlert("DDOS");

        ConcurrentLinkedQueue<ThrottleDecision> decisions = new ConcurrentLinkedQueue<>();
        CyclicBarrier start = new CyclicBarrier(N);
        CountDownLatch done = new CountDownLatch(N);
        ExecutorService pool = Executors.newFixedThreadPool(N);
        try {
            for (int i = 0; i < N; i++) {
                pool.execute(() -> {
                    try {
                        start.await();
                        decisions.add(service.evaluate(a));
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    } finally {
                        done.countDown();
                    }
                });
            }
            assertTrue(done.await(30, java.util.concurrent.TimeUnit.SECONDS), "threads finished");
        } finally {
            pool.shutdownNow();
        }

        List<ThrottleDecision> all = List.copyOf(decisions);
        assertEquals(N, all.size());
        assertEquals(1, all.stream().filter(d -> d == ThrottleDecision.ESCALATE).count(),
                     "exactly one thread must win the escalation flip");
        assertEquals(1, all.stream().filter(d -> d == ThrottleDecision.EMIT_LOW).count(),
                     "exactly one thread inserts/opens the window");
        assertEquals(N - 2, all.stream().filter(d -> d == ThrottleDecision.SUPPRESS).count());

        assertEquals(N, (int) jdbc.queryForObject(
            "SELECT event_count FROM alert_throttle_state", Integer.class),
            "every increment must land — a lost update would leave count < N");
    }
}
