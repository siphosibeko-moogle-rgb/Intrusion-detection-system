package com.ids.service;

import com.ids.service.IpInfoClient.IpLookupResult;
// ✅ No Spring imports — engine is plain Java
// ✅ No OrgWhitelistService — engine calls backend REST instead

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

// Plain Java — no Spring annotations
public class OrgDiscoveryService {

    private final IpInfoClient ipInfo;

    // Backend REST endpoint to record discovered orgs
    private final String backendUrl;
    private final String backendToken;

    private final Set<String> lookupCache = Collections.newSetFromMap(
            new ConcurrentHashMap<>());
    private final ExecutorService executor =
            Executors.newFixedThreadPool(3);

    private final AtomicInteger dailyCount  = new AtomicInteger(0);
    private static final int    DAILY_LIMIT = 1000;

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public OrgDiscoveryService(IpInfoClient ipInfo,
                                String backendUrl,
                                String backendToken) {
        this.ipInfo       = ipInfo;
        this.backendUrl   = backendUrl;
        this.backendToken = backendToken;
    }

    public void discoverAsync(String ip) {
        if (ip == null || isInternal(ip) || lookupCache.contains(ip)) return;
        if (dailyCount.get() >= DAILY_LIMIT) {
            System.err.println("[OrgDiscovery] Daily limit reached — skipping " + ip);
            return;
        }
        dailyCount.incrementAndGet();
        lookupCache.add(ip);

        executor.submit(() -> {
            try {
                IpLookupResult result = ipInfo.lookup(ip);

                // POST result directly to backend REST endpoint
                String json = String.format(
                    "{\"ip\":\"%s\",\"orgName\":\"%s\",\"asn\":\"%s\",\"country\":\"%s\"}",
                    result.ip(), result.orgName(), result.asn(), result.country()
                );

                HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(backendUrl + "/api/org-whitelist/discover"))
                    .header("Authorization", "Bearer " + backendToken)
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(5))
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

                http.send(req, HttpResponse.BodyHandlers.ofString());

                System.out.printf("[OrgDiscovery] %s → %s (%s) [%s]%n",
                    result.ip(), result.orgName(),
                    result.asn(), result.country());

            } catch (Exception e) {
                System.err.println("[OrgDiscovery] Failed for "
                    + ip + ": " + e.getMessage());
            }
        });
    }

    // Reset daily count — called manually at midnight
    // (no @Scheduled — engine has no Spring)
    public void resetDailyCount() { dailyCount.set(0); }

    public void shutdown() { executor.shutdownNow(); }

    private boolean isInternal(String ip) {
        return ip.startsWith("192.168.") ||
               ip.startsWith("10.")      ||
               ip.startsWith("172.16.")  ||
               ip.startsWith("172.17.")  ||
               ip.startsWith("172.18.")  ||
               ip.startsWith("127.")     ||
               ip.startsWith("224.")     ||
               ip.startsWith("239.")     ||
               ip.equals("255.255.255.255");
    }
}