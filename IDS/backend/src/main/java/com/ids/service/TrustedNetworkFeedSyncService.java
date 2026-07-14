package com.ids.service;

import com.ids.entity.TrustedNetworkEntry;
import com.ids.repository.TrustedNetworkRepository;
import com.ids.service.ProviderFeedParser.FeedRange;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Syncs trusted_networks from the providers' published IP-range feeds.
 *
 * Ownership model: this job only ever creates or deletes rows whose `source`
 * is one of the *_FEED markers below. MANUAL and SEED rows are never touched,
 * and rows that survive a sync keep whatever `enabled`/`suppress_beaconing`
 * an admin set on them — new rows always arrive with suppress_beaconing=false
 * (the same security default as everywhere else in this feature).
 *
 * Failure model: each provider syncs independently inside its own try/catch.
 * A fetch/parse failure — or a feed that parses to zero ranges — aborts that
 * provider's reconciliation entirely, so a transient outage or a feed format
 * change can never mass-delete existing trust. Mirrors the engine's
 * keep-last-known-good behavior on its side of the fence.
 *
 * Scheduling: the manual trigger (POST /api/trusted-networks/sync) always
 * works; the cron run is opt-in via ids.trusted-networks.sync.enabled.
 */
@Service
public class TrustedNetworkFeedSyncService {

    private static final String CLOUDFLARE_URL = "https://www.cloudflare.com/ips-v4";
    private static final String AWS_URL        = "https://ip-ranges.amazonaws.com/ip-ranges.json";
    private static final String GOOGLE_URL     = "https://www.gstatic.com/ipranges/goog.json";
    // Stable entry point; the actual JSON URL changes weekly and is scraped
    // from this page — see ProviderFeedParser.extractAzureDownloadUrl().
    private static final String AZURE_PAGE_URL =
        "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519";

    private final TrustedNetworkRepository repo;

    @Value("${ids.trusted-networks.sync.enabled:false}")
    private boolean scheduledSyncEnabled;

    // Default CLOUDFRONT only: AWS's full feed is ~7k+ IPv4 prefixes and the
    // engine scans ranges linearly per packet — opt in to more services (or
    // "ALL") deliberately, not by default.
    @Value("${ids.trusted-networks.sync.aws.services:CLOUDFRONT}")
    private List<String> awsServices;

    // Same reasoning: the full ServiceTags file is ~40k prefixes.
    @Value("${ids.trusted-networks.sync.azure.tags:AzureFrontDoor.Frontend}")
    private List<String> azureTags;

    private final HttpClient http = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build();

    public TrustedNetworkFeedSyncService(TrustedNetworkRepository repo) {
        this.repo = repo;
    }

    @Scheduled(cron = "${ids.trusted-networks.sync.cron:0 0 4 * * *}")
    void scheduledSync() {
        if (!scheduledSyncEnabled) return;
        Map<String, String> results = syncAll();
        results.forEach((provider, summary) ->
            System.out.println("[FeedSync] " + provider + ": " + summary));
    }

    /** Runs every provider feed; returns a per-provider human-readable summary.
     *  synchronized so a manual trigger and the cron can't reconcile concurrently. */
    public synchronized Map<String, String> syncAll() {
        Map<String, String> results = new LinkedHashMap<>();
        results.put("Cloudflare", syncProvider("Cloudflare", "CLOUDFLARE_FEED",
            () -> ProviderFeedParser.parseCloudflareText(fetch(CLOUDFLARE_URL))));
        results.put("AWS", syncProvider("AWS", "AWS_FEED",
            () -> ProviderFeedParser.parseAwsIpRanges(fetch(AWS_URL), upper(awsServices))));
        results.put("Google", syncProvider("Google", "GOOGLE_FEED",
            () -> ProviderFeedParser.parseGoogleRanges(fetch(GOOGLE_URL))));
        results.put("Azure", syncProvider("Azure", "AZURE_FEED", this::fetchAzureRanges));
        return results;
    }

    @FunctionalInterface
    private interface FeedFetcher {
        List<FeedRange> fetch() throws Exception;
    }

    private String syncProvider(String provider, String source, FeedFetcher fetcher) {
        try {
            List<FeedRange> feed = fetcher.fetch();
            if (feed.isEmpty()) {
                throw new IllegalStateException(
                    "feed returned no IPv4 ranges — refusing to reconcile");
            }

            Map<String, String> feedByCidr = new LinkedHashMap<>();
            for (FeedRange r : feed) feedByCidr.putIfAbsent(r.cidr(), r.category());

            // Deletions: only rows THIS feed created that the feed no longer lists.
            List<TrustedNetworkEntry> owned = repo.findBySource(source);
            List<TrustedNetworkEntry> toRemove = new ArrayList<>();
            for (TrustedNetworkEntry row : owned) {
                if (!feedByCidr.containsKey(row.getCidr())) toRemove.add(row);
            }

            // Additions: feed CIDRs not present under ANY source. A CIDR that
            // already exists as MANUAL/SEED stays as-is (no duplicate row, no
            // ownership takeover — cidr is UNIQUE anyway).
            Set<String> existingCidrs = new HashSet<>();
            for (TrustedNetworkEntry row : repo.findAll()) existingCidrs.add(row.getCidr());
            List<TrustedNetworkEntry> toAdd = new ArrayList<>();
            feedByCidr.forEach((cidr, category) -> {
                if (existingCidrs.contains(cidr)) return;
                TrustedNetworkEntry e = new TrustedNetworkEntry();
                e.setCidr(cidr);
                e.setProvider(provider);
                e.setCategory(category);
                e.setSource(source);
                // enabled=true, suppressBeaconing=false — entity defaults
                toAdd.add(e);
            });

            repo.deleteAll(toRemove);
            repo.saveAll(toAdd);

            int kept = owned.size() - toRemove.size();
            return String.format("added %d, removed %d, kept %d (feed has %d ranges)",
                toAdd.size(), toRemove.size(), kept, feedByCidr.size());

        } catch (Exception e) {
            String msg = "FAILED: " + e.getMessage() + " — existing rows left untouched";
            System.err.println("[FeedSync] " + provider + " " + msg);
            return msg;
        }
    }

    private List<FeedRange> fetchAzureRanges() throws Exception {
        String page = fetch(AZURE_PAGE_URL);
        String jsonUrl = ProviderFeedParser.extractAzureDownloadUrl(page);
        if (jsonUrl == null) {
            throw new IllegalStateException("could not find ServiceTags JSON URL on "
                + "the Microsoft download page (page layout may have changed)");
        }
        return ProviderFeedParser.parseAzureServiceTags(fetch(jsonUrl), upper(azureTags));
    }

    private String fetch(String url) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(60))
            // Microsoft's download page hangs/redirect-loops for non-browser
            // User-Agents (verified: "Mozilla/5.0 (compatible; …)" gets a 302
            // loop, a full browser UA gets the page). Send a browser-shaped UA
            // for every feed; the other providers don't care.
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                + "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
            .GET()
            .build();
        HttpResponse<String> response =
            http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("HTTP " + response.statusCode() + " from " + url);
        }
        return response.body();
    }

    private static Set<String> upper(List<String> values) {
        Set<String> out = new HashSet<>();
        for (String v : values) {
            String t = v.trim();
            if (!t.isEmpty()) out.add(t.toUpperCase());
        }
        return out;
    }
}
