package com.ids.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure parsers for the published provider IP-range feeds. No I/O in here —
 * each method takes the already-fetched body, so every format quirk is unit
 * testable without a network.
 *
 * All parsers are IPv4-only (the engine's matching is IPv4-only) and drop
 * anything that fails strict CIDR validation rather than letting a feed
 * format change inject garbage rows.
 */
final class ProviderFeedParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ProviderFeedParser() {}

    /** One candidate row from a feed: the CIDR plus a category hint
     *  (AWS service name, Azure tag name, …). */
    record FeedRange(String cidr, String category) {}

    /** Cloudflare https://www.cloudflare.com/ips-v4 — plain text, one CIDR per line. */
    static List<FeedRange> parseCloudflareText(String body) {
        List<FeedRange> out = new ArrayList<>();
        for (String line : body.split("\n")) {
            String s = line.trim();
            if (s.isEmpty() || s.startsWith("#")) continue;
            if (isValidIpv4Cidr(s)) out.add(new FeedRange(s, "CDN"));
        }
        return out;
    }

    /**
     * AWS https://ip-ranges.amazonaws.com/ip-ranges.json — keeps prefixes whose
     * "service" is in {@code services} (uppercase; the literal "ALL" keeps every
     * service — beware, that's ~7k+ prefixes and the engine scans ranges
     * linearly per packet). The same prefix often appears under several
     * services (AMAZON + EC2); first match wins.
     */
    static List<FeedRange> parseAwsIpRanges(String json, Set<String> services) throws Exception {
        boolean all = services.contains("ALL");
        Map<String, String> seen = new LinkedHashMap<>();
        for (JsonNode p : MAPPER.readTree(json).path("prefixes")) {
            String service = p.path("service").asText("");
            if (!all && !services.contains(service.toUpperCase())) continue;
            String cidr = p.path("ip_prefix").asText("").trim();
            if (isValidIpv4Cidr(cidr)) seen.putIfAbsent(cidr, service);
        }
        List<FeedRange> out = new ArrayList<>(seen.size());
        seen.forEach((cidr, service) -> out.add(new FeedRange(cidr, service)));
        return out;
    }

    /** Google https://www.gstatic.com/ipranges/goog.json — entries carry either
     *  ipv4Prefix or ipv6Prefix; only the former is kept. */
    static List<FeedRange> parseGoogleRanges(String json) throws Exception {
        List<FeedRange> out = new ArrayList<>();
        for (JsonNode p : MAPPER.readTree(json).path("prefixes")) {
            String cidr = p.path("ipv4Prefix").asText("").trim();
            if (isValidIpv4Cidr(cidr)) out.add(new FeedRange(cidr, "Google"));
        }
        return out;
    }

    /**
     * Azure ServiceTags_Public JSON — keeps addressPrefixes of service tags
     * whose "name" is in {@code tags} (case-insensitive). IPv6 prefixes in
     * the tag are skipped by validation.
     */
    static List<FeedRange> parseAzureServiceTags(String json, Set<String> tags) throws Exception {
        Set<String> wanted = new java.util.HashSet<>();
        for (String t : tags) wanted.add(t.toUpperCase());
        Map<String, String> seen = new LinkedHashMap<>();
        for (JsonNode value : MAPPER.readTree(json).path("values")) {
            String name = value.path("name").asText("");
            if (!wanted.contains(name.toUpperCase())) continue;
            for (JsonNode prefix : value.path("properties").path("addressPrefixes")) {
                String cidr = prefix.asText("").trim();
                if (isValidIpv4Cidr(cidr)) seen.putIfAbsent(cidr, name);
            }
        }
        List<FeedRange> out = new ArrayList<>(seen.size());
        seen.forEach((cidr, tag) -> out.add(new FeedRange(cidr, tag)));
        return out;
    }

    // Microsoft publishes ServiceTags at a URL that changes with every weekly
    // release; the stable entry point is the download-confirmation page, which
    // embeds the current file URL.
    private static final Pattern AZURE_JSON_URL = Pattern.compile(
        "https://download\\.microsoft\\.com/[^\"'\\s]*ServiceTags_Public_\\d{8}\\.json");

    /** Extracts the current ServiceTags JSON URL from the download page HTML;
     *  null if the page layout changed and no URL was found. */
    static String extractAzureDownloadUrl(String html) {
        if (html == null) return null;
        Matcher m = AZURE_JSON_URL.matcher(html);
        return m.find() ? m.group() : null;
    }

    private static boolean isValidIpv4Cidr(String s) {
        if (s == null || s.isEmpty()) return false;
        try {
            TrustedNetworkService.requireValidCidr(s);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
