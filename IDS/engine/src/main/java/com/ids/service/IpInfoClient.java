package com.ids.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;


import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;


public class IpInfoClient {

    private static final String BASE_URL = "https://ipinfo.io/%s/json";

    private final HttpClient   http   = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    private final ObjectMapper mapper = new ObjectMapper();

    public IpLookupResult lookup(String ip) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(String.format(BASE_URL, ip)))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();

            HttpResponse<String> res = http.send(req,
                    HttpResponse.BodyHandlers.ofString());

            if (res.statusCode() != 200) return IpLookupResult.unknown(ip);

            JsonNode node    = mapper.readTree(res.body());
            String   org     = node.path("org").asText("Unknown");
            String   country = node.path("country").asText("??");

            String asn     = org.contains(" ")
                    ? org.split(" ")[0] : "Unknown";
            String orgName = org.contains(" ")
                    ? org.substring(org.indexOf(" ") + 1) : org;

            return new IpLookupResult(ip, orgName, asn, country);

        } catch (Exception e) {
            System.err.println("[IpInfoClient] Lookup failed for "
                    + ip + ": " + e.getMessage());
            return IpLookupResult.unknown(ip);
        }
    }

    // Result record — this is the ONLY inner class here
    public record IpLookupResult(
            String ip, String orgName, String asn, String country) {

        public static IpLookupResult unknown(String ip) {
            return new IpLookupResult(ip, "Unknown", "Unknown", "??");
        }

        public boolean isKnown() {
            return !"Unknown".equals(orgName);
        }
    }
}