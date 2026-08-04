package com.ids.mobile.model;

/**
 * A single flagged source IP. Mirrors the JSON emitted by
 * GET /api/alerts/flagged-ips, field for field.
 *
 * Immutable for the same reason as HealthComponent: it crosses a thread
 * boundary from the poller to the RecyclerView adapter.
 */
public final class FlaggedIp {

    public final String ip;
    public final String mac;
    public final String organization;
    public final String asn;
    public final String country;
    public final String threatType;
    public final String protocol;
    public final String severity;
    public final int hits;
    public final String lastSeen;

    public FlaggedIp(String ip, String mac, String organization, String asn,
                     String country, String threatType, String protocol,
                     String severity, int hits, String lastSeen) {
        this.ip = ip;
        this.mac = mac;
        this.organization = organization;
        this.asn = asn;
        this.country = country;
        this.threatType = threatType;
        this.protocol = protocol;
        this.severity = severity == null ? "" : severity.toUpperCase();
        this.hits = hits;
        this.lastSeen = lastSeen;
    }

    /** "Cloudflare - US" / "Unknown" - whatever context we actually have. */
    public String describeOrigin() {
        StringBuilder sb = new StringBuilder();
        if (organization != null && !organization.isEmpty()) sb.append(organization);
        if (country != null && !country.isEmpty()) {
            if (sb.length() > 0) sb.append(" \u00b7 ");
            sb.append(country);
        }
        return sb.length() == 0 ? "Unknown origin" : sb.toString();
    }
}
