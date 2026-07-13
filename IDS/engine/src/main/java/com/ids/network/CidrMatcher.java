package com.ids.network;

/**
 * IPv4 CIDR block matcher: parses "104.16.0.0/13" into a base address +
 * prefix mask and answers containment queries.
 *
 * IPv4 only, by design — the rest of the engine (NetworkWhitelist's
 * normalize(), the detectors) is IPv4-centric, and half-supporting IPv6
 * here would just create entries that silently never match.
 *
 * matches() is allocation-free: it runs on the packet path, so the dotted
 * quad is parsed with a character walk instead of String.split(). Callers
 * with many ranges should convert the IP once via ipv4ToLong() and use
 * matches(long) in their loop.
 */
public final class CidrMatcher {

    private final String cidr;    // original text, for logging
    private final long   network; // base address with host bits masked off
    private final long   mask;    // prefix mask, e.g. /13 → 0xFFF80000

    private CidrMatcher(String cidr, long network, long mask) {
        this.cidr    = cidr;
        this.network = network;
        this.mask    = mask;
    }

    /** Parses an IPv4 CIDR string; returns null for anything malformed. */
    public static CidrMatcher parse(String s) {
        if (s == null) return null;
        String trimmed = s.trim();
        int slash = trimmed.indexOf('/');
        if (slash < 0) return null;
        long base = ipv4ToLong(trimmed.substring(0, slash));
        if (base < 0) return null;
        int prefix;
        try {
            prefix = Integer.parseInt(trimmed.substring(slash + 1));
        } catch (NumberFormatException e) {
            return null;
        }
        if (prefix < 0 || prefix > 32) return null;
        long mask = prefix == 0 ? 0 : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        return new CidrMatcher(trimmed, base & mask, mask);
    }

    /** True if the dotted-quad IPv4 address falls inside this block. */
    public boolean matches(String ip) {
        return matches(ipv4ToLong(ip));
    }

    /** Variant for callers that already converted via ipv4ToLong(). */
    public boolean matches(long ip) {
        return ip >= 0 && (ip & mask) == network;
    }

    public String getCidr() { return cidr; }

    @Override public String toString() { return cidr; }

    /**
     * Dotted-quad IPv4 → unsigned 32-bit value; -1 if not IPv4.
     * Character-walk parse — no split(), no substring, no allocation.
     */
    public static long ipv4ToLong(String ip) {
        if (ip == null || ip.isEmpty()) return -1;
        long value = 0;
        int octet = 0, digits = 0, dots = 0;
        for (int i = 0; i < ip.length(); i++) {
            char c = ip.charAt(i);
            if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
                if (++digits > 3 || octet > 255) return -1;
            } else if (c == '.') {
                if (digits == 0 || ++dots > 3) return -1;
                value = (value << 8) | octet;
                octet = 0;
                digits = 0;
            } else {
                return -1; // anything non-digit/non-dot (incl. IPv6 colons)
            }
        }
        if (dots != 3 || digits == 0) return -1;
        return (value << 8) | octet;
    }
}
