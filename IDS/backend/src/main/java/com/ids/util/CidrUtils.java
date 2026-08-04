package com.ids.util;

/**
 * Minimal IPv4 exact-IP/CIDR matching, shared by AiTriageService's
 * critical-asset check and TrustedNetworkService.isTrusted(). Mirrors the
 * arithmetic in TrustedCidrRangeService, kept separate here to avoid
 * touching that class's stable, already-reviewed config-loading path.
 */
public final class CidrUtils {

    private CidrUtils() { }

    /** True if ip equals target exactly, or target is a CIDR containing ip. */
    public static boolean matches(String ip, String target) {
        if (ip == null || target == null || target.isBlank()) return false;
        String t = target.trim();
        if (ip.equals(t)) return true;

        int slash = t.indexOf('/');
        if (slash < 0) return false;

        Long network = ipToLong(t.substring(0, slash));
        Long ipLong = ipToLong(ip);
        if (network == null || ipLong == null) return false;

        int prefix;
        try {
            prefix = Integer.parseInt(t.substring(slash + 1).trim());
        } catch (NumberFormatException e) {
            return false;
        }
        if (prefix < 0 || prefix > 32) return false;

        long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        return (ipLong & mask) == (network & mask);
    }

    /** Parses "a.b.c.d" into a 32-bit unsigned int (held as long), or null if malformed. */
    public static Long ipToLong(String ip) {
        if (ip == null) return null;
        String[] octets = ip.trim().split("\\.", -1);
        if (octets.length != 4) return null;
        long result = 0;
        for (String part : octets) {
            int octet;
            try {
                octet = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                return null;
            }
            if (octet < 0 || octet > 255) return null;
            result = (result << 8) | octet;
        }
        return result;
    }
}
