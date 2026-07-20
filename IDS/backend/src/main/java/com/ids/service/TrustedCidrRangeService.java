package com.ids.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Property-driven internal/LAN CIDR trust list for the Dashboard
 * "Whitelisted" tab.
 *
 * OrgWhitelistService.upsertFromIp() deliberately never stores private IPs
 * (isPrivateIp() filters 10./192.168./172.16-31/127.), so hosts like
 * 10.50.0.11 (Docker subnet) or 192.168.8.109 (LAN) can never get an
 * approved org_whitelist row. This service covers that gap by matching
 * against CIDR ranges loaded once from backend config, independent of the
 * org table.
 *
 * NOT the same as TrustedNetworkService: that class is DB-backed
 * (trusted_networks table), admin-managed, and holds external provider
 * ranges (Cloudflare/AWS/Azure/etc.) used to suppress beaconing-detector
 * noise. This class is config-only, IPv4 LAN/Docker-subnet focused, and
 * only affects which Dashboard tab an actor renders under.
 */
@Service
public class TrustedCidrRangeService {

    private static final String DEFAULT_CIDRS =
            "10.0.0.0/8,192.168.0.0/16,172.16.0.0/12,127.0.0.0/8";

    /** Parsed once at construction: one {networkInt, maskInt} pair per valid CIDR. */
    private final List<long[]> ranges;

    public TrustedCidrRangeService(
            @Value("${ids.whitelist.trusted-cidrs:" + DEFAULT_CIDRS + "}") String configuredCidrs) {
        List<long[]> parsed = new ArrayList<>();
        for (String raw : configuredCidrs.split(",")) {
            String cidr = raw.trim();
            if (cidr.isEmpty()) continue;
            long[] pair = parseCidr(cidr);
            if (pair == null) {
                // Fail loud (log), but never crash startup over one bad entry.
                System.err.println("[TrustedCidrRangeService] Skipping malformed CIDR: '" + cidr + "'");
                continue;
            }
            parsed.add(pair);
        }
        this.ranges = Collections.unmodifiableList(parsed);
    }

    /** True if ip parses as IPv4 and falls inside any loaded trusted CIDR. */
    public boolean isTrustedRange(String ip) {
        Long ipInt = ipToLong(ip);
        if (ipInt == null) return false;
        for (long[] range : ranges) {
            if (cidrContains(range, ipInt)) return true;
        }
        return false;
    }

    private static boolean cidrContains(long[] networkAndMask, long ipInt) {
        long network = networkAndMask[0];
        long mask = networkAndMask[1];
        return (ipInt & mask) == (network & mask);
    }

    /** Parses "a.b.c.d/n" into {networkInt, maskInt}, or null if malformed. */
    private static long[] parseCidr(String cidr) {
        int slash = cidr.indexOf('/');
        if (slash < 0) return null;
        Long network = ipToLong(cidr.substring(0, slash));
        if (network == null) return null;
        int prefix;
        try {
            prefix = Integer.parseInt(cidr.substring(slash + 1).trim());
        } catch (NumberFormatException e) {
            return null;
        }
        if (prefix < 0 || prefix > 32) return null;
        long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        return new long[]{network, mask};
    }

    /** Parses "a.b.c.d" into a 32-bit unsigned int (held as long), or null if malformed. */
    private static Long ipToLong(String ip) {
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
