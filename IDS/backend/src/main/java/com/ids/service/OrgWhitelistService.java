package com.ids.service;

import com.ids.entity.OrgWhitelistEntry;
import com.ids.repository.OrgWhitelistRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
public class OrgWhitelistService {

    private final OrgWhitelistRepository repo;
    private final RestTemplate restTemplate;
    private final TrustedCidrRangeService trustedCidrRanges;

    public OrgWhitelistService(OrgWhitelistRepository repo, TrustedCidrRangeService trustedCidrRanges) {
        this.repo              = repo;
        this.restTemplate      = new RestTemplate();
        this.trustedCidrRanges = trustedCidrRanges;
    }

    public List<OrgWhitelistEntry> getAll() { return repo.findAll(); }

    /**
     * True if EITHER an approved org_whitelist row matches this exact IP, OR
     * the IP falls inside a trusted internal CIDR range (see
     * TrustedCidrRangeService — covers private IPs, which upsertFromIp()
     * never stores here). Exact-IP checked first as the fast path.
     */
    public boolean isWhitelisted(String ip) {
        if (ip == null || ip.isBlank()) return false;
        boolean approvedExact = repo.findByIp(ip)
                   .map(OrgWhitelistEntry::isApproved) // WHITELIST_RULE: approved-only for org table.
                   .orElse(false);                     // flip to .isPresent() for "any entry present"
        if (approvedExact) return true;
        return trustedCidrRanges.isTrustedRange(ip);
    }

    // ── Organization discovery (used by the Flagged IPs view) ────────────
    // org_whitelist doubles as the lookup cache: one row per external IP,
    // enriched once via ip-api.com and reused forever after.

    private final ExecutorService lookupExecutor =
        Executors.newFixedThreadPool(2, r -> {
            Thread t = new Thread(r, "org-lookup");
            t.setDaemon(true);
            return t;
        });
    private final Set<String> lookupsInFlight = ConcurrentHashMap.newKeySet();

    /** Cached org entries for the given IPs, keyed by IP — one query. */
    public Map<String, OrgWhitelistEntry> getByIps(Collection<String> ips) {
        if (ips == null || ips.isEmpty()) return Map.of();
        Map<String, OrgWhitelistEntry> out = new HashMap<>();
        for (OrgWhitelistEntry e : repo.findByIpIn(ips)) out.put(e.getIp(), e);
        return out;
    }

    /** Approved exact-match org IPs among the given set — one query. */
    public Set<String> approvedIpsAmong(Collection<String> ips) {
        if (ips == null || ips.isEmpty()) return Set.of();
        Set<String> out = new HashSet<>();
        for (OrgWhitelistEntry e : repo.findByIpIn(ips)) {
            if (e.isApproved()) out.add(e.getIp());
        }
        return out;
    }

    /**
     * Queues an organization lookup for an IP that has no cached row yet.
     * Delegates to upsertFromIp() — the single org-lookup implementation
     * (DB-cache check, ip-api.com call, "Unknown" stored on failure) — on a
     * small daemon pool so callers (the flagged-ips endpoint) never block on
     * the external API. The in-flight set stops the same IP being queued
     * repeatedly while its first lookup is still running.
     */
    public void lookupAsync(String ip) {
        if (ip == null || ip.isBlank() || isPrivateIp(ip)) return;
        if (!lookupsInFlight.add(ip)) return;
        lookupExecutor.submit(() -> {
            try {
                upsertFromIp(ip);
            } catch (Exception e) {
                System.err.println("[OrgWhitelist] Async lookup failed for "
                    + ip + ": " + e.getMessage());
            } finally {
                lookupsInFlight.remove(ip);
            }
        });
    }

    public void upsertFromIp(String ip) {
        if (ip == null || ip.isBlank() || isPrivateIp(ip)) return;

        Optional<OrgWhitelistEntry> existing = repo.findByIp(ip);
        if (existing.isPresent()) {
            OrgWhitelistEntry e = existing.get();
            e.setHits(e.getHits() + 1);
            e.setLastSeen(LocalDateTime.now());
            repo.save(e);
            return;
        }

        OrgWhitelistEntry entry = new OrgWhitelistEntry();
        entry.setIp(ip);
        entry.setHits(1);
        entry.setApproved(false);

        try {
            // countryCode, not country: the column is VARCHAR(10) ("US"),
            // and ip-api's `country` is the full name ("United States"),
            // which overflows it and fails the insert.
            String url = "http://ip-api.com/json/" + ip + "?fields=org,as,countryCode";

            @SuppressWarnings("unchecked")
            Map<String, Object> resp = (Map<String, Object>)
                    restTemplate.getForObject(url, Map.class);

            if (resp != null) {
                Object org     = resp.get("org");
                Object as      = resp.get("as");
                Object country = resp.get("countryCode");
                // Blank org must become "Unknown": a stored blank reads as
                // "never looked up" to consumers and would re-queue the
                // lookup forever.
                entry.setOrgName(org != null && !org.toString().isBlank()
                        ? org.toString() : "Unknown");
                // Keep just the AS number ("AS15169"): the column is
                // VARCHAR(20) and ip-api's full string ("AS396982 Google
                // Cloud Platform") can overflow it.
                String asn = as != null ? as.toString() : "";
                int space = asn.indexOf(' ');
                entry.setAsn(space > 0 ? asn.substring(0, space) : asn);
                entry.setCountry(country != null ? country.toString() : "");
            } else {
                entry.setOrgName("Unknown");
            }
        } catch (Exception e) {
            entry.setOrgName("Unknown");
            entry.setAsn("");
            entry.setCountry("");
        }

        repo.save(entry);
    }

    public void recordOrUpdate(String ip, String orgName,
                               String asn, String country) {
        repo.findByIp(ip).ifPresentOrElse(e -> {
            e.setHits(e.getHits() + 1);
            e.setLastSeen(LocalDateTime.now());
            repo.save(e);
        }, () -> {
            OrgWhitelistEntry e = new OrgWhitelistEntry();
            e.setIp(ip); e.setOrgName(orgName);
            e.setAsn(asn); e.setCountry(country);
            repo.save(e);
        });
    }

    public void approve(Long id) {
        repo.findById(id).ifPresent(e -> {
            e.setApproved(true); repo.save(e); });
    }

    public void approveAll() {
        repo.findAll().forEach(e -> {
            e.setApproved(true); repo.save(e); });
    }

    public void delete(Long id) { repo.deleteById(id); }

    public static boolean isPrivateIp(String ip) {
        return ip.startsWith("10.")
            || ip.startsWith("192.168.")
            || ip.startsWith("172.16.") || ip.startsWith("172.17.")
            || ip.startsWith("172.18.") || ip.startsWith("172.19.")
            || ip.startsWith("172.2")   || ip.startsWith("172.3")
            || ip.startsWith("127.")
            || ip.equals("::1");
    }
}