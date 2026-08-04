package com.ids.service;

import com.ids.entity.TrustedNetworkEntry;
import com.ids.repository.TrustedNetworkRepository;
import com.ids.util.CidrUtils;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class TrustedNetworkService {

    private final TrustedNetworkRepository repo;

    public TrustedNetworkService(TrustedNetworkRepository repo) {
        this.repo = repo;
    }

    public List<TrustedNetworkEntry> getAll()     { return repo.findAll(); }
    public List<TrustedNetworkEntry> getEnabled() { return repo.findByEnabledTrue(); }

    /**
     * True if ip falls inside any ENABLED trusted_networks CIDR (Cloudflare,
     * AWS, Google, Azure, admin-added custom ranges, ...). Used by
     * AiTriageService as the "sourceTrustedNetwork" evidence flag — distinct
     * from OrgWhitelistService.isWhitelisted()/TrustedCidrRangeService,
     * which cover the separate approved-org-IP / internal-LAN trust systems.
     */
    public boolean isTrusted(String ip) {
        if (ip == null || ip.isBlank()) return false;
        for (TrustedNetworkEntry e : repo.findByEnabledTrue()) {
            if (CidrUtils.matches(ip, e.getCidr())) return true;
        }
        return false;
    }

    public TrustedNetworkEntry add(String cidr, String provider, String category,
                                   Boolean enabled, Boolean suppressBeaconing) {
        String normalized = requireValidCidr(cidr);
        if (provider == null || provider.isBlank()) {
            throw new IllegalArgumentException(
                "provider is required (e.g. Cloudflare, AWS, Google, Azure, Custom)");
        }
        if (repo.existsByCidr(normalized)) {
            throw new IllegalArgumentException("CIDR already exists: " + normalized);
        }
        TrustedNetworkEntry e = new TrustedNetworkEntry();
        e.setCidr(normalized);
        e.setProvider(provider.trim());
        e.setCategory(category == null || category.isBlank() ? null : category.trim());
        if (enabled != null)           e.setEnabled(enabled);
        if (suppressBeaconing != null) e.setSuppressBeaconing(suppressBeaconing);
        return repo.save(e);
    }

    /** Partial update: only keys present in {@code changes} are applied. */
    public TrustedNetworkEntry update(Long id, Map<String, Object> changes) {
        TrustedNetworkEntry e = repo.findById(id).orElseThrow(() ->
            new IllegalArgumentException("No trusted network with id " + id));

        if (changes.containsKey("cidr")) {
            e.setCidr(requireValidCidr((String) changes.get("cidr")));
        }
        if (changes.containsKey("provider")) {
            String provider = (String) changes.get("provider");
            if (provider == null || provider.isBlank()) {
                throw new IllegalArgumentException("provider cannot be blank");
            }
            e.setProvider(provider.trim());
        }
        if (changes.containsKey("category")) {
            String category = (String) changes.get("category");
            e.setCategory(category == null || category.isBlank() ? null : category.trim());
        }
        if (changes.containsKey("enabled")) {
            e.setEnabled(toBool(changes.get("enabled"), "enabled"));
        }
        if (changes.containsKey("suppressBeaconing")) {
            e.setSuppressBeaconing(toBool(changes.get("suppressBeaconing"), "suppressBeaconing"));
        }
        return repo.save(e);
    }

    public TrustedNetworkEntry setEnabled(Long id, boolean enabled) {
        return update(id, Map.of("enabled", enabled));
    }

    public void delete(Long id) { repo.deleteById(id); }

    /**
     * Validates an IPv4 CIDR string ("104.16.0.0/13") and returns it trimmed.
     * Fail loud on malformed input rather than silently storing garbage the
     * engine would ignore forever — same principle as the MAC validation in
     * the engine's NetworkWhitelist.loadProperties().
     * IPv4 only: the capture engine's matching is IPv4-only, so accepting an
     * IPv6 CIDR here would create an entry that silently never matches.
     */
    static String requireValidCidr(String cidr) {
        if (cidr == null || cidr.isBlank()) {
            throw new IllegalArgumentException("cidr is required (e.g. 104.16.0.0/13)");
        }
        String s = cidr.trim();
        int slash = s.indexOf('/');
        if (slash < 0) {
            throw new IllegalArgumentException(
                "Not a CIDR (missing /prefix): '" + s + "' — expected e.g. 104.16.0.0/13");
        }
        int prefix;
        try {
            prefix = Integer.parseInt(s.substring(slash + 1));
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("Invalid prefix length in '" + s + "'");
        }
        if (prefix < 0 || prefix > 32) {
            throw new IllegalArgumentException(
                "Prefix must be 0-32 (IPv4 only, IPv6 is not supported): '" + s + "'");
        }
        String[] octets = s.substring(0, slash).split("\\.", -1);
        if (octets.length != 4) {
            throw new IllegalArgumentException(
                "Invalid IPv4 address in '" + s + "' (IPv6 is not supported)");
        }
        for (String part : octets) {
            int octet;
            try {
                octet = Integer.parseInt(part);
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("Invalid IPv4 octet '" + part + "' in '" + s + "'");
            }
            if (octet < 0 || octet > 255) {
                throw new IllegalArgumentException("IPv4 octet out of range in '" + s + "'");
            }
        }
        return s;
    }

    private static boolean toBool(Object value, String field) {
        if (value instanceof Boolean b) return b;
        throw new IllegalArgumentException(field + " must be a boolean, got: " + value);
    }
}
