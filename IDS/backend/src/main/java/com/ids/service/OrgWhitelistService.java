package com.ids.service;

import com.ids.entity.OrgWhitelistEntry;
import com.ids.repository.OrgWhitelistRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class OrgWhitelistService {

    private final OrgWhitelistRepository repo;
    private final RestTemplate restTemplate;

    public OrgWhitelistService(OrgWhitelistRepository repo) {
        this.repo         = repo;
        this.restTemplate = new RestTemplate();
    }

    public List<OrgWhitelistEntry> getAll() { return repo.findAll(); }

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
            String url = "http://ip-api.com/json/" + ip + "?fields=org,as,country";

            @SuppressWarnings("unchecked")
            Map<String, Object> resp = (Map<String, Object>)
                    restTemplate.getForObject(url, Map.class);

            if (resp != null) {
                Object org     = resp.get("org");
                Object as      = resp.get("as");
                Object country = resp.get("country");
                entry.setOrgName(org     != null ? org.toString()     : "Unknown");
                entry.setAsn    (as      != null ? as.toString()      : "");
                entry.setCountry(country != null ? country.toString() : "");
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

    private boolean isPrivateIp(String ip) {
        return ip.startsWith("10.")
            || ip.startsWith("192.168.")
            || ip.startsWith("172.16.") || ip.startsWith("172.17.")
            || ip.startsWith("172.18.") || ip.startsWith("172.19.")
            || ip.startsWith("172.2")   || ip.startsWith("172.3")
            || ip.startsWith("127.")
            || ip.equals("::1");
    }
}