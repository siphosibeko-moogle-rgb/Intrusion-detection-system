package com.ids.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * A curated, admin-seeded provider CIDR range (Cloudflare, AWS, Google,
 * Azure, …). Deliberately a separate table from org_whitelist: these
 * entries are rare-change reference data with no per-IP hit counter or
 * auto-discovery lifecycle.
 */
@Entity
@Table(name = "trusted_networks")
public class TrustedNetworkEntry {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String cidr;

    @Column(nullable = false)
    private String provider;

    private String category;

    @Column(nullable = false)
    private boolean enabled = true;

    // SECURITY: defaults to FALSE and must stay that way. A trusted_networks
    // match only quiets unknown-IP/rogue-IP noise; beaconing detection stays
    // on unless an admin explicitly flips this per range — modern C2 hides on
    // Cloudflare Workers / AWS Lambda URLs / Azure Front Door precisely
    // because defenders blanket-trust those ranges.
    @Column(nullable = false)
    private boolean suppressBeaconing = false;

    // Where the entry came from. MANUAL for admin-added rows; reserved for a
    // future provider-feed sync job (which would stamp its own source value).
    @Column(nullable = false)
    private String source = "MANUAL";

    private LocalDateTime createdAt = LocalDateTime.now();
    private LocalDateTime updatedAt = LocalDateTime.now();

    @PreUpdate
    void touchUpdatedAt() { this.updatedAt = LocalDateTime.now(); }

    public Long          getId()                 { return id; }
    public String        getCidr()               { return cidr; }
    public String        getProvider()           { return provider; }
    public String        getCategory()           { return category; }
    public boolean       isEnabled()             { return enabled; }
    public boolean       isSuppressBeaconing()   { return suppressBeaconing; }
    public String        getSource()             { return source; }
    public LocalDateTime getCreatedAt()          { return createdAt; }
    public LocalDateTime getUpdatedAt()          { return updatedAt; }

    public void setCidr(String cidr)                     { this.cidr = cidr; }
    public void setProvider(String provider)             { this.provider = provider; }
    public void setCategory(String category)             { this.category = category; }
    public void setEnabled(boolean enabled)              { this.enabled = enabled; }
    public void setSuppressBeaconing(boolean suppress)   { this.suppressBeaconing = suppress; }
    public void setSource(String source)                 { this.source = source; }
}
