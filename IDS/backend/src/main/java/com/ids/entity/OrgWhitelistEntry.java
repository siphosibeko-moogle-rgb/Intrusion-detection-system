package com.ids.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "org_whitelist")
public class OrgWhitelistEntry {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String ip;
    private String  orgName;
    private String  asn;
    private String  country;
    private int     hits     = 1;
    private boolean approved = false;
    private LocalDateTime firstSeen = LocalDateTime.now();
    private LocalDateTime lastSeen  = LocalDateTime.now();

    public Long          getId()        { return id; }
    public String        getIp()        { return ip; }
    public String        getOrgName()   { return orgName; }
    public String        getAsn()       { return asn; }
    public String        getCountry()   { return country; }
    public int           getHits()      { return hits; }
    public boolean       isApproved()   { return approved; }
    public LocalDateTime getFirstSeen() { return firstSeen; }
    public LocalDateTime getLastSeen()  { return lastSeen; }

    public void setIp(String ip)              { this.ip = ip; }
    public void setOrgName(String orgName)    { this.orgName = orgName; }
    public void setAsn(String asn)            { this.asn = asn; }
    public void setCountry(String country)    { this.country = country; }
    public void setHits(int hits)             { this.hits = hits; }
    public void setApproved(boolean approved) { this.approved = approved; }
    public void setLastSeen(LocalDateTime t)  { this.lastSeen = t; }
}