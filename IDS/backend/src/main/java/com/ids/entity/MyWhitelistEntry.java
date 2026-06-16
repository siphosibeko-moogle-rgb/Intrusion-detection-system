package com.ids.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "my_whitelist")
public class MyWhitelistEntry {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String ip;
    private String mac;
    private String label;
    private LocalDateTime addedAt = LocalDateTime.now();

    public Long          getId()      { return id; }
    public String        getIp()      { return ip; }
    public String        getMac()     { return mac; }
    public String        getLabel()   { return label; }
    public LocalDateTime getAddedAt() { return addedAt; }

    public void setIp(String ip)           { this.ip = ip; }
    public void setMac(String mac)         { this.mac = mac; }
    public void setLabel(String label)     { this.label = label; }
    public void setAddedAt(LocalDateTime t){ this.addedAt = t; }
}