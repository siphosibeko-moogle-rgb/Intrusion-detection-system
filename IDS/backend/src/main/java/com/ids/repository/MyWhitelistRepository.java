package com.ids.repository;

import com.ids.entity.MyWhitelistEntry;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MyWhitelistRepository
        extends JpaRepository<MyWhitelistEntry, Long> {

    boolean existsByIp(String ip);
    boolean existsByMac(String mac);
}