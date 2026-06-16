package com.ids.repository;

import com.ids.entity.OrgWhitelistEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface OrgWhitelistRepository
        extends JpaRepository<OrgWhitelistEntry, Long> {

    boolean existsByIpAndApprovedTrue(String ip);

	Optional<OrgWhitelistEntry> findByIp(String ip);
}