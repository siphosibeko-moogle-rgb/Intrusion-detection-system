package com.ids.repository;

import com.ids.entity.TrustedNetworkEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface TrustedNetworkRepository
        extends JpaRepository<TrustedNetworkEntry, Long> {

    List<TrustedNetworkEntry> findByEnabledTrue();
    List<TrustedNetworkEntry> findBySource(String source);
    boolean existsByCidr(String cidr);
}
