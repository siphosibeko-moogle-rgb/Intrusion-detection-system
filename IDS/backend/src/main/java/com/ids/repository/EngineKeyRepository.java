package com.ids.repository;

import com.ids.enums.EngineKeyStatus;
import com.ids.model.EngineKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface EngineKeyRepository extends JpaRepository<EngineKey, UUID> {

    List<EngineKey> findByOwnerIdOrderByCreatedAtDesc(Long ownerId);

    Optional<EngineKey> findByKeyHash(String keyHash);

    List<EngineKey> findByStatusOrderByCreatedAtAsc(EngineKeyStatus status);

    // Admin agents page: fetch owners in the same query so rendering the
    // table never lazy-loads users one by one.
    @Query("select k from EngineKey k join fetch k.owner order by k.createdAt desc")
    List<EngineKey> findAllWithOwner();

    // Single-column UPDATE so the ingest hot path never does an entity
    // read-modify-write just to record liveness.
    @Modifying
    @Query("update EngineKey k set k.lastSeenAt = :now where k.id = :id")
    void touchLastSeen(@Param("id") UUID id, @Param("now") Instant now);
}
