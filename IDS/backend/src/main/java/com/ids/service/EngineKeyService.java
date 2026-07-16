package com.ids.service;

import com.ids.dto.EngineKeyView;
import com.ids.enums.EngineKeyStatus;
import com.ids.model.EngineKey;
import com.ids.model.User;
import com.ids.repository.AlertRepository;
import com.ids.repository.EngineKeyRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Engine key lifecycle: PENDING (requested) -> ACTIVE (admin approved,
 * key material generated) -> REVOKED (rejected or revoked).
 *
 * The raw key is 32 SecureRandom bytes, base64url-encoded. Only its SHA-256
 * hex digest is persisted — SHA-256 without a KDF is deliberate: the token
 * has 256 bits of entropy, so it is not brute-forceable the way a password
 * is. The raw key is returned from approve() exactly once and never logged.
 */
@Service
public class EngineKeyService {

    private final EngineKeyRepository repo;
    private final AlertRepository     alertRepo;
    private final SecureRandom random = new SecureRandom();

    public EngineKeyService(EngineKeyRepository repo, AlertRepository alertRepo) {
        this.repo      = repo;
        this.alertRepo = alertRepo;
    }

    public List<EngineKey> getKeysForOwner(Long ownerId) {
        return repo.findByOwnerIdOrderByCreatedAtDesc(ownerId);
    }

    public List<EngineKey> getByStatus(EngineKeyStatus status) {
        return repo.findByStatusOrderByCreatedAtAsc(status);
    }

    /**
     * Status rows for /engines — ownership is enforced inside both queries
     * (keys by owner_id, counts by engine_keys.owner_id), never by
     * post-filtering. Two queries total, independent of key count.
     */
    @Transactional(readOnly = true)
    public List<EngineKeyView> getViewsForOwner(Long ownerId) {
        Map<UUID, Long> counts = toCountMap(alertRepo.countPerEngineKeyForOwner(ownerId));
        Instant now = Instant.now();
        return repo.findByOwnerIdOrderByCreatedAtDesc(ownerId).stream()
                   .map(k -> toView(k, counts, now))
                   .toList();
    }

    /**
     * Status rows for /admin/agents — two queries total regardless of key
     * count: keys fetch-joined with owners, plus one grouped alert count.
     */
    @Transactional(readOnly = true)
    public List<EngineKeyView> getAllViews() {
        Map<UUID, Long> counts = toCountMap(alertRepo.countPerEngineKey());
        Instant now = Instant.now();
        return repo.findAllWithOwner().stream()
                   .map(k -> toView(k, counts, now))
                   .toList();
    }

    private static Map<UUID, Long> toCountMap(List<Object[]> rows) {
        Map<UUID, Long> m = new HashMap<>();
        for (Object[] r : rows) m.put((UUID) r[0], ((Number) r[1]).longValue());
        return m;
    }

    private static EngineKeyView toView(EngineKey k, Map<UUID, Long> counts, Instant now) {
        return new EngineKeyView(
            k.getOwner().getUsername(), k.getName(), k.getKeyPrefix(), k.getStatus(),
            k.getCreatedAt(), k.getApprovedAt(),
            SensorLiveness.of(k.getStatus(), k.getLastSeenAt(), now),
            SensorLiveness.relative(k.getLastSeenAt(), now),
            counts.getOrDefault(k.getId(), 0L));
    }

    /** User requests a key: row only, no key material until approval. */
    @Transactional
    public EngineKey request(User owner, String name) {
        return repo.save(new EngineKey(owner, name));
    }

    /**
     * Admin approves a PENDING request: generates the key, stores hash +
     * prefix, activates the row. Returns the RAW key — the only time it
     * ever leaves this method. Callers must show it once and drop it.
     */
    @Transactional
    public String approve(UUID id, User admin) {
        EngineKey key = repo.findById(id)
            .orElseThrow(() -> new IllegalArgumentException("No such key request"));
        if (key.getStatus() != EngineKeyStatus.PENDING)
            throw new IllegalStateException("Only PENDING requests can be approved");

        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String rawKey = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        key.setKeyHash(sha256Hex(rawKey));
        key.setKeyPrefix(rawKey.substring(0, 8));
        key.setStatus(EngineKeyStatus.ACTIVE);
        key.setApprovedAt(Instant.now());
        key.setApprovedBy(admin);
        repo.save(key);

        return rawKey;
    }

    /** Reject a PENDING request or revoke an ACTIVE key — both end REVOKED. */
    @Transactional
    public void revoke(UUID id) {
        EngineKey key = repo.findById(id)
            .orElseThrow(() -> new IllegalArgumentException("No such key"));
        if (key.getStatus() == EngineKeyStatus.REVOKED)
            return;
        key.setStatus(EngineKeyStatus.REVOKED);
        key.setRevokedAt(Instant.now());
        repo.save(key);
    }

    // Liveness granularity: skip the last_seen_at write if it advanced
    // within this window, so a chatty sensor costs one UPDATE per 30s,
    // not one per alert.
    private static final Duration LAST_SEEN_GRANULARITY = Duration.ofSeconds(30);

    /**
     * Ingest auth: hash the presented key, look it up, require ACTIVE.
     * PENDING/REVOKED/unknown all fail — empty Optional. Never log rawKey
     * here or in callers.
     *
     * On success, returns the key so callers can attribute what they ingest,
     * and records liveness via a throttled single-column UPDATE (never an
     * entity save on this path). lastSeenAt on the returned instance may
     * therefore lag by up to the granularity window.
     */
    @Transactional
    public Optional<EngineKey> authenticate(String rawKey) {
        if (rawKey == null || rawKey.isBlank())
            return Optional.empty();
        Optional<EngineKey> key = repo.findByKeyHash(sha256Hex(rawKey))
                .filter(k -> k.getStatus() == EngineKeyStatus.ACTIVE);
        key.ifPresent(k -> {
            Instant now = Instant.now();
            if (k.getLastSeenAt() == null
                    || k.getLastSeenAt().isBefore(now.minus(LAST_SEEN_GRANULARITY))) {
                repo.touchLastSeen(k.getId(), now);
            }
        });
        return key;
    }

    /** Boolean form of {@link #authenticate} for callers that don't attribute. */
    @Transactional
    public boolean isActiveKey(String rawKey) {
        return authenticate(rawKey).isPresent();
    }

    private static String sha256Hex(String value) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(
                md.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
