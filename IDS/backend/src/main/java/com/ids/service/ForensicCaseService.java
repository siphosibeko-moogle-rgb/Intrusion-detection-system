package com.ids.service;

import com.ids.model.ForensicCase;
import com.ids.model.PacketLog;
import com.ids.repository.ForensicCaseRepository;
import com.ids.repository.PacketLogRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Service
public class ForensicCaseService {

    private final ForensicCaseRepository caseRepo;
    private final PacketLogRepository packetRepo;

    public ForensicCaseService(ForensicCaseRepository caseRepo,
                               PacketLogRepository packetRepo) {
        this.caseRepo = caseRepo;
        this.packetRepo = packetRepo;
    }

    // ── CASES ─────────────────────────────────────

    public ForensicCase create(ForensicCase fc, String createdBy) {
        fc.setCreatedBy(createdBy);

        if (fc.getCaseNumber() == null || fc.getCaseNumber().isBlank()) {
            fc.setCaseNumber(generateCaseNumber());
        }

        return caseRepo.save(fc);
    }

    public ForensicCase update(Long id, ForensicCase patch, String byUser) {
        ForensicCase fc = caseRepo.findById(id)
                .orElseThrow(() -> new RuntimeException("Case not found: " + id));

        if (patch.getStatus() != null) fc.setStatus(patch.getStatus());
        if (patch.getAssignedTo() != null) fc.setAssignedTo(patch.getAssignedTo());
        if (patch.getFindings() != null) fc.setFindings(patch.getFindings());
        if (patch.getDescription() != null) fc.setDescription(patch.getDescription());
        if (patch.getSeverity() != null) fc.setSeverity(patch.getSeverity());

        if ("CLOSED".equals(patch.getStatus())) {
            fc.setClosedAt(Instant.now());
        }

        return caseRepo.save(fc);
    }

    public List<ForensicCase> getAll() {
        return caseRepo.findTop50ByOrderByOpenedAtDesc();
    }

    public Optional<ForensicCase> getById(Long id) {
        return caseRepo.findById(id);
    }

    public Optional<ForensicCase> getByNumber(String num) {
        return caseRepo.findByCaseNumber(num);
    }

    public List<ForensicCase> getByStatus(String status) {
        return caseRepo.findByStatusOrderByOpenedAtDesc(status);
    }

    public List<ForensicCase> getBySuspectIp(String ip) {
        return caseRepo.findBySuspectIpOrderByOpenedAtDesc(ip);
    }

    public List<ForensicCase> getBySuspectMac(String mac) {
        return caseRepo.findBySuspectMacOrderByOpenedAtDesc(mac);
    }

    public List<ForensicCase> getByAssignee(String user) {
        return caseRepo.findByAssignedToOrderByOpenedAtDesc(user);
    }

    public void delete(Long id) {
        caseRepo.deleteById(id);
    }

    // ── PACKETS ───────────────────────────────────

    public PacketLog savePacketLog(PacketLog log) {
        return packetRepo.save(log);
    }

    public Optional<PacketLog> getPacketById(Long id) {
        return packetRepo.findById(id);
    }

    public List<PacketLog> getPacketsByCase(Long caseId) {
        return packetRepo.findByCaseIdOrderByCapturedAtDesc(caseId);
    }

    public List<PacketLog> getPacketsByIp(String ip) {
        return packetRepo.findBySourceIpOrderByCapturedAtDesc(ip);
    }

    public List<PacketLog> getPacketsByMac(String mac) {
        return packetRepo.findBySourceMacOrderByCapturedAtDesc(mac);
    }

    public List<PacketLog> getRecentPackets() {
        return packetRepo.findTop200ByOrderByCapturedAtDesc();
    }

    // ── HELPERS ───────────────────────────────────

    private String generateCaseNumber() {
        int year = java.time.LocalDate.now().getYear();
        long seq = caseRepo.count() + 1;
        return String.format("CASE-%d-%03d", year, seq);
    }
}