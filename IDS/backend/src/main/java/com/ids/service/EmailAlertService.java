package com.ids.service;

import com.ids.model.Alert;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Service
public class EmailAlertService {

    private static final DateTimeFormatter FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                         .withZone(ZoneId.systemDefault());

    // Optional so Spring doesn't blow up when mail is not configured
    private final Optional<JavaMailSender> mailSender;

    @Value("${ids.email.enabled:false}")
    private boolean enabled;

    @Value("${ids.email.alert.to:security@company.com}")
    private String alertTo;

    @Value("${ids.email.alert.severities:CRITICAL,HIGH}")
    private String alertSeverities;

    @Value("${spring.mail.username:noreply@ids.local}")
    private String fromAddress;

    // Spring injects Optional<JavaMailSender> — if no bean exists, it's Optional.empty()
    public EmailAlertService(Optional<JavaMailSender> mailSender) {
        this.mailSender = mailSender;
    }

    @Async
    public void sendAlertEmail(Alert alert) {
        if (!enabled) return;

        if (mailSender.isEmpty()) {
            System.err.println("[EmailAlertService] Email is enabled but no mail server configured. " +
                               "Add spring.mail.host to application.properties.");
            return;
        }

        List<String> triggerSeverities = Arrays.asList(alertSeverities.split(","));
        if (!triggerSeverities.contains(alert.getSeverity())) return;

        try {
            SimpleMailMessage msg = new SimpleMailMessage();
            msg.setFrom(fromAddress);
            msg.setTo(alertTo);
            msg.setSubject("[IDS ALERT] " + alert.getSeverity() + " — " + alert.getThreatType());
            msg.setText(buildEmailBody(alert));
            mailSender.get().send(msg);
        } catch (Exception e) {
            System.err.println("[EmailAlertService] Failed to send email: " + e.getMessage());
        }
    }

    private String buildEmailBody(Alert alert) {
        return """
               IDS NETWORK INTRUSION ALERT
               ═══════════════════════════════════════════
               
               Threat Type  : %s
               Severity     : %s
               Timestamp    : %s
               
               ── Attacker Fingerprint ──────────────────
               Source IP    : %s
               Source MAC   : %s
               Destination  : %s
               
               ── Traffic Details ───────────────────────
               Protocol     : %s
               Request Type : %s
               Packet Count : %d packets in %dms
               
               ── Details ───────────────────────────────
               %s
               
               ═══════════════════════════════════════════
               This is an automated alert from your IDS.
               """.formatted(
                alert.getThreatType(),
                alert.getSeverity(),
                alert.getTimestamp() != null ? FMT.format(alert.getTimestamp()) : "N/A",
                alert.getSourceIp(),
                alert.getSourceMac(),
                alert.getDestIp(),
                alert.getProtocol(),
                alert.getRequestType(),
                alert.getPacketCount(),
                alert.getWindowMs(),
                alert.getDetails()
        );
    }
}