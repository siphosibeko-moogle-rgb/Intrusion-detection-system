package com.ids.detectors;

import com.ids.alerts.AlertManager;
import com.ids.models.PacketContext;
import com.ids.models.PacketRecord;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;
import com.ids.network.NetworkWhitelist;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class AfterHoursDetector implements Detector {

    private static final Set<Integer> SENSITIVE_PORTS = Set.of(
        22,3389,445,139,
        3306,5432,1433, 27017,
        389, 636, 88,
        8080, 8443, 9200
    );

    private static final int MIN_PACKETS = 10;
    private static final long COOLDOWN_MS = 300_000L;

    private final Map<String, PacketRecord> activityMap = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAlerts = new ConcurrentHashMap<>();

    private final AlertManager alertManager;
    // FIX: replaced the local String subnetPrefix + extractPrefix() with the
    // shared NetworkWhitelist instance. The old local check was
    //   ip.startsWith(subnetPrefix) || ip.startsWith("10.") || ip.startsWith("192.168.")
    // which meant ANY 10.x or 192.168.x address was "internal" regardless of
    // what subnet was actually configured — too broad, and it duplicated logic
    // that NetworkWhitelist.isInternal() already gets right (including Docker
    // subnet support via network.docker.subnets). One source of truth now.
    private final NetworkWhitelist whitelist;
    private final int workStartHour;
    private final int workEndHour;
    private final ZoneId timezone;
    private final boolean alertWeekends;

    public AfterHoursDetector(AlertManager alertManager,
                               NetworkWhitelist whitelist,
                               int workStartHour,
                               int workEndHour,
                               String timezoneId,
                               boolean alertWeekends) {

        this.alertManager = alertManager;
        this.whitelist = whitelist;
        this.workStartHour = workStartHour;
        this.workEndHour = workEndHour;
        this.alertWeekends = alertWeekends;

        ZoneId tz;
        try { tz = ZoneId.of(timezoneId); }
        catch (Exception e) { tz = ZoneId.of("Africa/Johannesburg"); }
        this.timezone = tz;
    }

    public void analyze(PacketContext ctx) {

        if (ctx.getSrcIp() == null) return;

        String srcIP = ctx.getSrcIp();
        String dstIP = ctx.getDstIp();
        String srcMac = ctx.getSrcMac();
        String dstMac = ctx.getDstMac();

        if (!whitelist.isInternal(srcIP)) return;
        if (srcIP.startsWith("127.")) return;

        long now = System.currentTimeMillis();
        ZonedDateTime zdt = Instant.ofEpochMilli(now).atZone(timezone);

        int hour = zdt.getHour();
        int dow = zdt.getDayOfWeek().getValue();

        boolean isWeekend = dow >= 6;
        boolean isAfterHours = hour < workStartHour || hour >= workEndHour;

        if (!isAfterHours && !(isWeekend && alertWeekends)) return;

        PacketRecord rec = activityMap.computeIfAbsent(srcIP,
            k -> new PacketRecord(srcIP, srcMac));

        rec.addAfterHoursTimestamp(now);

        int windowPackets = rec.getAfterHoursWindowCount(now);
        if (windowPackets < MIN_PACKETS) return;

        int dstPort = ctx.getDstPort();
        boolean sensitive = SENSITIVE_PORTS.contains(dstPort);

        String proto = ctx.getProtocol();
        String timeStr = zdt.format(DateTimeFormatter.ofPattern("HH:mm"));

        // WEEKEND
        if (isWeekend && alertWeekends) {
            String key = "WEEKEND:" + srcIP;

            if (shouldAlert(key, now)) {
                alertManager.raise(new ThreatEvent(
                    ThreatType.WEEKEND_ACCESS,
                    srcIP, srcMac,
                    dstIP, dstMac,
                    windowPackets, 60_000L,
                    "Weekend activity: " + srcIP + " at " + timeStr,
                    sensitive ? Severity.HIGH : Severity.MEDIUM,
                    proto, "WEEKEND", dstPort
                ));
            }
        }

        // AFTER HOURS
        if (isAfterHours && !isWeekend) {
            String key = "AFTER:" + srcIP;

            if (shouldAlert(key, now)) {

                boolean lateNight = hour < 5;
                Severity sev = (lateNight && sensitive) ? Severity.CRITICAL
                    : (lateNight || sensitive) ? Severity.HIGH
                    : Severity.MEDIUM;

                alertManager.raise(new ThreatEvent(
                    ThreatType.AFTER_HOURS_ACCESS,
                    srcIP, srcMac,
                    dstIP, dstMac,
                    windowPackets, 60_000L,
                    "After-hours activity: " + srcIP + " at " + timeStr,
                    sev,
                    proto, "AFTER_HOURS", dstPort
                ));
            }
        }

        // SENSITIVE ACCESS
        if ((isAfterHours || isWeekend) && sensitive && whitelist.isInternal(dstIP)) {
            String key = "SENSITIVE:" + srcIP + ":" + dstPort;

            if (shouldAlert(key, now)) {
                alertManager.raise(new ThreatEvent(
                    ThreatType.AFTER_HOURS_SERVER_ACCESS,
                    srcIP, srcMac,
                    dstIP, dstMac,
                    windowPackets, 60_000L,
                    "Sensitive off-hours access: " + srcIP +
                    " → " + dstIP + ":" + dstPort,
                    Severity.HIGH,
                    proto, "SENSITIVE", dstPort
                ));
            }
        }
    }

    private boolean shouldAlert(String key, long now) {
        Long last = lastAlerts.get(key);
        if (last == null || (now - last) > COOLDOWN_MS) {
            lastAlerts.put(key, now);
            return true;
        }
        return false;
    }

    public void cleanup() {
        long now = System.currentTimeMillis();

        activityMap.entrySet().removeIf(e ->
            now - e.getValue().getLastSeen() > 600_000L);

        lastAlerts.entrySet().removeIf(e ->
            now - e.getValue() > 600_000L);
    }
}