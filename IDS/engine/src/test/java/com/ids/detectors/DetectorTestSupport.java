package com.ids.detectors;

import com.ids.alerts.AlertSink;
import com.ids.models.PacketContext;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.ThreatType;
import com.ids.network.NetworkWhitelist;

import java.util.ArrayList;
import java.util.List;

/**
 * Shared fixtures for detector tests: a capturing AlertSink, a fluent
 * PacketContext builder, and a NetworkWhitelist stub that never trusts
 * anything (so tests exercise the detection logic itself, not allowlist
 * short-circuits).
 */
final class DetectorTestSupport {

    private DetectorTestSupport() {}

    /** Collects every raised event for assertions. */
    static final class CapturingSink implements AlertSink {
        final List<ThreatEvent> events = new ArrayList<>();

        @Override public void raise(ThreatEvent event) { events.add(event); }

        List<ThreatEvent> ofType(ThreatType type) {
            return events.stream().filter(e -> e.getType() == type).toList();
        }

        boolean raised(ThreatType type) { return !ofType(type).isEmpty(); }
    }

    /**
     * Whitelist that trusts nothing and treats 10.0.0.x as internal —
     * deterministic regardless of what ids-whitelist.properties on the
     * classpath says.
     */
    static NetworkWhitelist noTrustWhitelist() {
        return new NetworkWhitelist() {
            @Override public boolean isTrustedScanner(String srcIP) { return false; }
            @Override public boolean isTrusted(String ip)           { return false; }
            @Override public boolean isInternal(String ip) {
                return ip != null && ip.startsWith("10.0.0.");
            }
        };
    }

    /** Fluent builder for synthetic packets. Defaults: TCP, no flags set. */
    static final class Packet {
        private final PacketContext ctx = new PacketContext();

        static Packet tcp(String src, String dst, int dstPort, long ts) {
            Packet p = new Packet();
            p.ctx.setProtocol("TCP");
            p.ctx.setSrcIp(src);
            p.ctx.setDstIp(dst);
            p.ctx.setDstPort(dstPort);
            p.ctx.setSrcPort(50_000);
            p.ctx.setTimestamp(ts);
            p.ctx.setSrcMac("aa:bb:cc:dd:ee:01");
            p.ctx.setDstMac("aa:bb:cc:dd:ee:02");
            return p;
        }

        static Packet udp(String src, String dst, int dstPort, long ts) {
            Packet p = tcp(src, dst, dstPort, ts);
            p.ctx.setProtocol("UDP");
            return p;
        }

        Packet syn()             { ctx.setSyn(true);  return this; }
        Packet ack()             { ctx.setAck(true);  return this; }
        Packet fin()             { ctx.setFin(true);  return this; }
        Packet psh()             { ctx.setPsh(true);  return this; }
        Packet urg()             { ctx.setUrg(true);  return this; }
        Packet srcPort(int port) { ctx.setSrcPort(port); return this; }

        PacketContext build() { return ctx; }
    }
}
