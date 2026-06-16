package com.ids.models;

public class PacketContext {

    private String srcIp;
    private String dstIp;
    private String srcMac;
    private String dstMac;
    private int    srcPort;
    private int    dstPort;
    private String protocol;
    private long   timestamp;
    private int payloadLength;

    // TCP flags
    private boolean syn;
    private boolean ack;
    private boolean fin;
    private boolean rst;
    private boolean psh;
    private boolean urg;

    // ICMP
    private boolean icmpEchoRequest;

    // ── IP addresses — always stored as clean dotted-decimal strings ───
    // PacketParser is responsible for calling getHostAddress() before
    // passing values here. These setters accept String only — never
    // InetAddress — so there is no ambiguity about format.

    public String getSrcIp()              { return srcIp; }
    public void   setSrcIp(String srcIp)  { this.srcIp = srcIp; }

    public String getDstIp()              { return dstIp; }
    public void   setDstIp(String dstIp)  { this.dstIp = dstIp; }

    // ── MAC addresses ──────────────────────────────────────────────────
    public String getSrcMac()               { return srcMac; }
    public void   setSrcMac(String srcMac)  { this.srcMac = srcMac; }

    public String getDstMac()               { return dstMac; }
    public void   setDstMac(String dstMac)  { this.dstMac = dstMac; }

    // ── Ports ──────────────────────────────────────────────────────────
    public int  getSrcPort()            { return srcPort; }
    public void setSrcPort(int srcPort) { this.srcPort = srcPort; }

    public int  getDstPort()            { return dstPort; }
    public void setDstPort(int dstPort) { this.dstPort = dstPort; }

    // ── Protocol / timestamp ───────────────────────────────────────────
    public String getProtocol()                 { return protocol; }
    public void   setProtocol(String protocol)  { this.protocol = protocol; }

    public long getTimestamp()              { return timestamp; }
    public void setTimestamp(long ts)       { this.timestamp = ts; }

    // ── TCP flags ──────────────────────────────────────────────────────
    public boolean isSyn() { return syn; }
    public void setSyn(boolean syn) { this.syn = syn; }

    public boolean isAck() { return ack; }
    public void setAck(boolean ack) { this.ack = ack; }

    public boolean isFin() { return fin; }
    public void setFin(boolean fin) { this.fin = fin; }

    public boolean isRst() { return rst; }
    public void setRst(boolean rst) { this.rst = rst; }

    public boolean isPsh() { return psh; }
    public void setPsh(boolean psh) { this.psh = psh; }

    public boolean isUrg() { return urg; }
    public void setUrg(boolean urg) { this.urg = urg; }

    // ── ICMP ───────────────────────────────────────────────────────────
    public boolean isIcmpEchoRequest()                    { return icmpEchoRequest; }
    public void    setIcmpEchoRequest(boolean v)          { this.icmpEchoRequest = v; }

    public int getPayloadLength() {
        return payloadLength;
    }
    public void setPayloadLength(int payloadLength) {
        this.payloadLength = payloadLength;
    }
    // ── Protocol helpers ───────────────────────────────────────────────
    public boolean isTcp()  { return "TCP".equalsIgnoreCase(protocol); }
    public boolean isUdp()  { return "UDP".equalsIgnoreCase(protocol); }
    public boolean isIcmp() { return "ICMP".equalsIgnoreCase(protocol); }
    public boolean isArp()  { return "ARP".equalsIgnoreCase(protocol); }
}