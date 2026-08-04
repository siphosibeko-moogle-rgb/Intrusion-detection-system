package com.ids.mobile.model;

/**
 * One row on the status screen. Immutable — instances are built on a poller
 * thread and read on the UI thread, and final fields give us safe publication
 * without any synchronization.
 */
public final class HealthComponent {

    public final String name;
    public final String status;   // OK | WARN | ERROR | UNKNOWN
    public final String detail;

    public HealthComponent(String name, String status, String detail) {
        this.name = name;
        this.status = status == null ? "UNKNOWN" : status.toUpperCase();
        this.detail = detail == null ? "" : detail;
    }

    public boolean isHealthy() { return "OK".equals(status); }
}
