package com.ids.alerts;

import com.ids.models.ThreatEvent;

/**
 * The one thing a detector needs from the alerting subsystem: somewhere to
 * send a ThreatEvent. Detectors depend on this interface instead of the
 * concrete AlertManager so unit tests can substitute a capturing sink and
 * assert exactly which events a synthetic packet stream produces — no
 * threads, no log files, no HTTP.
 *
 * AlertManager is the production implementation (queue → console + log
 * file + backend POST).
 */
public interface AlertSink {

    void raise(ThreatEvent event);
}
