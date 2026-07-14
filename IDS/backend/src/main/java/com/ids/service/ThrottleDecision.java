package com.ids.service;

/** Outcome of AlertThrottleService.evaluate() for one incoming alert. */
public enum ThrottleDecision {
    /** Emit normally at the alert's own severity (also the non-whitelisted path). */
    EMIT_LOW,
    /** Fold into the most recent matching open alert; do not persist or broadcast a new one. */
    SUPPRESS,
    /** Rate crossed the threshold this call — emit ONE new HIGH alert. */
    ESCALATE
}
