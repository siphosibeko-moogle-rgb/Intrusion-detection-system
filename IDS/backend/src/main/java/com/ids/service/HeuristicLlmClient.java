package com.ids.service;

import com.ids.dto.TriageEvidence;
import com.ids.dto.TriageVerdict;
import com.ids.enums.TriageClassification;
import org.springframework.stereotype.Component;

import java.time.Instant;

import static com.ids.enums.TriageClassification.LIKELY_FALSE_POSITIVE;
import static com.ids.enums.TriageClassification.LIKELY_TRUE_POSITIVE;
import static com.ids.enums.TriageClassification.NEEDS_REVIEW;

/**
 * No-API-key deterministic triage. Always available — this is both the
 * default provider and ClaudeLlmClient's failure fallback, so it must never
 * throw and must always return a fully-formed verdict.
 */
@Component
public class HeuristicLlmClient implements LlmClient {

    public static final String NAME = "heuristic";

    @Override
    public TriageVerdict classify(TriageEvidence e) {
        if (e.sourceWhitelisted() || e.sourceTrustedNetwork()) {
            return verdict(e, LIKELY_FALSE_POSITIVE, 78,
                "Source is " + (e.sourceWhitelisted() ? "an approved/trusted-range host"
                        : "on an admin-trusted provider network") + "; no other aggravating factor.",
                "Low priority — no action needed unless severity escalates.");
        }

        if (e.threatScore() >= 75
                || (e.destIsCriticalAsset()
                    && ("CRITICAL".equals(e.severity()) || "HIGH".equals(e.severity())))) {
            return verdict(e, LIKELY_TRUE_POSITIVE, 88,
                "Threat score " + e.threatScore() + "/100"
                    + (e.destIsCriticalAsset() ? " and a critical asset is targeted" : "")
                    + " at " + e.severity() + " severity.",
                "Escalate for immediate analyst review.");
        }

        // High occurrenceCount is the throttle-aware volume signal — a
        // trusted host being repeatedly re-triggered is exactly what the
        // throttle's ESCALATE path exists to catch, so weight it here
        // rather than the (potentially under-counted) raw alert total.
        if (e.occurrenceCount() >= 5) {
            int confidence = Math.min(92, 60 + e.occurrenceCount());
            return verdict(e, LIKELY_TRUE_POSITIVE, confidence,
                "occurrenceCount=" + e.occurrenceCount() + " indicates sustained repeated activity "
                    + "(the sensor throttle folds repeats from trusted sources into this count rather "
                    + "than dropping them, so it is the true volume/rate signal).",
                "Investigate the rate/pattern — consistent with a scan, brute-force, or beaconing shape.");
        }

        return verdict(e, NEEDS_REVIEW, 50,
            "Evidence is thin or mixed: source not whitelisted, threat score "
                + e.threatScore() + "/100, occurrenceCount " + e.occurrenceCount() + ".",
            "Manual review recommended before acting.");
    }

    private TriageVerdict verdict(TriageEvidence e, TriageClassification classification, int confidence,
                                  String reasoning, String recommendation) {
        return new TriageVerdict(e.sourceIp(), e.threatType(), confidence, classification,
            reasoning, recommendation, NAME, Instant.now());
    }

    @Override
    public String name() { return NAME; }
}
