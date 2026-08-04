package com.ids.dto;

import com.ids.enums.TriageClassification;

import java.time.Instant;

/**
 * Triage-only output: a confidence score, a classification, and human
 * reasoning for a human analyst to read. Never mutates any security state.
 */
public record TriageVerdict(
    String sourceIp,
    String threatType,
    int confidence,
    TriageClassification classification,
    String reasoning,
    String recommendation,
    String model,
    Instant analysedAt
) {
    // Defensive clamp/truncate here too — this is the single choke point
    // every TriageVerdict passes through (heuristic rules, parsed LLM JSON,
    // and the failure-fallback path all construct one), so column-limit and
    // range violations can never reach the DB write in AiTriageService.
    public TriageVerdict {
        confidence = Math.max(0, Math.min(100, confidence));
        if (reasoning != null && reasoning.length() > 500) {
            reasoning = reasoning.substring(0, 500);
        }
        if (recommendation != null && recommendation.length() > 300) {
            recommendation = recommendation.substring(0, 300);
        }
    }
}
