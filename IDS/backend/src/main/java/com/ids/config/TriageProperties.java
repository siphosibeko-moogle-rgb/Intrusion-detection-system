package com.ids.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.Arrays;
import java.util.List;

/**
 * AI triage tuning, bound from application.properties:
 *
 *   ids.ai-triage.enabled=false
 *   ids.ai-triage.provider=heuristic          # heuristic | claude
 *   ids.ai-triage.base-url=https://api.anthropic.com
 *   ids.ai-triage.model=claude-sonnet-4-5
 *   ids.ai-triage.api-key=${IDS_AI_KEY:}
 *   ids.ai-triage.sweep-interval-ms=15000
 *   ids.ai-triage.max-actors-per-sweep=20
 *   ids.ai-triage.critical-assets=            # comma-sep IPs/CIDRs, empty ok
 */
@ConfigurationProperties(prefix = "ids.ai-triage")
public record TriageProperties(
    @DefaultValue("false") boolean enabled,
    @DefaultValue("heuristic") String provider,
    @DefaultValue("https://api.anthropic.com") String baseUrl,
    @DefaultValue("claude-sonnet-4-5") String model,
    @DefaultValue("") String apiKey,
    @DefaultValue("15000") long sweepIntervalMs,
    @DefaultValue("20") int maxActorsPerSweep,
    @DefaultValue("") String criticalAssets
) {
    /** Parsed comma-separated IPs/CIDRs; empty list when unset. */
    public List<String> criticalAssetList() {
        if (criticalAssets == null || criticalAssets.isBlank()) return List.of();
        return Arrays.stream(criticalAssets.split(","))
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .toList();
    }
}
