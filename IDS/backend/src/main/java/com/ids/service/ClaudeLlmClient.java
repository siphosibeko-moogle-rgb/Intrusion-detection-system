package com.ids.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.config.TriageProperties;
import com.ids.dto.TriageEvidence;
import com.ids.dto.TriageVerdict;
import com.ids.enums.TriageClassification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Active only when ids.ai-triage.provider=claude and an api-key is
 * configured (see TriageConfig). Uses the JDK's own java.net.http.HttpClient
 * deliberately — RestClient/WebClient are not a guaranteed dependency here
 * and this feature adds none.
 *
 * On ANY failure (transport, non-200, non-JSON, missing/out-of-range field)
 * this delegates to HeuristicLlmClient rather than throwing — a flaky LLM
 * call must never take down a sweep, let alone the ingest path it isn't even
 * on.
 */
@Component
public class ClaudeLlmClient implements LlmClient {

    private static final Logger log = LoggerFactory.getLogger(ClaudeLlmClient.class);
    public static final String NAME = "claude";

    private static final String SYSTEM_PROMPT = """
        You are a senior SOC analyst triaging an IDS alert. You never take action; you
        only assess. Raise confidence of a true positive when: the source has prior
        alerts against critical assets; the behaviour shape matches the threat type
        (many ports/short window = scan; many auth failures = brute force; regular
        fixed-interval callouts = beaconing); the threat score is high; or a critical
        asset is targeted. Treat occurrenceCount as the true volume — the sensor
        suppresses repeated alerts from trusted sources, so a modest raw count with a
        high occurrenceCount still indicates sustained activity. Lower confidence
        when: the source is whitelisted or on a trusted network, volume is genuinely
        low and isolated, or the pattern fits benign automation. If evidence is thin
        or contradictory, return NEEDS_REVIEW rather than guessing. Output ONLY the
        specified JSON.

        {"confidence": <0-100 int>,
         "classification": "LIKELY_TRUE_POSITIVE|LIKELY_FALSE_POSITIVE|NEEDS_REVIEW",
         "reasoning": "<=400 chars",
         "recommendation": "<=200 chars"}
        """;

    private final TriageProperties props;
    private final HeuristicLlmClient fallback;
    private final ObjectMapper mapper;
    private final HttpClient http;

    public ClaudeLlmClient(TriageProperties props, HeuristicLlmClient fallback, ObjectMapper mapper) {
        this.props = props;
        this.fallback = fallback;
        this.mapper = mapper;
        this.http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    }

    @Override
    public TriageVerdict classify(TriageEvidence evidence) {
        try {
            Map<String, Object> body = Map.of(
                "model", props.model(),
                "max_tokens", 400,
                "system", SYSTEM_PROMPT,
                "messages", List.of(Map.of("role", "user", "content", mapper.writeValueAsString(evidence)))
            );

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(props.baseUrl() + "/v1/messages"))
                .header("Content-Type", "application/json")
                .header("x-api-key", props.apiKey())
                .header("anthropic-version", "2023-06-01")
                .timeout(Duration.ofSeconds(8))
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                .build();

            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                log.warn("[AiTriage] Claude API returned HTTP {} for {}/{} — falling back to heuristic.",
                    response.statusCode(), evidence.sourceIp(), evidence.threatType());
                return fallback.classify(evidence);
            }

            JsonNode root = mapper.readTree(response.body());
            JsonNode contentBlock = root.path("content").path(0);
            String text = contentBlock.path("text").asText(null);
            if (text == null || text.isBlank()) {
                log.warn("[AiTriage] Claude response had no text content for {}/{} — falling back to heuristic.",
                    evidence.sourceIp(), evidence.threatType());
                return fallback.classify(evidence);
            }

            JsonNode verdictJson = mapper.readTree(text);
            int confidence = verdictJson.path("confidence").asInt(-1);
            String classificationRaw = verdictJson.path("classification").asText(null);
            String reasoning = verdictJson.path("reasoning").asText(null);
            String recommendation = verdictJson.path("recommendation").asText(null);

            if (confidence < 0 || confidence > 100 || classificationRaw == null
                    || reasoning == null || recommendation == null) {
                log.warn("[AiTriage] Claude response missing/out-of-range fields for {}/{} — falling back to heuristic.",
                    evidence.sourceIp(), evidence.threatType());
                return fallback.classify(evidence);
            }

            TriageClassification classification;
            try {
                classification = TriageClassification.valueOf(classificationRaw);
            } catch (IllegalArgumentException ex) {
                log.warn("[AiTriage] Claude returned unknown classification '{}' for {}/{} — falling back to heuristic.",
                    classificationRaw, evidence.sourceIp(), evidence.threatType());
                return fallback.classify(evidence);
            }

            return new TriageVerdict(evidence.sourceIp(), evidence.threatType(), confidence,
                classification, reasoning, recommendation, NAME, Instant.now());

        } catch (Exception e) {
            log.warn("[AiTriage] Claude call failed for {}/{}: {} — falling back to heuristic.",
                evidence.sourceIp(), evidence.threatType(), e.toString());
            return fallback.classify(evidence);
        }
    }

    @Override
    public String name() { return NAME; }
}
