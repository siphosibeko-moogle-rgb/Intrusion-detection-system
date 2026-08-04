package com.ids.config;

import com.ids.service.ClaudeLlmClient;
import com.ids.service.HeuristicLlmClient;
import com.ids.service.LlmClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TriageConfig {

    private static final Logger log = LoggerFactory.getLogger(TriageConfig.class);

    /**
     * Selects the LlmClient AiTriageService actually calls. provider=claude
     * AND a non-blank api-key activates ClaudeLlmClient (which itself falls
     * back to HeuristicLlmClient on any per-call failure); everything else —
     * provider=heuristic, or provider=claude with no key configured — uses
     * HeuristicLlmClient directly, so a missing key never breaks startup or
     * silently no-ops the feature.
     */
    @Bean
    public LlmClient activeLlmClient(TriageProperties props,
                                     ClaudeLlmClient claudeLlmClient,
                                     HeuristicLlmClient heuristicLlmClient) {
        boolean useClaude = "claude".equalsIgnoreCase(props.provider())
                && props.apiKey() != null && !props.apiKey().isBlank();
        LlmClient active = useClaude ? claudeLlmClient : heuristicLlmClient;
        log.info("[AiTriage] Active LLM client: {}", active.name());
        return active;
    }
}
