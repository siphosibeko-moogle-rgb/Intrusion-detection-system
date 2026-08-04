package com.ids.service;

import com.ids.dto.TriageEvidence;
import com.ids.dto.TriageVerdict;

public interface LlmClient {

    /**
     * MUST NOT throw on transport/parse failure — implementations return a
     * NEEDS_REVIEW (or delegate to a fallback) verdict instead. Called from
     * the sweep thread only, never from the ingest path.
     */
    TriageVerdict classify(TriageEvidence evidence);

    String name();
}
