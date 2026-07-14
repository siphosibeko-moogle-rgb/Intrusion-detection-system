package com.ids.service;

import com.ids.config.ThrottleProperties;
import com.ids.model.Alert;
import com.ids.repository.MyWhitelistRepository;
import com.ids.repository.OrgWhitelistRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AlertThrottleServiceUnitTest {

    @Mock JdbcTemplate           jdbc;
    @Mock MyWhitelistRepository  myWhitelist;
    @Mock OrgWhitelistRepository orgWhitelist;

    private AlertThrottleService service() {
        return new AlertThrottleService(jdbc, myWhitelist, orgWhitelist,
            new ThrottleProperties(null, Map.of()));
    }

    private static Alert alert(String sourceIp, String type) {
        Alert a = new Alert();
        a.setSourceIp(sourceIp);
        a.setThreatType(type);
        return a;
    }

    @Test
    void nonWhitelistedSourceEmitsNormallyWithoutTouchingTheDb() {
        when(myWhitelist.existsByIp("203.0.113.9")).thenReturn(false);
        when(orgWhitelist.existsByIpAndApprovedTrue("203.0.113.9")).thenReturn(false);

        assertEquals(ThrottleDecision.EMIT_LOW,
                     service().evaluate(alert("203.0.113.9", "PORT_SCAN")));

        verifyNoInteractions(jdbc); // bypass means no throttle-state row is ever created
    }

    @Test
    void alertWithoutSourceIpOrDetectorBypassesThrottleEntirely() {
        assertEquals(ThrottleDecision.EMIT_LOW, service().evaluate(alert(null, "PORT_SCAN")));
        assertEquals(ThrottleDecision.EMIT_LOW, service().evaluate(alert("10.0.0.5", null)));

        verifyNoInteractions(jdbc);
        verifyNoInteractions(myWhitelist); // no key -> not even a whitelist lookup
    }
}
