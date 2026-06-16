package com.ids.mapper;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.dto.ThreatEventDTO;
import com.ids.entity.ThreatEventEntity;
import com.ids.enums.ThreatType;
import com.ids.enums.Severity;

import java.time.LocalDateTime;

@Component
public class ThreatEventMapper {

    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    public ThreatEventEntity toEntity(ThreatEventDTO dto) {
        ThreatEventEntity entity = new ThreatEventEntity();

        entity.setSourceIp(dto.getSourceIp());
        entity.setDestinationIp(dto.getDestinationIp());

        entity.setThreatType(ThreatType.fromString(dto.getThreatType()));
        entity.setSeverity(Severity.fromString(dto.getSeverity()));

        entity.setProtocol(dto.getProtocol());
        entity.setPacketCount(dto.getPacketCount());

        entity.setTimestamp(LocalDateTime.parse(dto.getTimestamp()));

        try {
            entity.setDetails(objectMapper.writeValueAsString(dto.getExtraData()));
        } catch (Exception e) {
            entity.setDetails("{}");
        }

        return entity;
    }
}