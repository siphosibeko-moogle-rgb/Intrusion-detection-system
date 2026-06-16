package com.ids.service;

import org.springframework.stereotype.Service;

import com.ids.dto.ThreatEventDTO;
import com.ids.mapper.ThreatEventMapper;
import com.ids.entity.ThreatEventEntity; // ✅ FIXED
import com.ids.repository.ThreatEventRepository;

@Service
public class ThreatEventService {

    private final ThreatEventRepository repository;
    private final ThreatEventMapper mapper;

    public ThreatEventService(ThreatEventRepository repository, ThreatEventMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    public ThreatEventEntity saveEvent(ThreatEventDTO dto) {
        ThreatEventEntity entity = mapper.toEntity(dto);
        return repository.save(entity);
    }
}