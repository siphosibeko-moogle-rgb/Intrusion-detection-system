package com.ids.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ids.entity.ThreatEventEntity;

@Repository
public interface ThreatEventRepository extends JpaRepository<ThreatEventEntity, Long> {
}
