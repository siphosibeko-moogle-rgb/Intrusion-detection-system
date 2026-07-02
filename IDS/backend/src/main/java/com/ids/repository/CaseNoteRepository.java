package com.ids.repository;

import com.ids.entity.CaseNote;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CaseNoteRepository extends JpaRepository<CaseNote, Long> {

    // All notes for a case, newest first.
    List<CaseNote> findByCaseIdOrderByCreatedAtDesc(Long caseId);

    // Delete all notes when a case is deleted (cascade handles DB side,
    // but we may want to call this explicitly before soft-delete scenarios).
    void deleteByCaseId(Long caseId);
}