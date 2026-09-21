package com.cybershield.scan;

import com.cybershield.domain.RiskLevel;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.List;

public interface ScanRecordRepository extends JpaRepository<ScanRecord, String> {

    Page<ScanRecord> findByOwnerIdOrderByCreatedAtDesc(String ownerId, Pageable pageable);

    Page<ScanRecord> findAllByOrderByCreatedAtDesc(Pageable pageable);

    Page<ScanRecord> findByRiskLevelOrderByCreatedAtDesc(RiskLevel riskLevel, Pageable pageable);

    long deleteByCreatedAtBefore(Instant cutoff);

    @Query("select r.riskLevel as riskLevel, count(r) as c from ScanRecord r group by r.riskLevel")
    List<Object[]> countByRiskLevel();

    @Query("select r.type as type, count(r) as c from ScanRecord r group by r.type")
    List<Object[]> countByType();

    long countByCreatedAtAfter(Instant since);

    /**
     * Corroboration lookup for the investigator console: any hot-tier scan whose
     * redacted snippet mentions the suspect indicator (a domain, a masked phone
     * fragment...). Snippets are already redacted at write time, so this never
     * surfaces raw victim content beyond what an admin can already see.
     */
    @Query("select r from ScanRecord r where lower(r.snippet) like lower(concat('%', :needle, '%'))")
    List<ScanRecord> searchBySnippetContains(@org.springframework.data.repository.query.Param("needle") String needle);
}
