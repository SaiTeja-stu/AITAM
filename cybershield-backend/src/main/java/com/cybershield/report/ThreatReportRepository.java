package com.cybershield.report;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface ThreatReportRepository extends JpaRepository<ThreatReport, String> {

    long countByContentHash(String contentHash);

    Page<ThreatReport> findByStatusOrderByCreatedAtDesc(ThreatReport.Status status, Pageable pageable);

    Page<ThreatReport> findAllByOrderByCreatedAtDesc(Pageable pageable);

    @Query("select r from ThreatReport r where r.status = com.cybershield.report.ThreatReport.Status.CONFIRMED "
            + "and r.indicatorType is not null")
    List<ThreatReport> findConfirmedIndicators();

    long countByStatus(ThreatReport.Status status);
}
