package com.cybershield.investigate;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface InvestigatorAuditLogRepository extends JpaRepository<InvestigatorAuditLog, String> {
    Page<InvestigatorAuditLog> findAllByOrderBySearchedAtDesc(Pageable pageable);
    Page<InvestigatorAuditLog> findByInvestigatorIdOrderBySearchedAtDesc(String investigatorId, Pageable pageable);
}
