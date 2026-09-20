package com.cybershield.forensics;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface EmailIncidentRepository extends JpaRepository<EmailIncidentRecord, String> {

    List<EmailIncidentRecord> findTop10ByFromDomainOrderByCreatedAtDesc(String fromDomain);

    List<EmailIncidentRecord> findTop10ByOriginIpOrderByCreatedAtDesc(String originIp);
}
