package com.anshul.securescan.repository;

import com.anshul.securescan.entity.ScanHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Repository for storing and querying scan history records.
 */
@Repository
public interface ScanHistoryRepository extends JpaRepository<ScanHistory, Long> {
}
