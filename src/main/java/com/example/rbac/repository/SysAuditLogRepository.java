package com.example.rbac.repository;

import com.example.rbac.domain.SysAuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SysAuditLogRepository extends JpaRepository<SysAuditLog, Long> {
}
